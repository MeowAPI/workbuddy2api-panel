package upstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/proxypool"
)

func forwardingProxy(t *testing.T, calls, connections *atomic.Int32) *httptest.Server {
	t.Helper()
	forward := http.DefaultTransport.(*http.Transport).Clone()
	forward.Proxy = nil
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		out := req.Clone(req.Context())
		out.RequestURI = ""
		out.Header.Del("Proxy-Authorization")
		resp, err := forward.RoundTrip(out)
		if err != nil {
			http.Error(w, "forward failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, values := range resp.Header {
			w.Header()[k] = values
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	s.Start()
	t.Cleanup(func() { s.Close(); forward.CloseIdleConnections() })
	return s
}

func TestClaimRewardFallbackKeepsAccountProxy(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		originCalls.Add(1)
		if req.Header.Get("X-User-Id") != "reward-account" {
			t.Error("reward request lost its account")
		}
		if req.Header.Get("X-Client-Platform") != "web" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"code":1,"msg":"use web claim"}`)
			return
		}
		io.WriteString(w, `{"code":0,"data":{"credit":12,"energy":3}}`)
	}))
	defer origin.Close()
	var first, second, firstConns, secondConns atomic.Int32
	p1 := forwardingProxy(t, &first, &firstConns)
	p2 := forwardingProxy(t, &second, &secondConns)
	pp, err := proxypool.New([]string{p1.URL, p2.URL})
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	c.ChatBaseCN, c.WebBaseCN = origin.URL, origin.URL
	c.SetProxyPool(pp)
	defer c.HTTP.CloseIdleConnections()
	credit, energy, err := c.ClaimRewardMP(&auth.Auth{UID: "reward-account", AccessToken: "token"}, "task")
	if err != nil || credit != 12 || energy != 3 {
		t.Fatalf("reward failed: credit=%d energy=%d err=%v", credit, energy, err)
	}
	if first.Load() != 2 || second.Load() != 0 || originCalls.Load() != 2 {
		t.Fatalf("fallback changed proxy: first=%d second=%d origin=%d", first.Load(), second.Load(), originCalls.Load())
	}
}

func TestChatProxyFailureKeepsHealthyIdleConnections(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer origin.Close()
	var calls, connections, badCalls atomic.Int32
	good := forwardingProxy(t, &calls, &connections)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		badCalls.Add(1)
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer bad.Close()
	pp, err := proxypool.New([]string{good.URL, bad.URL})
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	c.ChatBaseCN = origin.URL
	c.SetProxyPool(pp)
	defer c.HTTP.CloseIdleConnections()
	goodAccount := &auth.Auth{UID: "healthy-account", AccessToken: "token"}
	chat := func(a *auth.Auth) error {
		rc, _, _, err := c.ChatStream(a, []byte(`{"messages":[]}`), "", ChatMeta{})
		if err != nil {
			return err
		}
		defer rc.Close()
		body, err := io.ReadAll(rc)
		if err == nil && string(body) != "data: [DONE]\n\n" {
			t.Fatalf("unexpected stream: %q", body)
		}
		return err
	}
	if err := chat(goodAccount); err != nil {
		t.Fatal(err)
	}
	if err := chat(&auth.Auth{UID: "broken-account", AccessToken: "token"}); !errors.Is(err, errProxyAuth) {
		t.Fatalf("expected proxy auth failure: %v", err)
	}
	if err := chat(goodAccount); err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 1 || calls.Load() != 2 || badCalls.Load() != 1 {
		t.Fatalf("healthy connection was discarded or account drifted: connections=%d good=%d bad=%d", connections.Load(), calls.Load(), badCalls.Load())
	}
}

func TestChatProxyParentCancellationPreservesBinding(t *testing.T) {
	entered := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 读完 POST body 后服务端才开始监测连接断开。
		io.Copy(io.Discard, req.Body)
		entered <- struct{}{}
		<-req.Context().Done()
	}))
	defer origin.Close()
	var calls, connections atomic.Int32
	p := forwardingProxy(t, &calls, &connections)
	pp, err := proxypool.New([]string{p.URL})
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	c.ChatBaseCN = origin.URL
	c.SetProxyPool(pp)
	defer c.HTTP.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		rc, _, _, err := c.ChatStreamContext(ctx, &auth.Auth{UID: "cancelled-account", AccessToken: "token"}, []byte(`{"messages":[]}`), "", ChatMeta{})
		if rc != nil {
			rc.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("request never reached the origin")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost parent cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("chat remained active after cancellation")
	}
	bound, ok := pp.BindingOf("cancelled-account")
	views, picks := pp.Snapshot()
	if !ok || bound != strings.TrimPrefix(p.URL, "http://") || picks != 1 || views[0].RecentFails != 0 {
		t.Fatalf("cancellation changed binding or health: bound=%q ok=%t views=%+v picks=%d", bound, ok, views, picks)
	}
}
