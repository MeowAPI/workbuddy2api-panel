package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/proxypool"
)

func newTestProxyRouter(t *testing.T, addresses ...string) *proxyRouter {
	t.Helper()
	pool, err := proxypool.New(addresses)
	if err != nil {
		t.Fatal(err)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Local httptest certificates only.
	r := &proxyRouter{pool: pool, direct: base, base: base, per: make(map[string]*http.Transport)}
	t.Cleanup(r.CloseIdleConnections)
	return r
}

func proxyRequest(t *testing.T, r *proxyRouter, address string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func assertProxyFailures(t *testing.T, r *proxyRouter, failures int) {
	t.Helper()
	views, _ := r.pool.Snapshot()
	if len(views) != 1 || views[0].RecentFails != failures || views[0].Frozen {
		t.Fatalf("unexpected failure accounting: %+v", views)
	}
}

func TestProxyHTTPAndCONNECT(t *testing.T) {
	for _, targetTLS := range []bool{false, true} {
		for _, proxyTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("targetTLS=%t/proxyTLS=%t", targetTLS, proxyTLS), func(t *testing.T) {
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.Header.Get("Proxy-Authorization") != "" {
						t.Error("proxy credentials reached the origin")
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					io.WriteString(w, "origin business response")
				}))
				if targetTLS {
					origin.StartTLS()
				} else {
					origin.Start()
				}
				defer origin.Close()
				var calls atomic.Int32
				forward := http.DefaultTransport.(*http.Transport).Clone()
				forward.Proxy = nil
				defer forward.CloseIdleConnections()
				proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					calls.Add(1)
					wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("private-user:private-password"))
					if req.Header.Get("Proxy-Authorization") != wantAuth {
						t.Error("proxy did not receive authentication")
						w.WriteHeader(http.StatusProxyAuthRequired)
						return
					}
					if req.Method == http.MethodConnect {
						upstream, err := net.DialTimeout("tcp", req.Host, time.Second)
						if err != nil {
							t.Error(err)
							w.WriteHeader(http.StatusBadGateway)
							return
						}
						defer upstream.Close()
						client, buffered, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						defer client.Close()
						client.SetDeadline(time.Now().Add(5 * time.Second))
						upstream.SetDeadline(time.Now().Add(5 * time.Second))
						io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
						done := make(chan struct{})
						go func() {
							io.Copy(upstream, buffered)
							upstream.Close()
							close(done)
						}()
						io.Copy(client, upstream)
						client.Close()
						<-done
						return
					}
					if !req.URL.IsAbs() {
						t.Error("HTTP proxy request must use absolute-form URL")
					}
					out := req.Clone(req.Context())
					out.RequestURI = ""
					out.Header.Del("Proxy-Authorization")
					resp, err := forward.RoundTrip(out)
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()
					w.WriteHeader(resp.StatusCode)
					io.Copy(w, resp.Body)
				}))
				if proxyTLS {
					proxy.StartTLS()
				} else {
					proxy.Start()
				}
				defer proxy.Close()
				u, _ := url.Parse(proxy.URL)
				u.User = url.UserPassword("private-user", "private-password")
				r := newTestProxyRouter(t, u.String())
				defer r.CloseIdleConnections()
				resp := proxyRequest(t, r, origin.URL)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusServiceUnavailable || string(body) != "origin business response" || calls.Load() != 1 {
					t.Fatalf("proxy forwarding failed: status=%d body=%q calls=%d err=%v", resp.StatusCode, body, calls.Load(), err)
				}
				assertProxyFailures(t, r, 0)
			})
		}
	}
}

type proxyTrackedBody struct{ closed bool }

func (*proxyTrackedBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *proxyTrackedBody) Close() error {
	b.closed = true
	return nil
}

func TestProxyExhaustionNeverDialsDirect(t *testing.T) {
	var directCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		directCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	r := newTestProxyRouter(t, "http://127.0.0.1:1")
	px := r.pool.Pick()
	for range 3 {
		r.pool.NoteFail(px)
	}
	body := &proxyTrackedBody{}
	req, _ := http.NewRequest(http.MethodPost, origin.URL, body)
	resp, err := r.RoundTrip(req)
	if !errors.Is(err, errProxyUnavailable) || resp != nil || !body.closed || directCalls.Load() != 0 {
		t.Fatalf("exhaustion must fail closed: resp=%v err=%v closed=%t direct=%d", resp, err, body.closed, directCalls.Load())
	}
	empty := newTestProxyRouter(t)
	if resp := proxyRequest(t, empty, origin.URL); resp.StatusCode != http.StatusNoContent || directCalls.Load() != 1 {
		t.Fatal("empty pool must retain direct routing")
	}
}

func TestProxyCancellationDoesNotRecordFailures(t *testing.T) {
	entered := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		entered <- struct{}{}
		<-req.Context().Done()
	}))
	defer proxy.Close()
	r := newTestProxyRouter(t, proxy.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &proxyTrackedBody{}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://origin.invalid/", body)
	if _, err := r.RoundTrip(req); !errors.Is(err, context.Canceled) || !body.closed {
		t.Fatalf("pre-cancelled request: err=%v closed=%t", err, body.closed)
	}
	if _, picks := r.pool.Snapshot(); picks != 0 {
		t.Fatal("pre-cancelled request selected a proxy")
	}
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if deadline {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://origin.invalid/", nil)
		result := make(chan error, 1)
		go func() {
			_, err := r.RoundTrip(req)
			result <- err
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("request never reached proxy")
		}
		want := context.DeadlineExceeded
		if !deadline {
			cancel()
			want = context.Canceled
		}
		select {
		case err := <-result:
			cancel()
			if !errors.Is(err, want) {
				t.Fatalf("cancellation error = %v, want %v", err, want)
			}
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("cancelled request did not return")
		}
		assertProxyFailures(t, r, 0)
	}
}

func TestProxy407ClosesResponseAndRecordsFailure(t *testing.T) {
	for _, targetScheme := range []string{"http", "https"} {
		t.Run(targetScheme, func(t *testing.T) {
			closed := make(chan struct{}, 1)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Length", "1000000")
				w.WriteHeader(http.StatusProxyAuthRequired)
				io.WriteString(w, "private-user:private-password")
				w.(http.Flusher).Flush()
				// For an HTTPS target this is the CONNECT callback path; net/http
				// owns the response body and the handler must not wait on context
				// while the client is still processing the callback error.
				if targetScheme == "https" {
					return
				}
				<-req.Context().Done()
				closed <- struct{}{}
			}))
			defer proxy.Close()
			u, _ := url.Parse(proxy.URL)
			u.User = url.UserPassword("private-user", "private-password")
			r := newTestProxyRouter(t, u.String())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, targetScheme+"://origin.invalid/", nil)
			resp, err := r.RoundTrip(req)
			if resp != nil || !errors.Is(err, errProxyAuth) || strings.Contains(err.Error(), "private-") {
				t.Fatalf("407 must become a safe proxy error: resp=%v err=%v", resp, err)
			}
			assertProxyFailures(t, r, 1)
			if targetScheme == "http" {
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("407 response connection was not closed")
				}
			}
		})
	}
}

func TestProxyTransportErrorIsSafeAndCancellationIsExcluded(t *testing.T) {
	for _, cause := range []error{errors.New("dial http://private-user:private-password@host:80 failed"), context.Canceled, context.DeadlineExceeded} {
		r := newTestProxyRouter(t, "http://private-user:private-password@host:80")
		r.base.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, cause }
		req, _ := http.NewRequest(http.MethodGet, "http://origin.invalid/", nil)
		resp, err := r.RoundTrip(req)
		if resp != nil || err == nil || !errors.Is(err, cause) || strings.Contains(err.Error(), "private-") {
			t.Fatalf("unsafe error or lost cause: resp=%v err=%v", resp, err)
		}
		fails := 0
		if cause != context.Canceled && cause != context.DeadlineExceeded {
			fails = 1
		}
		assertProxyFailures(t, r, fails)
	}
}

// serveTestSOCKS performs RFC 1928/1929 negotiation and forwards one real request.
// The requested hostname is deliberately unresolvable locally; only this proxy maps it.
func serveTestSOCKS(listener net.Listener, target string, authenticated bool) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	if header[0] != 5 {
		return errors.New("not SOCKS5")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	method := byte(0)
	if authenticated {
		method = 2
	}
	offered := false
	for _, m := range methods {
		offered = offered || m == method
	}
	if !offered {
		return errors.New("expected SOCKS authentication method not offered")
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return err
	}
	if authenticated {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return err
		}
		username := make([]byte, int(header[1]))
		if _, err := io.ReadFull(reader, username); err != nil {
			return err
		}
		n, err := reader.ReadByte()
		if err != nil {
			return err
		}
		password := make([]byte, int(n))
		if _, err := io.ReadFull(reader, password); err != nil {
			return err
		}
		if header[0] != 1 || string(username) != "private-user" || string(password) != "private-password" {
			return errors.New("incorrect SOCKS authentication")
		}
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return err
		}
	}
	var request [5]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 || request[3] != 3 {
		return errors.New("SOCKS request must carry a remote-resolved domain name")
	}
	hostname := make([]byte, int(request[4]))
	if _, err := io.ReadFull(reader, hostname); err != nil {
		return err
	}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(target)
	if string(hostname) != "origin.invalid" || strconv.Itoa(int(header[0])<<8|int(header[1])) != port {
		return errors.New("wrong SOCKS destination")
	}
	upstream, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	upstream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		io.Copy(upstream, reader)
		// 请求侧 EOF 只关闭写端，保留读端直到上游响应全部转发。
		upstream.(*net.TCPConn).CloseWrite()
		close(done)
	}()
	_, err = io.Copy(conn, upstream)
	conn.Close()
	<-done
	return err
}

func TestProxyNativeSOCKSRemoteDNSAndAuthentication(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		for _, auth := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/auth=%t", scheme, auth), func(t *testing.T) {
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					w.Header().Set("Connection", "close")
					io.WriteString(w, "SOCKS origin")
				}))
				defer origin.Close()
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				target := strings.TrimPrefix(origin.URL, "http://")
				result := make(chan error, 1)
				go func() { result <- serveTestSOCKS(listener, target, auth) }()
				u := &url.URL{Scheme: scheme, Host: listener.Addr().String()}
				if auth {
					u.User = url.UserPassword("private-user", "private-password")
				}
				r := newTestProxyRouter(t, u.String())
				_, port, _ := net.SplitHostPort(target)
				resp := proxyRequest(t, r, "http://origin.invalid:"+port+"/")
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != "SOCKS origin" {
					t.Fatalf("SOCKS forwarding failed: body=%q err=%v", body, err)
				}
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("SOCKS proxy did not finish")
				}
				assertProxyFailures(t, r, 0)
			})
		}
	}
}

func TestSetProxyPoolClonesStartupTransport(t *testing.T) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = 17 * time.Second
	base.TLSHandshakeTimeout = 11 * time.Second
	base.Proxy = func(*http.Request) (*url.URL, error) {
		return nil, errors.New("inherited proxy callback must be replaced")
	}
	client := &Client{HTTP: &http.Client{Transport: base}, ChatHTTP: &http.Client{Transport: base}}
	client.SetProxyPool(nil)
	if client.HTTP.Transport != base || client.ChatHTTP.Transport != base {
		t.Fatal("nil pool changed transport")
	}
	pool, err := proxypool.New([]string{"socks5h://user:password@127.0.0.1:1080"})
	if err != nil {
		t.Fatal(err)
	}
	client.SetProxyPool(pool)
	r, ok := client.HTTP.Transport.(*proxyRouter)
	if !ok || client.ChatHTTP.Transport != r {
		t.Fatal("HTTP and ChatHTTP must share the startup proxy router")
	}
	defer r.CloseIdleConnections()
	px := pool.Pick()
	transport := r.transportFor(px)
	if transport == base || transport.ResponseHeaderTimeout != base.ResponseHeaderTimeout || transport.TLSHandshakeTimeout != base.TLSHandshakeTimeout {
		t.Fatal("proxy transport did not clone timeout settings")
	}
	proxyURL, err := transport.Proxy(nil)
	if err != nil || proxyURL.String() != px.URL().String() {
		t.Fatalf("native SOCKS proxy not configured: %v, %v", proxyURL, err)
	}
	if r.transportFor(px) != transport {
		t.Fatal("proxy transport was not reused")
	}
}

func TestProxyBusinessStatusesDoNotRecordFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusBadGateway} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(status)
			}))
			defer proxy.Close()
			r := newTestProxyRouter(t, proxy.URL)
			resp := proxyRequest(t, r, "http://origin.invalid/")
			resp.Body.Close()
			if resp.StatusCode != status {
				t.Fatalf("business status changed: %d", resp.StatusCode)
			}
			assertProxyFailures(t, r, 0)
		})
	}
}

// 同一账号的请求固定命中同一代理；不同账号分散到不同代理。
func TestProxyRouterBindsAccountToProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer origin.Close()
	var hits [2]atomic.Int32
	var proxies [2]*httptest.Server
	for i := range 2 {
		i := i
		proxies[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hits[i].Add(1)
			out := req.Clone(req.Context())
			out.RequestURI = ""
			resp, err := http.DefaultTransport.RoundTrip(out)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}))
		defer proxies[i].Close()
	}
	r := newTestProxyRouter(t, proxies[0].URL, proxies[1].URL)
	for _, uid := range []string{"acct-a", "acct-b"} {
		for range 3 {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
			bindAccountToRequest(req, &auth.Auth{UID: uid})
			resp, err := r.RoundTrip(req)
			if err != nil {
				cancel()
				t.Fatalf("%s: %v", uid, err)
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			cancel()
			if readErr != nil {
				t.Fatal(readErr)
			}
		}
	}
	aAddr, ok := r.pool.BindingOf("acct-a")
	if !ok {
		t.Fatal("acct-a has no proxy binding")
	}
	bAddr, ok := r.pool.BindingOf("acct-b")
	if !ok {
		t.Fatal("acct-b has no proxy binding")
	}
	if aAddr == bAddr {
		t.Fatalf("two accounts share one proxy: %s", aAddr)
	}
	if hits[0].Load() != 3 || hits[1].Load() != 3 {
		t.Fatalf("requests not bound per account: hits=%d/%d", hits[0].Load(), hits[1].Load())
	}
	views, _ := r.pool.Snapshot()
	for _, v := range views {
		if v.Bound != 1 {
			t.Fatalf("each proxy should bind exactly one account: %+v", views)
		}
	}
}
