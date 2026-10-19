package proxypool

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustParse(t *testing.T, raw string) Proxy {
	t.Helper()
	px, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", raw, err)
	}
	return px
}

func TestParseForms(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
	}{
		{"http://127.0.0.1:7890", "http", "127.0.0.1:7890"},
		{"https://user:pass@proxy.example.com:8443", "http", "proxy.example.com:8443"},
		{"socks5://127.0.0.1:1080", "socks5", "127.0.0.1:1080"},
		{"socks5h://u@10.0.0.1:1080", "socks5", "10.0.0.1:1080"},
		{"  http://127.0.0.1:8080  ", "http", "127.0.0.1:8080"},
	}
	for _, c := range cases {
		px := mustParse(t, c.raw)
		if px.Scheme() != c.scheme {
			t.Errorf("Parse(%q).Scheme = %q, want %q", c.raw, px.Scheme(), c.scheme)
		}
		if px.URL().Host != c.host {
			t.Errorf("Parse(%q).URL().Host = %q, want %q", c.raw, px.URL().Host, c.host)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, raw := range []string{
		"",
		"127.0.0.1:7890",     // 无 scheme
		"ftp://127.0.0.1:21", // 不支持协议
		"http://",            // 无 host
		"socks5://",          // 无 host
		"://bad",             // 解析失败
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) 应报错，实际通过", raw)
		}
	}
}

func TestNewSkipsEmptyAndRejectsBad(t *testing.T) {
	p, err := New([]string{" http://a:1 ", "", "  "})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Len() != 1 || !p.Enabled() {
		t.Fatalf("空行应跳过：Len=%d", p.Len())
	}
	if _, err := New([]string{"http://a:1", "bogus"}); err == nil {
		t.Fatal("任一条非法应整体报错（fail fast）")
	}
}

func TestDisabledPool(t *testing.T) {
	p, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Enabled() || p.Pick() != nil || p.Len() != 0 {
		t.Fatal("空池：Enabled=false、Pick=nil、Len=0")
	}
	views, picks := p.Snapshot()
	if views != nil || picks != 0 {
		t.Fatal("空池 Snapshot 返回零值")
	}
	// nil 池同样安全（调用方零值防御）。
	var nilPool *Pool
	if nilPool.Enabled() || nilPool.Pick() != nil || nilPool.Len() != 0 {
		t.Fatal("nil 池：全部安全退化")
	}
	nilPool.NoteFail(nil) // 不得 panic
}

func TestPickRoundRobin(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2", "http://c:3"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for range 6 {
		px := p.Pick()
		if px == nil {
			t.Fatal("全池可用时 Pick 不应返回 nil")
		}
		got = append(got, px.Raw)
	}
	want := []string{"http://a:1", "http://b:2", "http://c:3", "http://a:1", "http://b:2", "http://c:3"}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("轮转顺序错误：got %v, want %v", got, want)
		}
	}
}

func TestNoteFailFreezes(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2"})
	if err != nil {
		t.Fatal(err)
	}
	a := p.Pick() // a:1
	for range failThreshold {
		p.NoteFail(a)
	}
	views, _ := p.Snapshot()
	if !views[0].Frozen || views[0].Pickable {
		t.Fatalf("连败 %d 次后 a 应冷却： %+v", failThreshold, views[0])
	}
	if views[1].Frozen {
		t.Fatal("b 未失败，不应冷却")
	}
	// 冷却中的 a 被跳过，Pick 只出 b。
	for range 3 {
		if px := p.Pick(); px.Raw != "http://b:2" {
			t.Fatalf("冷却期应只选 b，实际 %s", px.Raw)
		}
	}
	// 期满回池：直接改 frozen 截止到过去（不依赖真实时钟）。
	p.mu.Lock()
	p.frozen[0] = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if av := p.Pick(); av == nil || av.Raw != "http://a:1" {
		t.Fatalf("期满后 a 应回池，实际 %v", av)
	} else {
		// 回池同时失败计数清零：再失败 1 次不立即重新冷却。
		p.NoteFail(av)
	}
	views, _ = p.Snapshot()
	if views[0].Frozen || views[0].RecentFails != 1 {
		t.Fatalf("回池后计数应清零重新记： %+v", views[0])
	}
}

func TestAllFrozenHasNoPick(t *testing.T) {
	p, err := New([]string{"http://a:1"})
	if err != nil {
		t.Fatal(err)
	}
	a := p.Pick()
	for range failThreshold {
		p.NoteFail(a)
	}
	if px := p.Pick(); px != nil {
		t.Fatalf("全池冷却应返回 nil，调用方必须报错，实际 %v", px)
	}
}

func TestNoteFailNilAndForeignSafe(t *testing.T) {
	p, _ := New([]string{"http://a:1"})
	p.NoteFail(nil) // 不得 panic
	foreign := mustParse(t, "http://z:9")
	p.NoteFail(&foreign) // 不在池内：静默忽略，不得 panic
	if views, _ := p.Snapshot(); views[0].RecentFails != 0 {
		t.Fatalf("外来条目不应记账： %+v", views[0])
	}
}

func TestConcurrentPickAndFail(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2", "http://c:3", "http://d:4"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var picked atomic.Int64
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				px := p.Pick()
				if px == nil {
					continue // 全池冷却，路由层必须拒绝请求
				}
				picked.Add(1)
				if g%2 == 0 {
					p.NoteFail(px)
				}
			}
		}()
	}
	wg.Wait()
	views, picks := p.Snapshot()
	if len(views) != 4 {
		t.Fatalf("Snapshot 应含 4 条，实际 %d", len(views))
	}
	if picks != picked.Load() {
		t.Fatalf("并发下 picks 计数丢失：snapshot=%d, 实际选中=%d", picks, picked.Load())
	}
}

func TestParseCanonicalAndDeduplicate(t *testing.T) {
	p, err := New([]string{
		" HTTP://User:secret@EXAMPLE.com:08080/ ",
		"http://User:secret@example.com:8080",
		"SOCKS5H://[0:0:0:0:0:0:0:1]:01080/",
		"socks5://[::1]:1080",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Len() != 2 {
		t.Fatalf("canonical duplicates retained: %d", p.Len())
	}
	if got := p.Pick().URL().String(); got != "http://User:secret@example.com:8080" {
		t.Fatalf("canonical HTTP URL = %q", got)
	}
	if got := p.Pick().URL().String(); got != "socks5://[::1]:1080" {
		t.Fatalf("canonical SOCKS URL = %q", got)
	}
}

func TestParseRejectsUnsafeURLsWithoutCredentials(t *testing.T) {
	for _, suffix := range []string{
		"host", "host:", "host:0", "host:65536", "host:-1", "host:abc",
		"host:80/path", "host:80?token=secret", "host:80?", "host:80#secret", "host:80#",
		"[hostname]:80", "::1:80", ":80", "host:80/%zz",
	} {
		_, err := Parse("http://private-user:private-password@" + suffix)
		if err == nil {
			t.Errorf("accepted invalid authority/path %q", suffix)
			continue
		}
		if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("parse error leaks credentials: %v", err)
		}
	}
	if _, err := Parse("http://private-user:private%password@host:80"); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("malformed userinfo must produce a safe error: %v", err)
	}
}

func TestProxyObservabilityRemovesAllUserinfo(t *testing.T) {
	p, err := New([]string{"http://private-user:private-password@host:80"})
	if err != nil {
		t.Fatal(err)
	}
	px := p.Pick()
	if px.String() != "http://host:80" {
		t.Fatalf("unsafe display: %s", px)
	}
	views, _ := p.Snapshot()
	encoded, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "@") {
		t.Fatalf("snapshot leaks userinfo: %s", encoded)
	}
	if px.URL().User.Username() != "private-user" {
		t.Fatal("redaction mutated the authentication URL")
	}
}

func TestFailureWindowAndFrozenConcurrentFailures(t *testing.T) {
	p, _ := New([]string{"http://a:1"})
	px := p.Pick()
	p.mu.Lock()
	p.fails[0][0] = time.Now().Add(-failureWindow - time.Second)
	p.fails[0][1] = time.Now().Add(-time.Minute)
	p.failures[0] = 2
	p.mu.Unlock()
	p.NoteFail(px)
	views, _ := p.Snapshot()
	if views[0].Frozen || views[0].RecentFails != 2 {
		t.Fatalf("window must prune expired failures only: %+v", views[0])
	}
	p.NoteFail(px)
	views, _ = p.Snapshot()
	until := views[0].UnfreezeAt
	if !views[0].Frozen {
		t.Fatal("three failures in window must freeze")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				p.NoteFail(px)
				p.Snapshot()
			}
		}()
	}
	wg.Wait()
	views, _ = p.Snapshot()
	if !views[0].UnfreezeAt.Equal(until) || views[0].RecentFails != 0 {
		t.Fatalf("in-flight failures extended cooldown: %+v", views[0])
	}
	p.mu.Lock()
	p.frozen[0] = time.Now().Add(-time.Second)
	p.mu.Unlock()
	p.NoteFail(px) // 旧请求在下一次 Pick 回池之前仍不计入新一轮。
	if next := p.Pick(); next != px {
		t.Fatal("expired proxy not restored")
	}
	views, _ = p.Snapshot()
	if views[0].Frozen || views[0].RecentFails != 0 {
		t.Fatalf("restored pool retained failures: %+v", views[0])
	}
}

func TestNoteFailRejectsCopiedAndOtherPoolEntries(t *testing.T) {
	p, _ := New([]string{"http://a:1"})
	other, _ := New([]string{"http://a:1"})
	copy := *p.Pick()
	p.NoteFail(&copy)
	p.NoteFail(other.Pick())
	views, _ := p.Snapshot()
	if views[0].RecentFails != 0 {
		t.Fatal("foreign indices must not affect this pool")
	}
}
