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

// 按账号绑定：同一 uid 固定同一代理，不同账号尽量分散到不同代理。
func TestPickForBindsAccount(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2"})
	if err != nil {
		t.Fatal(err)
	}
	first := p.PickFor("u1")
	if first == nil {
		t.Fatal("binding pool should assign a proxy")
	}
	for range 5 {
		if got := p.PickFor("u1"); got == nil || got.Raw != first.Raw {
			t.Fatalf("account binding drifted: first=%s got=%v", first.Raw, got)
		}
	}
	second := p.PickFor("u2")
	if second == nil || second.Raw == first.Raw {
		t.Fatalf("second account should spread to another proxy: %v", second)
	}
	if _, ok := p.BindingOf("u1"); !ok {
		t.Fatal("BindingOf should report the assigned proxy")
	}
	views, _ := p.Snapshot()
	total := 0
	for _, v := range views {
		total += v.Bound
	}
	if total != 2 {
		t.Fatalf("bound account count = %d, want 2", total)
	}
}

// 绑定代理冷却期间该账号失败关闭，不换 IP；其他账号不受影响，期满自动恢复。
func TestPickForBoundCoolingFailsClosed(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2"})
	if err != nil {
		t.Fatal(err)
	}
	a := p.PickFor("u1")
	if a == nil || a.Raw != "http://a:1" {
		t.Fatalf("u1 should bind a:1, got %v", a)
	}
	if b := p.PickFor("u2"); b == nil || b.Raw != "http://b:2" {
		t.Fatalf("u2 should bind b:2, got %v", b)
	}
	for range failThreshold {
		p.NoteFail(a)
	}
	if got := p.PickFor("u1"); got != nil {
		t.Fatalf("bound proxy cooling must fail closed, got %v", got)
	}
	if got := p.PickFor("u2"); got == nil || got.Raw != "http://b:2" {
		t.Fatalf("unrelated account must stay usable, got %v", got)
	}
	// 冷却期满：原绑定恢复。
	p.mu.Lock()
	p.frozen[a.index] = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if got := p.PickFor("u1"); got == nil || got.Raw != "http://a:1" {
		t.Fatalf("binding should resume after cooldown, got %v", got)
	}
}

// 关闭绑定：同一账号按请求轮转，且不产生绑定记录。
func TestBindAccountOffUsesRoundRobin(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2"})
	if err != nil {
		t.Fatal(err)
	}
	p.SetBindAccount(false)
	if p.BindAccount() {
		t.Fatal("BindAccount should be false after SetBindAccount(false)")
	}
	seen := map[string]bool{}
	for range 4 {
		px := p.PickFor("u1")
		if px == nil {
			t.Fatal("pool should stay usable")
		}
		seen[px.Raw] = true
	}
	if len(seen) != 2 {
		t.Fatalf("binding off should round robin, saw %v", seen)
	}
	if _, ok := p.BindingOf("u1"); ok {
		t.Fatal("binding off must not record an assignment")
	}
}

// 无账号请求（uid 为空）始终轮转，不占用绑定名额。
func TestPickForAnonymousRoundRobin(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 4 {
		seen[p.PickFor("").Raw] = true
	}
	if len(seen) != 2 {
		t.Fatalf("anonymous requests should round robin, saw %v", seen)
	}
	views, _ := p.Snapshot()
	for _, v := range views {
		if v.Bound != 0 {
			t.Fatalf("anonymous requests must not bind: %+v", v)
		}
	}
}

// 并发首请求只产生一个绑定。
func TestConcurrentPickForSingleBinding(t *testing.T) {
	p, err := New([]string{"http://a:1", "http://b:2", "http://c:3"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				p.PickFor("same-account")
			}
		}()
	}
	wg.Wait()
	views, _ := p.Snapshot()
	total := 0
	for _, v := range views {
		total += v.Bound
	}
	if total != 1 {
		t.Fatalf("concurrent first picks created %d bindings, want 1", total)
	}
}
