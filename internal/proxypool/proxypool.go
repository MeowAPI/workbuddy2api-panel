// Package proxypool 出站代理池：多上游代理地址的轮转选择与故障冷却。
//
// 背景：WAF 拦的是网关出口 IP 而非账号（server/wafip.go 已实证：多号 1 秒内
// 连环 403）。账号池只能轮换"谁去请求"，换不了"从哪里出去"。代理池把出口
// IP 也做成一层可轮换的资源，与账号池正交组合。
//
// 设计取舍：
//   - 只做静态列表轮转（round-robin + 故障旁路），不内置抓取/主动健康探测
//     ——代理来源高度个人化（自建 / 机场 / 商业池），探测目标的语义网关侧
//     无法假设；每代理的实际健康度由"真实请求的失败"记账（NoteFail），
//     短窗内失败达阈值进入冷却期，期满自动回池。
//   - 全池冷却中 Pick 返回 nil；调用方必须报错，不能绕过代理直连。
//   - 无代理配置（空列表）时池处于未启用态：调用方拿到 nil，出站行为与
//     本包引入前逐位一致（零回归）。
//   - 进程内状态、不落盘：代理列表来自 config.json，冷却计数重启清零。
package proxypool

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 失败记账参数：failureWindow 短窗内累计 failThreshold 次真实请求失败 →
// 该代理冷却 cooldown（期间不被选中），期满自动回池并清空失败计数。
const (
	failureWindow = 10 * time.Minute
	failThreshold = 3
	cooldown      = 5 * time.Minute
)

// Proxy 一条代理配置（config proxy.list 的解析形态）。
//
// 支持的形态（scheme 决定协议）：
//   - http://[user:pass@]host:port    — HTTP/HTTPS 代理（CONNECT 隧道）
//   - socks5://[user:pass@]host:port  — SOCKS5 代理
//   - socks5h://[...]                 — 同 socks5，域名解析交给代理端
//
// 非法形态在启动/保存配置时 fail fast（Parse 返回错误），运行期绝不半开。
type Proxy struct {
	Raw    string // 规范配置串（含认证信息，仅供内部标识与配置使用）
	scheme string // "http" / "socks5"
	url    *url.URL
	index  int // 所属池中的条目索引；独立 Parse 的结果不属于任何池
}

// Parse 解析单条代理串。空串不是合法代理（配置侧应跳过空行）。
func Parse(raw string) (Proxy, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Proxy{}, errors.New("proxy: 无效代理 URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	scheme := "http"
	switch u.Scheme {
	case "http", "https":
	case "socks5", "socks5h":
		u.Scheme = "socks5"
		scheme = "socks5"
	default:
		return Proxy{}, errors.New("proxy: 仅支持 http/https/socks5/socks5h")
	}
	if u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return Proxy{}, errors.New("proxy: 代理 URL 不允许路径、查询参数或片段")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\\t\r\n@?#%") {
		return Proxy{}, errors.New("proxy: 代理必须包含有效 host:port")
	}
	if strings.Contains(host, ":") {
		ip := net.ParseIP(host)
		if ip == nil {
			return Proxy{}, errors.New("proxy: 无效代理主机")
		}
		host = ip.String()
	} else if strings.ContainsAny(u.Host, "[]") {
		return Proxy{}, errors.New("proxy: 方括号仅允许 IPv6 地址")
	} else {
		name := strings.TrimSuffix(host, ".")
		if len(name) > 253 {
			return Proxy{}, errors.New("proxy: 无效代理主机")
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Proxy{}, errors.New("proxy: 无效代理主机")
			}
			for _, ch := range label {
				if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
					return Proxy{}, errors.New("proxy: 无效代理主机")
				}
			}
		}
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return Proxy{}, errors.New("proxy: 无效代理端口")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Proxy{}, errors.New("proxy: 代理端口必须为 1–65535")
	}
	u.Host = net.JoinHostPort(strings.ToLower(host), strconv.Itoa(n))
	u.Path, u.RawPath = "", ""
	return Proxy{Raw: u.String(), scheme: scheme, url: u, index: -1}, nil
}

// Scheme 归一后的协议（"http" / "socks5"）。
func (p Proxy) Scheme() string { return p.scheme }

// URL 返回解析后的代理地址（共享引用，调用方不得修改）。
func (p Proxy) URL() *url.URL { return p.url }

// String 返回去除全部 userinfo 的安全展示地址。
func (p Proxy) String() string {
	if p.url == nil {
		return "proxy"
	}
	u := *p.url
	u.User = nil
	return u.String()
}

// Display 返回 host:port 形态的展示地址（不含协议与凭据），
// 面板账号行标注「该账号固定从哪个出口出去」用。
func (p Proxy) Display() string {
	if p.url == nil {
		return ""
	}
	return p.url.Host
}

// Pool 代理池。零值不可用；用 New 构建。
type Pool struct {
	mu      sync.Mutex
	proxies []Proxy
	next    int // round-robin 游标

	// 固定大小的失败窗口避免每次失败分配；所有状态按条目索引对齐。
	fails    [][failThreshold]time.Time
	failures []int
	frozen   []time.Time
	lastPick []time.Time
	picks    int64

	// 按账号绑定出口（bind_account）：uid → 代理下标，bound[i] 为该代理
	// 已绑定的账号数。绑定在进程内首次见到 uid 时分配，重启后重新分配。
	bind     bool
	bindings map[string]int
	bound    []int
}

// New 按配置列表构建。raw 里的空行跳过；任一条非法直接报错（fail fast）。
// 空列表返回未启用池（Enabled() == false），Pick 恒返回 nil（直连）。
func New(raw []string) (*Pool, error) {
	p := &Pool{}
	seen := make(map[string]struct{}, len(raw))
	for _, r := range raw {
		if strings.TrimSpace(r) == "" {
			continue
		}
		px, err := Parse(r)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[px.Raw]; exists {
			continue
		}
		seen[px.Raw] = struct{}{}
		px.index = len(p.proxies)
		p.proxies = append(p.proxies, px)
	}
	p.fails = make([][failThreshold]time.Time, len(p.proxies))
	p.failures = make([]int, len(p.proxies))
	p.frozen = make([]time.Time, len(p.proxies))
	p.lastPick = make([]time.Time, len(p.proxies))
	p.bind = true // 缺省按账号绑定；配置显式 false 时由 SetBindAccount 关闭
	p.bindings = map[string]int{}
	p.bound = make([]int, len(p.proxies))
	return p, nil
}

// Enabled 报告代理池是否启用（至少一条合法代理）。
func (p *Pool) Enabled() bool { return p != nil && len(p.proxies) > 0 }

// Len 代理条数。
func (p *Pool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.proxies)
}

// BindAccount 报告是否按账号绑定出口代理（缺省 true）。
func (p *Pool) BindAccount() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bind
}

// SetBindAccount 热切换绑定模式。关闭时保留既有绑定（重新开启即恢复），
// 不重建代理连接池；切换只影响后续请求的选路。
func (p *Pool) SetBindAccount(enabled bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bind = enabled
}

// Pick 轮转选择下一个可用代理；全池冷却中返回 nil，调用方须区分 Enabled。
func (p *Pool) Pick() *Proxy {
	if !p.Enabled() {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pickLocked(time.Now())
}

// PickFor 按账号选择出口代理：
//   - 绑定模式且 uid 非空：同一账号固定使用首次分配的代理（不随请求轮转），
//     首次分配选「已绑定账号数最少」的可用代理，尽量让账号分散到不同出口；
//     绑定的代理冷却期间返回 nil——宁可该账号失败也不中途换 IP。
//   - 绑定关闭或 uid 为空（无账号的探测请求）：回落普通轮转 Pick。
func (p *Pool) PickFor(uid string) *Proxy {
	if !p.Enabled() {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if uid == "" || !p.bind {
		return p.pickLocked(now)
	}
	if idx, ok := p.bindings[uid]; ok {
		if !p.availableLocked(idx, now) {
			return nil
		}
		p.notePickLocked(idx, now)
		return &p.proxies[idx]
	}
	idx := p.leastBoundLocked(now)
	if idx < 0 {
		return nil
	}
	p.bindings[uid] = idx
	p.bound[idx]++
	p.notePickLocked(idx, now)
	return &p.proxies[idx]
}

// BindingOf 返回当前生效的代理展示地址（host:port，无凭据）。
// 关闭绑定时隐藏保留的分配；查询不会触发新分配。
func (p *Pool) BindingOf(uid string) (string, bool) {
	if p == nil || uid == "" {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.bind {
		return "", false
	}
	idx, ok := p.bindings[uid]
	if !ok {
		return "", false
	}
	return p.proxies[idx].Display(), true
}

// pickLocked 持锁轮转选一个可用代理（跳过冷却条目）。
func (p *Pool) pickLocked(now time.Time) *Proxy {
	n := len(p.proxies)
	for i := range n {
		idx := (p.next + i) % n
		if !p.availableLocked(idx, now) {
			continue
		}
		p.notePickLocked(idx, now)
		return &p.proxies[idx]
	}
	return nil
}

// availableLocked 报告条目当前可用；冷却到期时顺带清零失败计数（惰性回收）。
func (p *Pool) availableLocked(idx int, now time.Time) bool {
	if t := p.frozen[idx]; !t.IsZero() {
		if now.Before(t) {
			return false
		}
		p.frozen[idx] = time.Time{}
		p.failures[idx] = 0
	}
	return true
}

// leastBoundLocked 选已绑定账号数最少的可用代理（平手按轮转游标次序）。
func (p *Pool) leastBoundLocked(now time.Time) int {
	n := len(p.proxies)
	best := -1
	for i := range n {
		idx := (p.next + i) % n
		if !p.availableLocked(idx, now) {
			continue
		}
		if best < 0 || p.bound[idx] < p.bound[best] {
			best = idx
		}
	}
	return best
}

// notePickLocked 记录选中：推进轮转游标并更新观测字段。
func (p *Pool) notePickLocked(idx int, now time.Time) {
	p.next = (idx + 1) % len(p.proxies)
	p.lastPick[idx] = now
	p.picks++
}

// NoteFail 记一次该代理上的请求失败。窗口内累计达 failThreshold → 冷却。
// nil 入参静默忽略（调用方防御）。
func (p *Pool) NoteFail(px *Proxy) {
	if p == nil || px == nil || px.index < 0 || px.index >= len(p.proxies) || &p.proxies[px.index] != px {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i := px.index
	// 冷却期间的并发旧请求不得重新累计或延长冷却；Pick 回池时清零。
	if !p.frozen[i].IsZero() {
		return
	}
	now := time.Now()
	kept := 0
	for _, t := range p.fails[i][:p.failures[i]] {
		if now.Sub(t) <= failureWindow {
			p.fails[i][kept] = t
			kept++
		}
	}
	p.fails[i][kept] = now
	kept++
	p.failures[i] = kept
	if kept == failThreshold {
		p.frozen[i] = now.Add(cooldown)
		p.failures[i] = 0
	}
}

// View 单条代理的观测快照（面板 API 用）。
type View struct {
	Raw         string    `json:"raw"`
	Scheme      string    `json:"scheme"`
	Frozen      bool      `json:"frozen"`
	UnfreezeAt  time.Time `json:"unfreeze_at"`
	RecentFails int       `json:"recent_fails"`
	LastPick    time.Time `json:"last_pick"`
	Pickable    bool      `json:"pickable"`
	// Bound 绑定到该代理的账号数（bind_account 模式；关闭时为 0）。
	Bound int `json:"bound"`
}

// Snapshot 返回全部代理的观测状态与总选中次数。
func (p *Pool) Snapshot() (views []View, picks int64) {
	if !p.Enabled() {
		return nil, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	views = make([]View, 0, len(p.proxies))
	for i := range p.proxies {
		px := &p.proxies[i]
		v := View{Raw: px.String(), Scheme: px.scheme, LastPick: p.lastPick[i]}
		if p.bind {
			v.Bound = p.bound[i]
		}
		if t := p.frozen[i]; !t.IsZero() && now.Before(t) {
			v.Frozen = true
			v.UnfreezeAt = t
		} else {
			v.Pickable = true
		}
		for _, t := range p.fails[i][:p.failures[i]] {
			if now.Sub(t) <= failureWindow {
				v.RecentFails++
			}
		}
		views = append(views, v)
	}
	return views, p.picks
}
