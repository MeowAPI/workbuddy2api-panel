// proxy.go 出站代理池接线（internal/proxypool 的消费侧）。
//
// 接管方式：SetProxyPool 把 HTTP/ChatHTTP 的 Transport 替换为 proxyRouter——
// 一个代理感知的 RoundTripper：每次请求向池轮转取一个代理，按代理构造并缓存
// 独立的 *http.Transport（连接池按代理隔离）。空池保持直连，全池冷却明确报错。
//
// 失败记账：传输层错误和 HTTP 407 记 NoteFail；调用方取消或 deadline 不记。
// 其他上游业务响应（包括 4xx/5xx）不影响代理健康度。
package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"

	"github.com/linguo2625469/workbuddy2api-panel/internal/proxypool"
)

// proxyRouter 代理感知 RoundTripper。
type proxyRouter struct {
	pool   *proxypool.Pool
	direct http.RoundTripper // 仅空池可使用原 Transport 直连
	base   *http.Transport   // 继承 TLS/h2 禁用/头超时等参数
	mu     sync.Mutex
	per    map[string]*http.Transport // 规范代理串 → 独立 Transport（静态配置）
}

var (
	errProxyUnavailable = errors.New("proxy: all configured proxies are cooling down")
	errProxyAuth        = errors.New("proxy: authentication required (HTTP 407)")
)

// proxyError 保留 errors.Is/As 语义，但不把底层错误中的代理凭据或响应文本带入日志。
type proxyError struct {
	address string
	cause   error
}

func (e *proxyError) Error() string { return "proxy: transport failed via " + e.address }
func (e *proxyError) Unwrap() error { return e.cause }

// SetProxyPool 注入出站代理池；nil 或空池为空操作（保持直连现状）。
// 必须在 main 设置完 ChatHTTP.Transport 的 ResponseHeaderTimeout 之后调用：
// 母本从当时生效的 Transport 克隆，每个代理分身继承全部连接层加固与超时参数。
func (c *Client) SetProxyPool(pool *proxypool.Pool) {
	if pool == nil || !pool.Enabled() {
		return
	}
	base, ok := c.ChatHTTP.Transport.(*http.Transport)
	if !ok {
		// 测试注入的自定义 RoundTripper：语义未知，不接管（宁缺毋滥）。
		return
	}
	c.HTTP.Transport = &proxyRouter{
		pool:   pool,
		direct: c.ChatHTTP.Transport,
		base:   base,
		per:    map[string]*http.Transport{},
	}
	c.ChatHTTP.Transport = c.HTTP.Transport
}

// RoundTrip 按池轮转；代理耗尽时关闭未发送的 Body，禁止直连兜底。
func (r *proxyRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	px := r.pool.Pick()
	if px == nil {
		if !r.pool.Enabled() {
			return r.direct.RoundTrip(req)
		}
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errProxyUnavailable
	}
	tr := r.transportFor(px)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		r.pool.NoteFail(px)
		roundTripCloseIdle(tr)
		if errors.Is(err, errProxyAuth) {
			return nil, errProxyAuth
		}
		return nil, &proxyError{address: px.String(), cause: err}
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		if resp.Body != nil {
			resp.Body.Close()
		}
		roundTripCloseIdle(tr)
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		r.pool.NoteFail(px)
		return nil, errProxyAuth
	}
	return resp, nil
}

// CloseIdleConnections 实现 closeIdler：清空直连与全部代理分身的空闲连接池
// （ChatStreamContext 传输层失败后的既有清池路径经 chatHTTP().Transport 到这里）。
func (r *proxyRouter) CloseIdleConnections() {
	roundTripCloseIdle(r.direct)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, tr := range r.per {
		tr.CloseIdleConnections()
	}
}

// transportFor 返回该代理专属 Transport（首次按需构造，之后复用）。
// net/http 原生支持 HTTP、HTTPS、SOCKS5/h，保留母本 DialContext 与超时设置。
func (r *proxyRouter) transportFor(px *proxypool.Proxy) *http.Transport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tr, ok := r.per[px.Raw]; ok {
		return tr
	}
	tr := r.base.Clone()
	tr.Proxy = http.ProxyURL(px.URL())
	onConnect := tr.OnProxyConnectResponse
	tr.OnProxyConnectResponse = func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, connectRes *http.Response) error {
		if connectRes.StatusCode == http.StatusProxyAuthRequired {
			return errProxyAuth
		}
		if onConnect != nil {
			return onConnect(ctx, proxyURL, connectReq, connectRes)
		}
		return nil
	}
	r.per[px.Raw] = tr
	return tr
}
