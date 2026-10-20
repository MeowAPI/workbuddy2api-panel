// proxy_bind_config_test.go 代理按账号绑定开关的配置语义：
// 缺省 true（新行为）、显式 false 可回退按请求轮转、代理列表校验仍 fail fast。
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProxyBindAccountDefaultTrue(t *testing.T) {
	c := Default()
	if err := c.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !c.Proxy.BindAccount {
		t.Fatal("proxy.bind_account 缺省应为 true（按账号绑定出口 IP）")
	}
}

func TestProxyBindAccountExplicitFalse(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "c.json")
	if err := os.WriteFile(fp, []byte(`{"proxy":{"bind_account":false,"list":["http://127.0.0.1:7890"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(fp)
	if err != nil {
		t.Fatal(err)
	}
	if c.Proxy.BindAccount {
		t.Fatal("显式 bind_account=false 应回退按请求轮转")
	}
	if len(c.Proxy.List) != 1 {
		t.Fatalf("proxy.list = %v", c.Proxy.List)
	}
}
