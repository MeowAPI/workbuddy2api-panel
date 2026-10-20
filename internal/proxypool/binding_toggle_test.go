package proxypool

import "testing"

func TestBindingToggleReflectsActiveRoutingAndRestoresAssignment(t *testing.T) {
	p, err := New([]string{"http://user:secret@a:80", "http://b:80"})
	if err != nil {
		t.Fatal(err)
	}
	original := p.PickFor("account")
	if original == nil {
		t.Fatal("expected initial proxy")
	}
	for range failThreshold {
		p.NoteFail(original)
	}
	p.SetBindAccount(false)
	if addr, ok := p.BindingOf("account"); ok || addr != "" {
		t.Fatalf("disabled binding still visible: addr=%q ok=%t", addr, ok)
	}
	views, _ := p.Snapshot()
	for _, v := range views {
		if v.Bound != 0 {
			t.Fatalf("disabled binding counted as active: %+v", v)
		}
	}
	// Rotating mode can use the healthy alternative, without replacing the saved binding.
	if picked := p.PickFor("account"); picked == nil || picked == original {
		t.Fatalf("rotating mode failed to use the healthy proxy: %v", picked)
	}
	p.SetBindAccount(true)
	addr, ok := p.BindingOf("account")
	if !ok || addr != "a:80" {
		t.Fatalf("original binding lost or credentials exposed: %q %t", addr, ok)
	}
	if picked := p.PickFor("account"); picked != nil {
		t.Fatalf("reenabling bypassed the original proxy cooldown: %v", picked)
	}
	views, _ = p.Snapshot()
	if views[0].Bound != 1 || !views[0].Frozen || views[1].Bound != 0 {
		t.Fatalf("mode toggle changed binding or cooling state: %+v", views)
	}
}
