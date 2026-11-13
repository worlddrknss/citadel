package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestOutboundPolicy(t *testing.T) {
	strict := outboundPolicy{blockPrivate: true}
	lenient := outboundPolicy{}
	for addr, want := range map[string][2]bool{ // {strict permits, lenient permits}
		"93.184.216.34":       {true, true},
		"2606:4700::1111":     {true, true},
		"127.0.0.1":           {false, false},
		"::1":                 {false, false},
		"::ffff:127.0.0.1":    {false, false},
		"169.254.169.254":     {false, false},
		"fe80::1":             {false, false},
		"fd00:ec2::254":       {false, false},
		"100.100.100.200":     {false, false},
		"0.0.0.0":             {false, false},
		"224.0.0.1":           {false, false},
		"10.1.2.3":            {false, true},
		"172.16.0.1":          {false, true},
		"192.168.1.1":         {false, true},
		"100.64.0.1":          {false, true},
		"fd12:3456::1":        {false, true},
		"::ffff:10.0.0.1":     {false, true},
		"64:ff9b::7f00:1":     {false, false}, // NAT64 of 127.0.0.1
		"64:ff9b::a00:1":      {false, true},  // NAT64 of 10.0.0.1
		"2002:a9fe:a9fe::1":   {false, false}, // 6to4 of 169.254.169.254
		"64:ff9b::5db8:d822":  {true, true},   // NAT64 of a public address
		"::a00:1":             {false, true},  // IPv4-compatible
		"255.255.255.255":     {false, false},
		"198.18.0.1":          {false, true},
		"2001:db8::1":         {true, true},
		"192.0.0.192":         {false, false},
		"[not-an-address]:80": {false, false},
	} {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			if strict.control(errOutboundBlocked)(context.Background(), "tcp", addr, nil) == nil {
				t.Errorf("%s: unparsable address allowed", addr)
			}
			continue
		}
		if got := strict.permits(a); got != want[0] {
			t.Errorf("strict %s: permits=%v, want %v", addr, got, want[0])
		}
		if got := lenient.permits(a); got != want[1] {
			t.Errorf("lenient %s: permits=%v, want %v", addr, got, want[1])
		}
	}
	allowed := outboundPolicy{blockPrivate: true, allowed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")}}
	for addr, want := range map[string]bool{"10.9.9.9": true, "127.0.0.1": true, "127.0.0.2": false, "192.168.0.1": false, "::ffff:10.0.0.1": true} {
		if got := allowed.permits(netip.MustParseAddr(addr)); got != want {
			t.Errorf("allowed %s: permits=%v, want %v", addr, got, want)
		}
	}
	if !(outboundPolicy{allowLoopback: true}).permits(netip.MustParseAddr("127.0.0.1")) {
		t.Error("allowLoopback did not permit loopback")
	}
}

func TestGuardedHTTPClient(t *testing.T) {
	var hits int
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer site.Close()

	_, err := newGuardedHTTPClient(nil, 5*time.Second).Get(site.URL)
	if err == nil || !isOutboundBlocked(err) {
		t.Fatalf("guarded client reached loopback: err=%v", err)
	}
	if hits != 0 {
		t.Fatalf("loopback server was hit %d times", hits)
	}
	c := newGuardedHTTPClient([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, 5*time.Second)
	resp, err := c.Get(site.URL + "/redirect")
	if err != nil {
		t.Fatalf("allowed loopback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed: status %d", resp.StatusCode)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	resp, err = c.Get(site.URL)
	if err != nil {
		t.Fatalf("environment proxy was used: %v", err)
	}
	resp.Body.Close()
}
