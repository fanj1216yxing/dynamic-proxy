package main

import "testing"

func TestParseMixedProxyKeepsHTTPSScheme(t *testing.T) {
	scheme, addr, auth, header, err := parseMixedProxy("https://user:pass@1.2.3.4:443")
	if err != nil {
		t.Fatalf("parseMixedProxy returned error: %v", err)
	}
	if scheme != "https" {
		t.Fatalf("expected scheme https, got %s", scheme)
	}
	if addr != "1.2.3.4:443" {
		t.Fatalf("expected addr 1.2.3.4:443, got %s", addr)
	}
	if auth == nil || auth.User != "user" || auth.Password != "pass" {
		t.Fatalf("expected auth user/pass, got %#v", auth)
	}
	if header == "" {
		t.Fatalf("expected non-empty Proxy-Authorization header")
	}
}

func TestFilterMixedProxiesBySchemeIncludesHTTPS(t *testing.T) {
	entries := []string{
		"https://2.2.2.2:443",
		"http://1.1.1.1:80",
		"socks5://3.3.3.3:1080",
	}

	filtered := filterMixedProxiesByScheme(entries, map[string]bool{"https": true})
	if len(filtered) != 1 || filtered[0] != "https://2.2.2.2:443" {
		t.Fatalf("expected only https entry, got %#v", filtered)
	}
}

func TestBuildPoolStatusPayloadIncludesHealthyProxyLists(t *testing.T) {
	strictPool := NewProxyPool(0, false)
	relaxedPool := NewProxyPool(0, false)
	cfPool := NewProxyPool(0, false)
	mixedPool := NewProxyPool(0, false)
	mainstreamPool := NewProxyPool(0, false)
	cfMixedPool := NewProxyPool(0, false)

	strictPool.Update([]string{"s1:1"})
	relaxedPool.Update([]string{"r1:1"})
	cfPool.Update([]string{"c1:1"})
	mixedPool.Update([]string{"https://m1:443"})
	mainstreamPool.Update([]string{"vmess://example"})
	cfMixedPool.Update([]string{"https://cfm:443"})

	payload := buildPoolStatusPayload(strictPool, relaxedPool, cfPool, mixedPool, mainstreamPool, cfMixedPool, ":17233")

	allHealthy, ok := payload["all_healthy_proxies"].([]string)
	if !ok {
		t.Fatalf("expected []string all_healthy_proxies, got %#v", payload["all_healthy_proxies"])
	}
	if len(allHealthy) != 6 {
		t.Fatalf("expected 6 healthy proxies, got %d (%#v)", len(allHealthy), allHealthy)
	}

	mixedEntries, ok := payload["http_socks_proxies"].([]string)
	if !ok || len(mixedEntries) != 1 || mixedEntries[0] != "https://m1:443" {
		t.Fatalf("expected mixed http_socks_proxies to include https entry, got %#v", payload["http_socks_proxies"])
	}
}
