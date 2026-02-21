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

func TestNormalizeMixedProxyEntryStripsHTTPSParams(t *testing.T) {
	entry := "https://user:pass@1.2.3.4:443?foo=bar#frag"

	normalized, ok := normalizeMixedProxyEntry(entry)
	if !ok {
		t.Fatalf("normalizeMixedProxyEntry returned false")
	}

	expected := "https://user:pass@1.2.3.4:443"
	if normalized != expected {
		t.Fatalf("expected %s, got %s", expected, normalized)
	}
}
