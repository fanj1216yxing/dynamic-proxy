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

func TestNormalizeMixedProxyEntryVLESSDropsFragmentKeepsQuery(t *testing.T) {
	entry := "vless://123e4567-e89b-12d3-a456-426614174000@1.2.3.4:443?encryption=none&security=tls&type=ws#node-name"

	normalized, ok := normalizeMixedProxyEntry(entry)
	if !ok {
		t.Fatalf("normalizeMixedProxyEntry returned false")
	}

	expected := "vless://123e4567-e89b-12d3-a456-426614174000@1.2.3.4:443?encryption=none&security=tls&type=ws"
	if normalized != expected {
		t.Fatalf("expected %s, got %s", expected, normalized)
	}
}

func TestParseSpecialProxyURLMixedKeepsFullVLESSAndVMESS(t *testing.T) {
	vmessRaw := "vmess://eyJhZGQiOiIxLjEuMS4xIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwibmV0Ijoid3MiLCJwYXRoIjoiLyIsInRscyI6InRscyJ9"
	vlessRaw := "vless://123e4567-e89b-12d3-a456-426614174000@2.2.2.2:443?encryption=none&security=tls&type=ws#name"

	parsed := parseSpecialProxyURLMixed(vmessRaw + "\n" + vlessRaw)
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed entries, got %d: %#v", len(parsed), parsed)
	}

	if _, ok := parseVMESSNode(parsed[0]); !ok {
		t.Fatalf("expected normalized vmess entry, got %s", parsed[0])
	}

	expectedVLESS := "vless://123e4567-e89b-12d3-a456-426614174000@2.2.2.2:443?encryption=none&security=tls&type=ws"
	if parsed[1] != expectedVLESS {
		t.Fatalf("expected vless entry %s, got %s", expectedVLESS, parsed[1])
	}
}
