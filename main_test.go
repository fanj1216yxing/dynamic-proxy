package main

import (
	"strings"
	"testing"
)

func assertSchemeCoverage(t *testing.T, entries []string, wanted ...string) {
	t.Helper()
	seen := make(map[string]bool)
	for _, entry := range entries {
		seen[detectProxyScheme(entry, "")] = true
	}
	for _, scheme := range wanted {
		if !seen[scheme] {
			t.Fatalf("expected scheme %s in parsed entries, got %v", scheme, seen)
		}
	}
}

func TestParserRegressionClashMixedProtocols(t *testing.T) {
	content := `proxies:
  - {name: vm, type: vmess, server: vm.example.com, port: 443, uuid: 11111111-1111-1111-1111-111111111111, network: ws, tls: true}
  - {name: vl, type: vless, server: vl.example.com, port: 443, uuid: 22222222-2222-2222-2222-222222222222, network: ws, tls: true}
  - {name: hy, type: hy2, server: hy.example.com, port: 443, password: hy-pass, sni: hy.example.com}
  - {name: ss, type: ss, server: ss.example.com, port: 8388, cipher: aes-256-gcm, password: ss-pass}
  - {name: tr, type: trojan, server: tr.example.com, port: 443, password: tr-pass, sni: tr.example.com}
`
	entries, format := parseRegularProxyContentMixed(content)
	if format != "clash" {
		t.Fatalf("expected clash format, got %s", format)
	}
	assertSchemeCoverage(t, entries, "vmess", "vless", "hy2", "ss", "trojan")
}

func TestParserRegressionSingboxExportLikeLines(t *testing.T) {
	content := strings.Join([]string{
		"\ufeffvless://33333333-3333-3333-3333-333333333333@vl2.example.com:443?encryption=none&security=tls",
		"vmess://vm2.example.com:443?id=44444444-4444-4444-4444-444444444444&net=ws&tls=tls",
		"hy2://hy-pass@hy2.example.com:443?sni=hy2.example.com",
		"ss://aes-256-gcm:ss-pass@ss2.example.com:8388",
		"trojan://tr-pass@tr2.example.com:443?sni=tr2.example.com",
	}, "\r\n")
	entries, _ := parseRegularProxyContentMixed(content)
	assertSchemeCoverage(t, entries, "vmess", "vless", "hy2", "ss", "trojan")
}

func TestParserRegressionBase64ExportLike(t *testing.T) {
	plain := strings.Join([]string{
		"vmess://vm3.example.com:443?id=55555555-5555-5555-5555-555555555555&net=ws&tls=tls",
		"vless://66666666-6666-6666-6666-666666666666@vl3.example.com:443?encryption=none",
		"hy2://hy-pass@hy3.example.com:443?sni=hy3.example.com",
		"ss://aes-256-gcm:ss-pass@ss3.example.com:8388",
		"trojan://tr-pass@tr3.example.com:443",
	}, "\n")
	encoded := encodeBase64URLNoPadding([]byte(plain))
	entries, format := parseRegularProxyContentMixed(encoded)
	if !strings.HasPrefix(format, "base64+") {
		t.Fatalf("expected base64 derived format, got %s", format)
	}
	assertSchemeCoverage(t, entries, "vmess", "vless", "hy2", "ss", "trojan")
}

func TestNormalizeMixedProxyEntryCompletesCriticalTLSParams(t *testing.T) {
	config = Config{}
	config.TLSParamPolicy.DefaultALPN = []string{"h2", "http/1.1"}
	entry, ok := normalizeMixedProxyEntry("trojan://pass@example.com:443")
	if !ok {
		t.Fatalf("expected trojan entry to normalize")
	}
	if !strings.Contains(entry, "sni=example.com") {
		t.Fatalf("expected sni filled, got %s", entry)
	}
	if !strings.Contains(entry, "alpn=h2%2Chttp%2F1.1") {
		t.Fatalf("expected alpn filled, got %s", entry)
	}
	if !strings.Contains(entry, "insecure=false") {
		t.Fatalf("expected insecure default false, got %s", entry)
	}
}

func TestShouldAllowInsecureByWhitelist(t *testing.T) {
	config = Config{}
	config.CertVerifyWhitelist.Enabled = true
	config.CertVerifyWhitelist.RequireInsecure = true
	config.CertVerifyWhitelist.AllowedHosts = []string{"allowed.example.com"}
	allowed, host := shouldAllowInsecureByWhitelist("trojan://p@allowed.example.com:443?sni=allowed.example.com&alpn=h2&insecure=true")
	if !allowed || host != "allowed.example.com" {
		t.Fatalf("expected allowed host to pass whitelist, got allowed=%t host=%s", allowed, host)
	}
	allowed, _ = shouldAllowInsecureByWhitelist("trojan://p@allowed.example.com:443?sni=allowed.example.com&alpn=h2")
	if allowed {
		t.Fatalf("expected missing insecure=true to be denied when require_insecure=true")
	}
}
