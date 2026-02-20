package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNormalizeMixedProxyEntry_PreservesCredentials(t *testing.T) {
	got, ok := normalizeMixedProxyEntry("http://user:pass@127.0.0.1:8080")
	if !ok {
		t.Fatalf("expected normalization success")
	}
	if got != "http://user:pass@127.0.0.1:8080" {
		t.Fatalf("expected credentials to be preserved, got %s", got)
	}
}

func TestParseMixedProxy_WithCredentials(t *testing.T) {
	scheme, addr, auth, httpAuthHeader, err := parseMixedProxy("http://user:pass@127.0.0.1:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "http" {
		t.Fatalf("expected scheme http, got %s", scheme)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatalf("expected addr 127.0.0.1:8080, got %s", addr)
	}
	if auth == nil || auth.User != "user" || auth.Password != "pass" {
		t.Fatalf("unexpected parsed auth: %#v", auth)
	}
	if httpAuthHeader != "Basic dXNlcjpwYXNz" {
		t.Fatalf("unexpected Proxy-Authorization value: %s", httpAuthHeader)
	}
}

func TestParseRegularProxyContent_Base64Plain(t *testing.T) {
	raw := "1.1.1.1:80\n2.2.2.2:1080\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	proxies, format := parseRegularProxyContent(encoded)
	if format != "base64+plain" {
		t.Fatalf("expected format base64+plain, got %s", format)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d (%v)", len(proxies), proxies)
	}
}

func TestParseRegularProxyContentMixed_Base64Plain(t *testing.T) {
	raw := strings.Join([]string{
		"socks5://1.1.1.1:1080",
		"http://2.2.2.2:8080",
	}, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	proxies, format := parseRegularProxyContentMixed(encoded)
	if format != "base64+plain" {
		t.Fatalf("expected format base64+plain, got %s", format)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d (%v)", len(proxies), proxies)
	}
}

func TestParseProxySwitchInterval_DefaultMinutes(t *testing.T) {
	d, rotateEveryRequest, err := parseProxySwitchInterval("30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rotateEveryRequest {
		t.Fatalf("expected rotateEveryRequest=false")
	}
	if d.Minutes() != 30 {
		t.Fatalf("expected 30 minutes, got %v", d)
	}
}

func TestParseProxySwitchInterval_Now(t *testing.T) {
	d, rotateEveryRequest, err := parseProxySwitchInterval("now")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rotateEveryRequest {
		t.Fatalf("expected rotateEveryRequest=true")
	}
	if d != 0 {
		t.Fatalf("expected duration 0 for now, got %v", d)
	}
}

func TestParseProxySwitchInterval_Invalid(t *testing.T) {
	_, _, err := parseProxySwitchInterval("abc")
	if err == nil {
		t.Fatalf("expected error for invalid value")
	}
}

func TestFilterMixedProxiesByScheme(t *testing.T) {
	entries := []string{
		"http://1.1.1.1:80",
		"socks5://2.2.2.2:1080",
		"vmess://3.3.3.3:443",
		"vless://4.4.4.4:443",
	}

	httpSocks := filterMixedProxiesByScheme(entries, httpSocksMixedSchemes)
	if len(httpSocks) != 2 {
		t.Fatalf("expected 2 http/socks entries, got %d (%v)", len(httpSocks), httpSocks)
	}

	mainstream := filterMixedProxiesByScheme(entries, mainstreamMixedSchemes)
	if len(mainstream) != 2 {
		t.Fatalf("expected 2 mainstream entries, got %d (%v)", len(mainstream), mainstream)
	}
}

func TestParseClashSubscriptionMixed_SupportsSSAndTrojan(t *testing.T) {
	content := `proxies:
  - type: ss
    server: 1.2.3.4
    port: 443
    cipher: aes-128-gcm
    password: secret
  - type: trojan
    server: 5.6.7.8
    port: 8443
    password: token
`

	proxies, ok := parseClashSubscriptionMixed(content)
	if !ok {
		t.Fatalf("expected clash mixed parsing to succeed")
	}

	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d (%v)", len(proxies), proxies)
	}
}

func TestNormalizeMixedProxyEntry_SSBase64(t *testing.T) {
	entry := "ss://YWVzLTEyOC1nY206c2VjcmV0QDEuMi4zLjQ6NDQz"
	got, ok := normalizeMixedProxyEntry(entry)
	if !ok {
		t.Fatalf("expected normalization success")
	}
	if got != "ss://aes-128-gcm:secret@1.2.3.4:443" {
		t.Fatalf("unexpected normalized ss entry: %s", got)
	}
}

func TestResolveMixedDialTarget_NonHTTPSocksUse17290(t *testing.T) {
	dialScheme, dialAddr, useAuth := resolveMixedDialTarget("vless", "8.8.8.8:443")
	if dialScheme != "https" {
		t.Fatalf("expected https dial scheme, got %s", dialScheme)
	}
	if dialAddr != "8.8.8.8:17290" {
		t.Fatalf("expected 17290 relay port, got %s", dialAddr)
	}
	if !useAuth {
		t.Fatalf("expected relay mode to preserve upstream auth for vless")
	}
}

func TestParseSpecialProxyURLMixed_RecognizesMainstreamSchemes(t *testing.T) {
	content := strings.Join([]string{
		"trojan://password@1.2.3.4:443 # trojan node",
		"ss://5.6.7.8:443 # ss node",
	}, "\n")

	proxies := parseSpecialProxyURLMixed(content)
	if len(proxies) != 2 {
		t.Fatalf("expected 2 parsed proxies, got %d (%v)", len(proxies), proxies)
	}

	mainstream := filterMixedProxiesByScheme(proxies, mainstreamMixedSchemes)
	if len(mainstream) != 2 {
		t.Fatalf("expected 2 mainstream proxies, got %d (%v)", len(mainstream), mainstream)
	}
}

func TestResolveMixedDialTarget_VMesseRelayDisablesAuth(t *testing.T) {
	dialScheme, dialAddr, useAuth := resolveMixedDialTarget("vmess", "8.8.4.4:443")
	if dialScheme != "https" {
		t.Fatalf("expected https dial scheme, got %s", dialScheme)
	}
	if dialAddr != "8.8.4.4:17290" {
		t.Fatalf("expected 17290 relay port, got %s", dialAddr)
	}
	if useAuth {
		t.Fatalf("expected vmess relay mode to disable upstream auth")
	}
}

func TestParseMixedProxy_VLESSAuthPreservedForRelay(t *testing.T) {
	scheme, addr, auth, httpAuthHeader, err := parseMixedProxy("vless://uuid-123@9.9.9.9:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "vless" || addr != "9.9.9.9:443" {
		t.Fatalf("unexpected parsed proxy: %s %s", scheme, addr)
	}
	if auth == nil || auth.User != "uuid-123" {
		t.Fatalf("expected vless uuid to be captured as auth user, got %#v", auth)
	}
	if httpAuthHeader == "" {
		t.Fatalf("expected Proxy-Authorization header to be generated")
	}

	_, _, useAuth := resolveMixedDialTarget(scheme, addr)
	if !useAuth {
		t.Fatalf("expected vless relay path to keep auth")
	}
}
