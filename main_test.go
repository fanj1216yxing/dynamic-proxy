package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

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
