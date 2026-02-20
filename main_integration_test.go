package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func poolSize(p *ProxyPool) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

func startForwardProxy(t *testing.T, requireAuth bool, expectedAuth string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:"+mainstreamMixedRelayPort)
	if err != nil {
		t.Fatalf("listen relay proxy: %v", err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireAuth && r.Header.Get("Proxy-Authorization") != expectedAuth {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		if r.Method == http.MethodConnect {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack unsupported", http.StatusInternalServerError)
				return
			}
			clientConn, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			defer clientConn.Close()
			_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = buf.Flush()

			targetConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
			if err != nil {
				return
			}
			defer targetConn.Close()
			go io.Copy(targetConn, clientConn)
			io.Copy(clientConn, targetConn)
			return
		}

		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	go func() { _ = http.Serve(ln, h) }()
	t.Cleanup(func() { _ = ln.Close() })
}

func TestIntegration_NonStandardConfigAndMainstreamPool(t *testing.T) {
	targetTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer targetTLS.Close()
	mixedHealthCheckURL = targetTLS.URL
	t.Cleanup(func() { mixedHealthCheckURL = defaultMixedHealthCheckURL })

	var hits int32
	subscriptionYAML := `proxies:
  - type: vmess
    server: 127.0.0.1
    port: 18080
    uuid: 11111111-1111-1111-1111-111111111111
  - type: vless
    server: 127.0.0.1
    port: 18081
    uuid: 22222222-2222-2222-2222-222222222222
  - type: hy2
    server: 127.0.0.1
    port: 18082
    password: hy2-secret
`
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, subscriptionYAML)
	}))
	defer source.Close()

	cfg := Config{}
	cfg.ProxyListURLs = []string{source.URL}
	cfg.HealthCheckConcurrency = 4
	cfg.HealthCheck.TotalTimeoutSeconds = 8
	cfg.HealthCheck.TLSHandshakeThresholdSeconds = 8
	cfg.UpdateIntervalMinutes = 1
	cfg.ProxySwitchIntervalMin = "1"
	config = cfg

	parsed, format := parseRegularProxyContentMixed(subscriptionYAML)
	t.Logf("[%s] parse format=%s count=%d", time.Now().Format(time.RFC3339), format, len(parsed))
	if len(parsed) != 3 {
		t.Fatalf("expected 3 proxies, got %d: %v", len(parsed), parsed)
	}

	joined := strings.Join(parsed, "\n")
	if !strings.Contains(joined, "vless://22222222-2222-2222-2222-222222222222@127.0.0.1:18081") {
		t.Fatalf("missing normalized vless credential entry: %v", parsed)
	}
	if !strings.Contains(joined, "hy2://hy2-secret@127.0.0.1:18082") {
		t.Fatalf("missing normalized hy2 credential entry: %v", parsed)
	}

	startForwardProxy(t, false, "")

	mixedPool := NewProxyPool(time.Minute, false)
	mainstreamPool := NewProxyPool(time.Minute, false)
	cfPool := NewProxyPool(time.Minute, false)

	t.Logf("[%s] monitor :17290 mainstream pool size=%d", time.Now().Format(time.RFC3339), poolSize(mainstreamPool))
	updateMixedProxyPool(mixedPool, mainstreamPool, cfPool)

	deadline := time.Now().Add(10 * time.Second)
	for {
		sz := poolSize(mainstreamPool)
		t.Logf("[%s] monitor :17290 mainstream pool size=%d", time.Now().Format(time.RFC3339), sz)
		if sz > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mainstream pool size did not grow above zero")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestIntegration_VlessHy2AuthRequired(t *testing.T) {
	targetTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer targetTLS.Close()
	mixedHealthCheckURL = targetTLS.URL
	t.Cleanup(func() { mixedHealthCheckURL = defaultMixedHealthCheckURL })

	config.HealthCheck.TotalTimeoutSeconds = 8
	config.HealthCheck.TLSHandshakeThresholdSeconds = 8

	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	startForwardProxy(t, true, expected)

	for _, entry := range []string{
		"vless://user:pass@127.0.0.1:18081",
		"hy2://user:pass@127.0.0.1:18082",
	} {
		if !checkMixedProxyHealth(entry, false) {
			t.Fatalf("expected health check pass for %s", entry)
		}
	}

	for _, entry := range []string{
		"vless://127.0.0.1:18081",
		"hy2://127.0.0.1:18082",
	} {
		if checkMixedProxyHealth(entry, false) {
			t.Fatalf("expected health check fail without credentials for %s", entry)
		}
	}
}

func TestIntegration_ParseLocalSamples(t *testing.T) {
	v2Raw, err := os.ReadFile("v2.yaml")
	if err != nil {
		t.Fatalf("read v2.yaml: %v", err)
	}
	v2Parsed, format := parseRegularProxyContentMixed(string(v2Raw))
	t.Logf("[%s] v2.yaml format=%s parsed=%d", time.Now().Format(time.RFC3339), format, len(v2Parsed))
	if len(v2Parsed) == 0 {
		t.Fatal("v2.yaml should parse at least one proxy")
	}

	proxiesRaw, err := os.ReadFile("proxies.yaml")
	if err != nil {
		t.Fatalf("read proxies.yaml: %v", err)
	}
	proxiesParsed, proxiesFormat := parseRegularProxyContentMixed(string(proxiesRaw))
	t.Logf("[%s] proxies.yaml format=%s parsed=%d", time.Now().Format(time.RFC3339), proxiesFormat, len(proxiesParsed))
	if len(proxiesParsed) == 0 {
		t.Fatal("proxies.yaml should parse at least one proxy")
	}
}

func TestListEndpointForHTTPProxyPool(t *testing.T) {
	pool := NewProxyPool(time.Minute, false)
	pool.Update([]string{"1.1.1.1:80", "2.2.2.2:80"})
	_, _ = pool.GetNext()

	cfg := Config{}
	cfg.Auth.Username = "admin"
	cfg.Auth.Password = "secret"
	config = cfg

	req := httptest.NewRequest(http.MethodGet, "http://local/list", nil)
	rr := httptest.NewRecorder()
	handleHTTPProxy(rr, req, pool, nil, "MIXED")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status code, got: %d body=%s", rr.Code, rr.Body.String())
	}

	reqOK := httptest.NewRequest(http.MethodGet, "http://local/list", nil)
	reqOK.SetBasicAuth("admin", "secret")
	rrOK := httptest.NewRecorder()
	handleHTTPProxy(rrOK, reqOK, pool, nil, "MIXED")

	if rrOK.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d body=%s", rrOK.Code, rrOK.Body.String())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(rrOK.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if int(payload["proxy_count"].(float64)) != 2 {
		t.Fatalf("unexpected proxy_count: %+v", payload)
	}
	if payload["current_proxy"].(string) == "" {
		t.Fatalf("current_proxy should not be empty: %+v", payload)
	}
}

func TestMainstreamMixedFallbackToHTTPSocksPool(t *testing.T) {
	cfg := Config{}
	config = cfg

	mainstreamPool := NewProxyPool(time.Minute, false)
	fallbackPool := NewProxyPool(time.Minute, false)
	fallbackPool.Update([]string{"socks5://127.0.0.1:19090"})

	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	rr := httptest.NewRecorder()

	handleHTTPProxy(rr, req, mainstreamPool, fallbackPool, "MAINSTREAM-MIXED")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected bad gateway from unreachable fallback proxy, got %d body=%s", rr.Code, rr.Body.String())
	}
}
