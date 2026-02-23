package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startBlackholeServer(t *testing.T) (addr string, stop func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start blackhole server: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				<-done
				_ = c.Close()
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
	}
}

func TestCheckProxyHealthWithSettingsDetailed_BlackholeProxyTimesOut(t *testing.T) {
	proxyAddr, stop := startBlackholeServer(t)
	defer stop()

	settings := HealthCheckSettings{
		TotalTimeoutSeconds:          1,
		TLSHandshakeThresholdSeconds: 1,
	}

	start := time.Now()
	ok, err := checkProxyHealthWithSettingsDetailed(proxyAddr, true, settings)
	elapsed := time.Since(start)

	if ok {
		t.Fatalf("expected proxy to be unhealthy for blackhole server")
	}
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("health check should timeout quickly, took %v (err=%v)", elapsed, err)
	}
}

func TestHealthCheckProxiesSingleStage_ProgressCanReach100WithBlackholeInput(t *testing.T) {
	proxyAddr, stop := startBlackholeServer(t)
	defer stop()

	config = Config{HealthCheckConcurrency: 4}

	settings := HealthCheckSettings{
		TotalTimeoutSeconds:          1,
		TLSHandshakeThresholdSeconds: 1,
	}

	proxies := []string{
		"127.0.0.1:1",
		"invalid-entry",
		proxyAddr,
		fmt.Sprintf("%s:99999", "127.0.0.1"),
	}

	start := time.Now()
	result := healthCheckProxiesSingleStage(proxies, settings)
	elapsed := time.Since(start)

	if len(result.Strict) != 0 || len(result.Relaxed) != 0 || len(result.CFPass) != 0 {
		t.Fatalf("expected all proxies to fail in this test scenario")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("batch should complete without hanging, took %v", elapsed)
	}
}

func TestCheckMainstreamProxyHealth_RespectsTimeoutForSocksEntries(t *testing.T) {
	proxyAddr, stop := startBlackholeServer(t)
	defer stop()

	config = Config{
		HealthCheck: HealthCheckSettings{
			TotalTimeoutSeconds:          1,
			TLSHandshakeThresholdSeconds: 1,
		},
	}

	start := time.Now()
	status := checkMainstreamProxyHealth("socks5://"+proxyAddr, false)
	elapsed := time.Since(start)

	if status.Healthy {
		t.Fatalf("expected blackhole socks proxy to be unhealthy")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("mixed health check should stop by timeout, got %v", elapsed)
	}
}

func TestHealthCheckMixedProxies_HealthyCanGrowUnderSlowFailures(t *testing.T) {
	oldHealthChecker := mixedProxyHealthChecker
	oldCFChecker := mixedCFBypassChecker
	defer func() {
		mixedProxyHealthChecker = oldHealthChecker
		mixedCFBypassChecker = oldCFChecker
	}()

	config = Config{HealthCheckConcurrency: 3}

	var healthySeen atomic.Int64
	mixedProxyHealthChecker = func(proxyEntry string, strictMode bool) proxyHealthStatus {
		switch proxyEntry {
		case "healthy-a", "healthy-b":
			healthySeen.Add(1)
			return proxyHealthStatus{Healthy: true, Scheme: "http", Category: healthFailureNone}
		default:
			time.Sleep(120 * time.Millisecond)
			return proxyHealthStatus{Healthy: false, Scheme: "socks5", Category: healthFailureTimeout}
		}
	}
	mixedCFBypassChecker = func(proxyEntry string) bool { return false }

	result := healthCheckMixedProxies([]string{"healthy-a", "slow-1", "slow-2", "healthy-b", "slow-3"})
	if len(result.Healthy) != 2 {
		t.Fatalf("expected 2 healthy proxies, got %d", len(result.Healthy))
	}
	if healthySeen.Load() != 2 {
		t.Fatalf("expected healthy checker to mark 2 proxies")
	}
}

func TestHealthCheckMixedProxies_EmptyPool(t *testing.T) {
	oldHealthChecker := mixedProxyHealthChecker
	defer func() { mixedProxyHealthChecker = oldHealthChecker }()
	mixedProxyHealthChecker = func(proxyEntry string, strictMode bool) proxyHealthStatus {
		t.Fatalf("health checker should not be called for empty pool")
		return proxyHealthStatus{}
	}
	config = Config{HealthCheckConcurrency: 5}

	result := healthCheckMixedProxies(nil)
	if len(result.Healthy) != 0 || len(result.CFPass) != 0 {
		t.Fatalf("expected empty result for empty pool")
	}
}

func TestMergeUniqueMixedEntries_Deduplicates(t *testing.T) {
	merged := mergeUniqueMixedEntries([]string{"a", "a", "b"}, []string{"b", "c", ""})
	if len(merged) != 3 {
		t.Fatalf("expected 3 unique entries, got %d (%v)", len(merged), merged)
	}
}

func TestHealthCheckMixedProxies_ConcurrencyLimitRespected(t *testing.T) {
	oldHealthChecker := mixedProxyHealthChecker
	defer func() { mixedProxyHealthChecker = oldHealthChecker }()
	config = Config{HealthCheckConcurrency: 2}

	var running atomic.Int64
	var maxRunning atomic.Int64
	mixedProxyHealthChecker = func(proxyEntry string, strictMode bool) proxyHealthStatus {
		current := running.Add(1)
		for {
			prev := maxRunning.Load()
			if current <= prev || maxRunning.CompareAndSwap(prev, current) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		running.Add(-1)
		return proxyHealthStatus{Healthy: false, Scheme: "http", Category: healthFailureTimeout}
	}

	healthCheckMixedProxies([]string{"p1", "p2", "p3", "p4", "p5", "p6"})
	if maxRunning.Load() > 2 {
		t.Fatalf("expected max concurrency <=2, got %d", maxRunning.Load())
	}
}

func TestReorderMixedHealthCheckQueue_PreservesEntries(t *testing.T) {
	input := []string{"slow-1", "slow-2", "healthy-a", "healthy-b", "slow-3", "slow-4"}
	reordered := reorderMixedHealthCheckQueue(input)

	if len(reordered) != len(input) {
		t.Fatalf("expected same size, got %d vs %d", len(reordered), len(input))
	}

	sortedInput := slices.Clone(input)
	sortedOutput := slices.Clone(reordered)
	slices.Sort(sortedInput)
	slices.Sort(sortedOutput)
	if !slices.Equal(sortedInput, sortedOutput) {
		t.Fatalf("reordered queue changed entries: in=%v out=%v", sortedInput, sortedOutput)
	}
}

func TestHealthCheckMixedProxies_ReorderingAvoidsHealthyStarvation(t *testing.T) {
	oldHealthChecker := mixedProxyHealthChecker
	defer func() { mixedProxyHealthChecker = oldHealthChecker }()

	config = Config{HealthCheckConcurrency: 2}

	firstHealthyAt := int64(0)
	var checkedOrder atomic.Int64
	mixedProxyHealthChecker = func(proxyEntry string, strictMode bool) proxyHealthStatus {
		idx := checkedOrder.Add(1)
		if proxyEntry == "healthy-late" {
			firstHealthyAt = idx
			return proxyHealthStatus{Healthy: true, Scheme: "http", Category: healthFailureNone}
		}
		time.Sleep(40 * time.Millisecond)
		return proxyHealthStatus{Healthy: false, Scheme: "http", Category: healthFailureTimeout}
	}

	result := healthCheckMixedProxies([]string{
		"slow-1", "slow-2", "slow-3", "slow-4", "slow-5", "slow-6", "slow-7", "slow-8", "healthy-late",
	})

	if len(result.Healthy) != 1 {
		t.Fatalf("expected one healthy proxy, got %d", len(result.Healthy))
	}
	if firstHealthyAt == 0 {
		t.Fatalf("healthy proxy was never checked")
	}
	if firstHealthyAt >= 9 {
		t.Fatalf("healthy proxy should not be starved to queue tail, first healthy idx=%d", firstHealthyAt)
	}
}

func TestMixedSchedulerComparisonMetrics(t *testing.T) {
	oldHealthChecker := mixedProxyHealthChecker
	defer func() { mixedProxyHealthChecker = oldHealthChecker }()
	config = Config{HealthCheckConcurrency: 20}

	proxies := make([]string, 0, 1000)
	for i := 0; i < 800; i++ {
		proxies = append(proxies, fmt.Sprintf("slow-%d", i))
	}
	for i := 0; i < 200; i++ {
		proxies = append(proxies, fmt.Sprintf("healthy-%d", i))
	}

	checker := func(proxyEntry string) proxyHealthStatus {
		if len(proxyEntry) >= 7 && proxyEntry[:7] == "healthy" {
			time.Sleep(5 * time.Millisecond)
			return proxyHealthStatus{Healthy: true, Scheme: "http", Category: healthFailureNone}
		}
		time.Sleep(120 * time.Millisecond)
		return proxyHealthStatus{Healthy: false, Scheme: "http", Category: healthFailureTimeout}
	}

	run := func(queue []string) (time.Duration, int) {
		var checked atomic.Int64
		var healthy atomic.Int64
		jobs := make(chan string, 80)
		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < config.HealthCheckConcurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for entry := range jobs {
					status := checker(entry)
					if status.Healthy {
						healthy.Add(1)
					}
					checked.Add(1)
				}
			}()
		}
		for _, e := range queue {
			jobs <- e
		}
		close(jobs)
		wg.Wait()
		_ = checked.Load()
		return time.Since(start), int(healthy.Load())
	}

	fifoDuration, fifoHealthy := run(proxies)
	reorderedDuration, reorderedHealthy := run(reorderMixedHealthCheckQueue(proxies))

	t.Logf("scheduler_metrics fifo_duration=%s reordered_duration=%s fifo_healthy=%d reordered_healthy=%d", fifoDuration, reorderedDuration, fifoHealthy, reorderedHealthy)
	if reorderedHealthy != fifoHealthy {
		t.Fatalf("healthy count mismatch")
	}
}

func TestMixedHealthSettingsForProtocol_UsesOverrides(t *testing.T) {
	config = Config{}
	config.HealthCheckTwoStage.StageOne = HealthCheckSettings{TotalTimeoutSeconds: 4, TLSHandshakeThresholdSeconds: 2}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 8, TLSHandshakeThresholdSeconds: 4}
	config.HealthCheckProtocolOverrides = map[string]TwoStageHealthCheckSettings{
		"vmess": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 15, TLSHandshakeThresholdSeconds: 8},
		},
	}

	stage1 := mixedHealthSettingsForProtocol("vmess", 1)
	stage2 := mixedHealthSettingsForProtocol("vmess", 2)
	fallback := mixedHealthSettingsForProtocol("socks5", 2)

	if stage1.TotalTimeoutSeconds != 6 || stage1.TLSHandshakeThresholdSeconds != 3 {
		t.Fatalf("unexpected vmess stage1 override: %+v", stage1)
	}
	if stage2.TotalTimeoutSeconds != 15 || stage2.TLSHandshakeThresholdSeconds != 8 {
		t.Fatalf("unexpected vmess stage2 override: %+v", stage2)
	}
	if fallback.TotalTimeoutSeconds != 8 || fallback.TLSHandshakeThresholdSeconds != 4 {
		t.Fatalf("unexpected fallback stage2 settings: %+v", fallback)
	}
}

func TestHealthCheckMixedProxies_TwoStageStage1FastDrop(t *testing.T) {
	proxyAddr, stop := startBlackholeServer(t)
	defer stop()

	config = Config{HealthCheckConcurrency: 2}
	config.HealthCheckTwoStage.Enabled = true
	config.HealthCheckTwoStage.StageOne = HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 1}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 1}
	config.HealthCheckProtocolOverrides = map[string]TwoStageHealthCheckSettings{}

	start := time.Now()
	result := healthCheckMixedProxies([]string{"socks5://" + proxyAddr})
	elapsed := time.Since(start)

	if len(result.Healthy) != 0 {
		t.Fatalf("expected stage1 drop for blackhole proxy")
	}
	if elapsed > 4*time.Second {
		t.Fatalf("two-stage mixed health check should stop quickly, got %v", elapsed)
	}
}

func TestParseMixedProxy_MainstreamAndMalformed_TableDriven(t *testing.T) {
	vmessPayload, err := json.Marshal(vmessNode{V: "2", Add: "vmess.example.com", Port: "443", ID: "11111111-1111-1111-1111-111111111111", Net: "ws", TLS: "tls", Host: "cdn.example.com", Path: "/ws", SNI: "sni.example.com"})
	if err != nil {
		t.Fatalf("failed to prepare vmess payload: %v", err)
	}

	tests := []struct {
		name       string
		entry      string
		wantScheme string
		wantAddr   string
		wantErr    bool
	}{
		{
			name:       "vmess v2rayn json",
			entry:      "vmess://" + base64.StdEncoding.EncodeToString(vmessPayload),
			wantScheme: "vmess",
			wantAddr:   "vmess.example.com:443",
		},
		{
			name:       "vless reality tls",
			entry:      "vless://22222222-2222-2222-2222-222222222222@vless.example.com:443?security=tls&type=ws&host=edge.example.com&path=%2Fvless&sni=reality.example.com&pbk=pubkey&sid=ab12&flow=xtls-rprx-vision",
			wantScheme: "vless",
			wantAddr:   "vless.example.com:443",
		},
		{
			name:       "hy2 with sni and alpn",
			entry:      "hy2://secret-password@hy2.example.com:8443?sni=hy2.example.com&alpn=h3,h2",
			wantScheme: "hy2",
			wantAddr:   "hy2.example.com:8443",
		},
		{
			name:    "missing uuid",
			entry:   "vless://@vless.example.com:443?security=tls",
			wantErr: true,
		},
		{
			name:    "missing host",
			entry:   "hy2://secret@:8443?sni=test.example.com",
			wantErr: true,
		},
		{
			name:    "invalid port",
			entry:   "vless://33333333-3333-3333-3333-333333333333@vless.example.com:abc?security=tls",
			wantErr: true,
		},
		{
			name:    "bad vmess base64",
			entry:   "vmess://@@@@not-base64@@@@",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme, addr, _, _, err := parseMixedProxy(tc.entry)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected parse error for %q", tc.entry)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if scheme != tc.wantScheme || addr != tc.wantAddr {
				t.Fatalf("unexpected parse result: got scheme=%s addr=%s, want scheme=%s addr=%s", scheme, addr, tc.wantScheme, tc.wantAddr)
			}
		})
	}
}

type delayDialer struct {
	delay      time.Duration
	targetAddr string
}

func (d delayDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.targetAddr)
}

func TestMainstreamProxyHealthStageChecks_HighLatencyViaMockDialer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	oldBuilder := upstreamDialerBuilder
	oldURL := mixedHealthCheckURL
	defer func() {
		upstreamDialerBuilder = oldBuilder
		mixedHealthCheckURL = oldURL
	}()

	targetAddr := strings.TrimPrefix(srv.URL, "http://")
	mixedHealthCheckURL = srv.URL
	upstreamDialerBuilder = func(entry string) (UpstreamDialer, string, error) {
		switch entry {
		case "stage1-slow":
			return delayDialer{delay: 120 * time.Millisecond, targetAddr: targetAddr}, "socks5", nil
		case "stage2-slow":
			return delayDialer{delay: 80 * time.Millisecond, targetAddr: targetAddr}, "socks5", nil
		default:
			return nil, "", fmt.Errorf("unexpected entry: %s", entry)
		}
	}

	stage1 := checkMainstreamProxyHealthStage1("stage1-slow", HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 0})
	if stage1.Category != healthFailureTimeout {
		t.Fatalf("expected stage1 timeout category, got %+v", stage1)
	}

	stage2 := checkMainstreamProxyHealthStage2("stage2-slow", false, HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 0})
	if !stage2.Status.Healthy {
		t.Fatalf("expected stage2 to pass when only overall GET latency is slow, got %+v", stage2.Status)
	}
}

func TestBuildUpstreamDialer_MainstreamSchemesSupported(t *testing.T) {
	entries := []string{
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"vmess.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111"}`)),
		"vless://11111111-1111-1111-1111-111111111111@vless.example.com:443?security=tls&type=ws",
		"hy2://password@hy2.example.com:8443?sni=hy2.example.com&alpn=h3,h2",
	}

	for _, entry := range entries {
		t.Run(entry, func(t *testing.T) {
			_, scheme, err := buildUpstreamDialer(entry)
			if err != nil {
				t.Fatalf("buildUpstreamDialer should support %s, got err=%v", entry, err)
			}
			if scheme == "" {
				t.Fatalf("scheme should not be empty for %s", entry)
			}
		})
	}
}

func TestParseClashSubscriptionForMixed_PreservesMainstreamFields(t *testing.T) {
	content := `proxies:
  - name: vmess-node
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    network: ws
    tls: true
    sni: sni.vmess.example.com
    alpn: [h2,h3]
    ws-opts:
      path: /vmess
      headers:
        Host: ws.vmess.example.com
  - name: vless-node
    type: vless
    server: vless.example.com
    port: 8443
    uuid: 22222222-2222-2222-2222-222222222222
    network: ws
    tls: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: pubkey123
      short-id: abcd
    ws-opts:
      path: /vless
      headers:
        Host: ws.vless.example.com
  - name: hy2-node
    type: hy2
    server: hy2.example.com
    port: 9443
    password: hy2pass
    sni: hy2.sni.example.com
    alpn: [h3,h2]
    hysteria2:
      obfs: salamander
      obfs-password: obfspass
`

	entries, ok := parseClashSubscriptionForMixed(content)
	if !ok {
		t.Fatalf("expected mixed clash subscription to parse")
	}
	joined := strings.Join(entries, "\n")

	checks := []string{
		"vmess://vmess.example.com:443?",
		"network=ws",
		"path=%2Fvmess",
		"host=ws.vmess.example.com",
		"sni=sni.vmess.example.com",
		"alpn=h2%2Ch3",
		"vless://22222222-2222-2222-2222-222222222222@vless.example.com:8443?",
		"flow=xtls-rprx-vision",
		"fp=chrome",
		"pbk=pubkey123",
		"sid=abcd",
		"hy2://hy2pass@hy2.example.com:9443?",
		"obfs=salamander",
		"obfs-password=obfspass",
	}
	for _, fragment := range checks {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("expected parsed entries to preserve %q, got:\n%s", fragment, joined)
		}
	}
}

func TestMixedHealthSettingsForProtocol_FallbackOrder(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()

	config.HealthCheck = HealthCheckSettings{TotalTimeoutSeconds: 7, TLSHandshakeThresholdSeconds: 3}
	config.HealthCheckTwoStage.StageOne = HealthCheckSettings{TotalTimeoutSeconds: 4, TLSHandshakeThresholdSeconds: 2}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 8, TLSHandshakeThresholdSeconds: 4}
	config.HealthCheckProtocolOverrides = map[string]TwoStageHealthCheckSettings{
		"vmess": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 15, TLSHandshakeThresholdSeconds: 8},
		},
		"vless": {
			StageOne: HealthCheckSettings{},
			StageTwo: HealthCheckSettings{},
		},
	}

	settings, tier := mixedHealthSettingsForProtocolWithTier("vmess", 2)
	if tier != "protocol_override" || settings.TotalTimeoutSeconds != 15 {
		t.Fatalf("expected protocol override tier for vmess stage2, got tier=%s settings=%+v", tier, settings)
	}

	settings, tier = mixedHealthSettingsForProtocolWithTier("vless", 1)
	if tier != "two_stage_default" || settings.TotalTimeoutSeconds != 4 {
		t.Fatalf("expected two-stage default tier for empty override, got tier=%s settings=%+v", tier, settings)
	}

	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{}
	settings, tier = mixedHealthSettingsForProtocolWithTier("unknown", 2)
	if tier != "global_health_check" || settings.TotalTimeoutSeconds != 7 {
		t.Fatalf("expected global fallback tier, got tier=%s settings=%+v", tier, settings)
	}
}

func TestParseRegularProxyContentMixed_PreservesMainstreamPayloadWithExtraText(t *testing.T) {
	ssLine := "prefix ss://YWVzLTI1Ni1nY206cGFzczEyMw@1.2.3.4:8388/?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket#name suffix"
	ssrPayload := "example.com:8443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:cHdkMTIz/?remarks=bm9kZTE&obfsparam=b2Jmcw"
	ssrLine := "说明 " + "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(ssrPayload)) + " extra-text"
	trojanLine := "tag trojan://secret@8.8.8.8:443?sni=cdn.example.com trailing"

	proxies, format := parseRegularProxyContentMixed(strings.Join([]string{
		"# comment",
		ssLine,
		ssrLine,
		trojanLine,
	}, "\n"))

	if format != "plain" {
		t.Fatalf("expected plain format, got %s", format)
	}

	expectedSSR := "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(ssrPayload))
	expected := []string{
		"ss://YWVzLTI1Ni1nY206cGFzczEyMw@1.2.3.4:8388?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket#name",
		expectedSSR,
		"trojan://secret@8.8.8.8:443?sni=cdn.example.com",
	}
	for _, want := range expected {
		if !slices.Contains(proxies, want) {
			t.Fatalf("expected proxy %q in parsed result: %v", want, proxies)
		}
	}
}

func TestParseSpecialProxyURLMixed_MainstreamMalformedSkipsFallback(t *testing.T) {
	ssrPayload := "example.com:9443:auth_chain_a:aes-128-cfb:plain:cGFzczEyMw/?remarks=dGVzdA"
	validSSR := "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(ssrPayload))

	content := strings.Join([]string{
		"noise " + validSSR + " trailing",
		"broken ssr://invalid$$ 9.9.9.9:9999",
		"broken ss://invalid 6.6.6.6:6666",
		"broken trojan:// 7.7.7.7:7777",
		"fallback https://5.5.5.5:443",
	}, "\n")

	proxies := parseSpecialProxyURLMixed(content)

	if !slices.Contains(proxies, validSSR) {
		t.Fatalf("expected valid SSR payload to be preserved, got: %v", proxies)
	}
	if !slices.Contains(proxies, "https://5.5.5.5:443") {
		t.Fatalf("expected https fallback entry, got: %v", proxies)
	}
	for _, forbidden := range []string{"socks5://9.9.9.9:9999", "socks5://6.6.6.6:6666", "socks5://7.7.7.7:7777"} {
		if slices.Contains(proxies, forbidden) {
			t.Fatalf("unexpected degraded fallback %s in %v", forbidden, proxies)
		}
	}
}

type adapterDialRecorder struct {
	mu      sync.Mutex
	entries []string
}

func (r *adapterDialRecorder) add(v string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, v)
}

func (r *adapterDialRecorder) hasPrefix(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.entries {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

type mockMainstreamAdapter struct {
	targetAddr string
	recorder   *adapterDialRecorder
}

func (a *mockMainstreamAdapter) DialContext(ctx context.Context, proxyScheme, proxyEntry, proxyAddr, network, addr string) (net.Conn, error) {
	if a.recorder != nil {
		a.recorder.add(proxyScheme + "|" + proxyEntry + "|" + proxyAddr + "|" + addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, a.targetAddr)
}

func TestMainstreamHealthChecks_UseAdapterDialBranchForSSSSRAndTrojan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	oldFactory := mainstreamAdapterFactory
	oldURL := mixedHealthCheckURL
	oldConfig := config
	defer func() {
		mainstreamAdapterFactory = oldFactory
		mixedHealthCheckURL = oldURL
		config = oldConfig
	}()

	targetAddr := strings.TrimPrefix(srv.URL, "http://")
	recorder := &adapterDialRecorder{}
	mainstreamAdapterFactory = func() mainstreamDialAdapter {
		return &mockMainstreamAdapter{targetAddr: targetAddr, recorder: recorder}
	}
	mixedHealthCheckURL = srv.URL
	config.Detector.Core = "mihomo"

	entries := []string{
		"ss://YWVzLTI1Ni1nY206cGFzczEyMw@1.2.3.4:8388?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket",
		"ssr://ZXhhbXBsZS5jb206ODQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmNIZGtNVEl6Lz9vYmZzcGFyYW09YjJKbWN3JnByb3RvcGFyYW09Y0hKdmRHOQ",
		"trojan://secret@8.8.8.8:443?sni=cdn.example.com&alpn=h2%2Ch3&allowInsecure=1&type=ws&path=%2Ftr",
	}

	for _, entry := range entries {
		stage1 := checkMainstreamProxyHealthStage1(entry, HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2})
		if !stage1.Healthy {
			t.Fatalf("stage1 should use adapter dial branch for %s, got %+v", entry, stage1)
		}
		stage2 := checkMainstreamProxyHealthStage2(entry, false, HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2})
		if !stage2.Status.Healthy {
			t.Fatalf("stage2 should use adapter dial branch for %s, got %+v", entry, stage2.Status)
		}
	}

	for _, prefix := range []string{"ss|", "ssr|", "trojan|"} {
		if !recorder.hasPrefix(prefix) {
			t.Fatalf("expected adapter recorder to include %s calls, got %+v", prefix, recorder.entries)
		}
	}
}

func TestParseKernelNodeConfig_MapsSSSSRAndTrojanFields(t *testing.T) {
	ssNode, err := parseKernelNodeConfig("ss", "ss://YWVzLTI1Ni1nY206cGFzczEyMw@1.2.3.4:8388?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket", "1.2.3.4:8388")
	if err != nil {
		t.Fatalf("parse ss kernel node failed: %v", err)
	}
	if ssNode.SS.Cipher != "aes-256-gcm" || ssNode.SS.Password != "pass123" || ssNode.SS.Plugin != "v2ray-plugin" || ssNode.SS.PluginOpts != "mode=websocket" {
		t.Fatalf("unexpected ss node mapping: %+v", ssNode.SS)
	}

	ssrNode, err := parseKernelNodeConfig("ssr", "ssr://ZXhhbXBsZS5jb206ODQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmNIZGtNVEl6Lz9vYmZzcGFyYW09YjJKbWN3JnByb3RvcGFyYW09Y0hKdmRHOQ", "example.com:8443")
	if err != nil {
		t.Fatalf("parse ssr kernel node failed: %v", err)
	}
	if ssrNode.SSR.Protocol != "auth_sha1_v4" || ssrNode.SSR.Obfs != "tls1.2_ticket_auth" || ssrNode.SSR.ProtocolParam != "proto" || ssrNode.SSR.ObfsParam != "obfs" {
		t.Fatalf("unexpected ssr node mapping: %+v", ssrNode.SSR)
	}

	trojanNode, err := parseKernelNodeConfig("trojan", "trojan://secret@8.8.8.8:443?sni=cdn.example.com&alpn=h2%2Ch3&allowInsecure=1&type=ws&path=%2Ftr&host=ws.example.com", "8.8.8.8:443")
	if err != nil {
		t.Fatalf("parse trojan kernel node failed: %v", err)
	}
	if trojanNode.Trojan.SNI != "cdn.example.com" || len(trojanNode.Trojan.ALPN) != 2 || !trojanNode.Trojan.AllowInsecure || trojanNode.Trojan.Network != "ws" || trojanNode.Trojan.Path != "/tr" || trojanNode.Trojan.Host != "ws.example.com" {
		t.Fatalf("unexpected trojan node mapping: %+v", trojanNode.Trojan)
	}
}

type fixedTargetDialer struct {
	targetAddr string
}

func (d fixedTargetDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.targetAddr)
}

func startSleepTLSLikeServer(t *testing.T, sleep time.Duration, closeImmediately bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				if closeImmediately {
					return
				}
				time.Sleep(sleep)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
	}
}

func TestMainstreamStage2_TLSFailureCategoriesWithMockServers(t *testing.T) {
	oldBuilder := upstreamDialerBuilder
	oldURL := mixedHealthCheckURL
	defer func() {
		upstreamDialerBuilder = oldBuilder
		mixedHealthCheckURL = oldURL
	}()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer tlsSrv.Close()
	tlsAddr := strings.TrimPrefix(tlsSrv.URL, "https://")

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()
	httpAddr := strings.TrimPrefix(httpSrv.URL, "http://")

	timeoutAddr, stopTimeout := startSleepTLSLikeServer(t, 2*time.Second, false)
	defer stopTimeout()
	eofAddr, stopEOF := startSleepTLSLikeServer(t, 0, true)
	defer stopEOF()

	upstreamDialerBuilder = func(entry string) (UpstreamDialer, string, error) {
		switch entry {
		case "timeout":
			return fixedTargetDialer{targetAddr: timeoutAddr}, "trojan", nil
		case "eof":
			return fixedTargetDialer{targetAddr: eofAddr}, "trojan", nil
		case "cert":
			return fixedTargetDialer{targetAddr: tlsAddr}, "trojan", nil
		case "protocol":
			return fixedTargetDialer{targetAddr: httpAddr}, "trojan", nil
		default:
			return nil, "", fmt.Errorf("unknown entry")
		}
	}

	mixedHealthCheckURL = "https://127.0.0.1/"
	settings := HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 1}

	timeoutResult := checkMainstreamProxyHealthStage2("timeout", false, settings).Status
	if timeoutResult.Category != healthFailureTimeout || timeoutResult.ErrorCode != "DP-TRJ-206" || !strings.Contains(timeoutResult.Reason, "error_code=DP-TRJ-206") {
		t.Fatalf("unexpected timeout classification: %+v", timeoutResult)
	}

	eofResult := checkMainstreamProxyHealthStage2("eof", false, settings).Status
	if eofResult.Category != healthFailureEOF || eofResult.ErrorCode != "DP-TRJ-204" || !strings.Contains(eofResult.Reason, "error_code=DP-TRJ-204") {
		t.Fatalf("unexpected eof classification: %+v", eofResult)
	}

	certResult := checkMainstreamProxyHealthStage2("cert", true, settings).Status
	if certResult.Category != healthFailureCertVerify || certResult.ErrorCode != "DP-TRJ-202" || !strings.Contains(certResult.Reason, "error_code=DP-TRJ-202") {
		t.Fatalf("unexpected cert classification: %+v", certResult)
	}

	protocolResult := checkMainstreamProxyHealthStage2("protocol", false, settings).Status
	if protocolResult.Category != healthFailureProtocolError || protocolResult.ErrorCode != "DP-TRJ-205" || !strings.Contains(protocolResult.Reason, "error_code=DP-TRJ-205") {
		t.Fatalf("unexpected protocol classification: %+v", protocolResult)
	}
}

func TestClassifyHealthFailure_SNIMismatchCode(t *testing.T) {
	category, code := classifyHealthFailure(x509.HostnameError{})
	if category != healthFailureSNIMismatch || code != "sni_mismatch" {
		t.Fatalf("expected sni mismatch classification, got category=%s code=%s", category, code)
	}
}

func TestParseKernelNodeConfig_TrojanInsecureCompatibility(t *testing.T) {
	node, err := parseKernelNodeConfig("trojan", "trojan://secret@8.8.8.8:443?sni=cdn.example.com&insecure=1", "8.8.8.8:443")
	if err != nil {
		t.Fatalf("parse trojan node failed: %v", err)
	}
	if !node.Trojan.AllowInsecure {
		t.Fatalf("expected insecure compatibility to map to allowInsecure")
	}
}

func TestResolveMainstreamCoreBackend_UsesExternalKernelBackendForKnownCores(t *testing.T) {
	t.Setenv("DP_MIHOMO_SIDECAR_ADDR", "127.0.0.1:18080")
	t.Setenv("DP_META_SIDECAR_ADDR", "127.0.0.1:28080")
	t.Setenv("DP_SINGBOX_SIDECAR_ADDR", "127.0.0.1:38080")

	for _, core := range []string{"mihomo", "meta", "singbox"} {
		backend, ok := resolveMainstreamCoreBackend(core)
		if !ok {
			t.Fatalf("expected backend for core %s", core)
		}
		if _, ok := backend.(*externalKernelBackend); !ok {
			t.Fatalf("expected externalKernelBackend for core %s, got %T", core, backend)
		}
	}
}

func TestMainstreamUpstreamDialer_ExternalKernelUnavailableReturnsCoreError(t *testing.T) {
	oldFactory := mainstreamAdapterFactory
	oldConfig := config
	defer func() {
		mainstreamAdapterFactory = oldFactory
		config = oldConfig
	}()

	_ = os.Unsetenv("DP_MIHOMO_SIDECAR_ADDR")
	config.Detector.Core = "mihomo"
	mainstreamAdapterFactory = func() mainstreamDialAdapter { return &mainstreamTCPConnectAdapter{} }

	d := newMainstreamUpstreamDialer("trojan", "trojan://secret@1.1.1.1:443?sni=example.com", "1.1.1.1:443")
	_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatalf("expected unavailable core error")
	}
	if !errors.Is(err, errMainstreamCoreUnavailable) {
		t.Fatalf("expected errMainstreamCoreUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "code=core_unavailable") {
		t.Fatalf("expected standard core error code, got %v", err)
	}
}

func TestExternalKernelBackend_ProtocolSpecificHealthCheckCommands(t *testing.T) {
	backend := &externalKernelBackend{
		sidecarAddr: "127.0.0.1:9",
		protocolHealthChecks: map[string]string{
			"ss":     "exit 0",
			"ssr":    "exit 0",
			"trojan": "exit 0",
		},
	}

	nodes := []kernelNodeConfig{
		{Protocol: "ss", SS: struct {
			Cipher     string
			Password   string
			Plugin     string
			PluginOpts string
		}{Cipher: "aes-256-gcm", Password: "pass"}},
		{Protocol: "ssr"},
		{Protocol: "trojan"},
	}
	for _, node := range nodes {
		if err := backend.HealthCheck(context.Background(), node); err != nil {
			t.Fatalf("expected protocol health check to pass for %s: %v", node.Protocol, err)
		}
	}
}
