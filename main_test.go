package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetRuntimeHealthForTest() {
	runtimeHealth = newRuntimeHealthState()
}

func resetMixedStageMetricsForTest(t *testing.T) {
	t.Helper()
	original := mixedStageMetrics
	mixedStageMetrics = newStagePromMetrics()
	t.Cleanup(func() {
		mixedStageMetrics = original
	})
}

func boolPtr(v bool) *bool {
	return &v
}

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

func TestParserRegressionClashDropsVLESSIPWithoutDomainSNI(t *testing.T) {
	content := `proxies:
  - {name: bad-vless, type: vless, server: 1.2.3.4, port: 443, uuid: 11111111-1111-1111-1111-111111111111, network: ws, tls: true}
  - {name: good-vless, type: vless, server: 2.3.4.5, port: 443, uuid: 22222222-2222-2222-2222-222222222222, network: ws, tls: true, sni: example.com}
`
	entries, format := parseRegularProxyContentMixed(content)
	if format != "clash" {
		t.Fatalf("expected clash format, got %s", format)
	}
	for _, entry := range entries {
		if strings.Contains(entry, "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443") {
			t.Fatalf("unexpected ip-only-sni vless entry accepted: %s", entry)
		}
	}
	foundGood := false
	for _, entry := range entries {
		if strings.Contains(entry, "vless://22222222-2222-2222-2222-222222222222@2.3.4.5:443") {
			foundGood = true
			break
		}
	}
	if !foundGood {
		t.Fatalf("expected vless entry with domain sni to be retained, entries=%v", entries)
	}
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

func TestParseRegularProxyContentMixedExpandsPlainEndpointsByProtocol(t *testing.T) {
	content := strings.Join([]string{
		"103.210.22.17:3128",
		"38.3.162.129:999",
		"210.61.216.63:60808",
		"154.64.211.145:999",
		"139.59.1.14:80",
		"103.191.165.146:8090",
	}, "\n")

	entries, format := parseRegularProxyContentMixed(content)
	if format != "plain" {
		t.Fatalf("expected plain format, got %s", format)
	}
	if len(entries) != 24 {
		t.Fatalf("expected 24 expanded entries, got %d", len(entries))
	}

	counts := protocolHealthyCounts(entries)
	if counts["http"] != 6 || counts["https"] != 6 || counts["socks4"] != 6 || counts["socks5"] != 6 {
		t.Fatalf("unexpected expanded protocol counts: %#v", counts)
	}
}

func TestParseSpecialProxyURLMixedExpandsPlainEndpointAndKeepsExplicitScheme(t *testing.T) {
	content := strings.Join([]string{
		"103.210.22.17:3128",
		"socks4://38.3.162.129:999",
		"proxy 210.61.216.63:60808 note",
	}, "\n")

	entries := parseSpecialProxyURLMixed(content)
	counts := protocolHealthyCounts(entries)
	if counts["http"] != 2 || counts["https"] != 2 || counts["socks5"] != 2 || counts["socks4"] != 3 {
		t.Fatalf("unexpected special parser protocol counts: %#v", counts)
	}
}

func TestParseMixedProxySupportsSocks4(t *testing.T) {
	scheme, addr, auth, _, err := parseMixedProxy("socks4://user@103.210.22.17:3128")
	if err != nil {
		t.Fatalf("expected socks4 parse success, got err=%v", err)
	}
	if scheme != "socks4" || addr != "103.210.22.17:3128" {
		t.Fatalf("unexpected socks4 parse output scheme=%s addr=%s", scheme, addr)
	}
	if auth == nil || auth.User != "user" {
		t.Fatalf("expected socks4 user auth to be preserved, got %#v", auth)
	}
}

func TestBuildUpstreamDialerSupportsSocks4(t *testing.T) {
	dialer, scheme, err := buildUpstreamDialer("socks4://103.210.22.17:3128")
	if err != nil {
		t.Fatalf("expected buildUpstreamDialer success, got %v", err)
	}
	if scheme != "socks4" {
		t.Fatalf("expected scheme socks4, got %s", scheme)
	}
	if _, ok := dialer.(*socks4UpstreamDialer); !ok {
		t.Fatalf("expected socks4 upstream dialer, got %T", dialer)
	}
}

func TestParseVLESSNodeRejectsInvalidUUID(t *testing.T) {
	_, ok := parseVLESSNode("vless://not-a-uuid@103.210.22.17:443?encryption=none&security=tls&sni=example.com")
	if ok {
		t.Fatalf("expected vless parse failure for invalid uuid")
	}
}

func TestParseVMESSNodeRejectsInvalidUUID(t *testing.T) {
	_, ok := parseVMESSNode("vmess://vm.example.com:443?id=not-a-uuid&net=ws&tls=tls")
	if ok {
		t.Fatalf("expected vmess parse failure for invalid uuid")
	}
}

func TestNormalizeMixedProxyEntryRejectsVLESSIPWithoutDomainSNI(t *testing.T) {
	entry, ok := normalizeMixedProxyEntry("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none")
	if ok {
		t.Fatalf("expected ip-only-sni vless to be rejected, got %s", entry)
	}
}

func TestNormalizeMixedProxyEntryAcceptsVLESSIPWithDomainSNI(t *testing.T) {
	entry, ok := normalizeMixedProxyEntry("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&sni=example.com")
	if !ok {
		t.Fatalf("expected vless with domain sni to normalize")
	}
	if !strings.Contains(entry, "sni=example.com") {
		t.Fatalf("expected normalized entry to preserve domain sni, got %s", entry)
	}
}

func TestNormalizeMixedProxyEntryFillsVLESSEncryptionNone(t *testing.T) {
	config = Config{}
	config.TLSParamPolicy.DefaultALPN = []string{"h2", "http/1.1"}
	entry, ok := normalizeMixedProxyEntry("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com")
	if !ok {
		t.Fatalf("expected vless entry to normalize")
	}
	if !strings.Contains(entry, "encryption=none") {
		t.Fatalf("expected normalized vless entry to include encryption=none, got %s", entry)
	}
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

func TestNormalizeMixedProxyEntryPreservesAllowInsecureAlias(t *testing.T) {
	config = Config{}
	config.TLSParamPolicy.DefaultALPN = []string{"h2", "http/1.1"}
	entry, ok := normalizeMixedProxyEntry("trojan://pass@example.com:443?allow_insecure=true")
	if !ok {
		t.Fatalf("expected trojan entry to normalize")
	}
	if !strings.Contains(entry, "insecure=true") {
		t.Fatalf("expected insecure=true to be preserved, got %s", entry)
	}
	if !strings.Contains(entry, "allow_insecure=true") {
		t.Fatalf("expected allow_insecure=true to be preserved, got %s", entry)
	}
}

func TestParseTrojanNodeForKernelAcceptsAllowInsecureUnderscore(t *testing.T) {
	node, ok := parseTrojanNodeForKernel("trojan://pass@example.com:443?sni=example.com&allow_insecure=true")
	if !ok {
		t.Fatalf("expected trojan node parse success")
	}
	if !node.Insecure {
		t.Fatalf("expected allow_insecure=true to set Insecure=true")
	}
}

func TestParseTrojanNodeForKernelParsesFingerprint(t *testing.T) {
	node, ok := parseTrojanNodeForKernel("trojan://pass@example.com:443?sni=example.com&fp=chrome")
	if !ok {
		t.Fatalf("expected trojan node parse success")
	}
	if node.Fingerprint != "chrome" {
		t.Fatalf("expected fp=chrome to be preserved, got %q", node.Fingerprint)
	}
}

func TestBuildRuntimeSingboxOutboundTrojanAddsUTLS(t *testing.T) {
	config = Config{}
	config.TLSParamPolicy.DefaultALPN = []string{"h2", "http/1.1"}
	node := kernelNodeConfig{Protocol: "trojan", Address: "example.com", Port: "443"}
	node.Trojan.Password = "pass"
	node.Trojan.SNI = "example.com"
	node.Trojan.Fingerprint = "random"

	out, err := buildRuntimeSingboxOutbound(node)
	if err != nil {
		t.Fatalf("expected build success: %v", err)
	}
	tlsRaw, ok := out["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected tls map")
	}
	utlsRaw, ok := tlsRaw["utls"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected utls map")
	}
	if utlsRaw["fingerprint"] != "randomized" {
		t.Fatalf("expected random fp normalized to randomized, got %v", utlsRaw["fingerprint"])
	}
}

func TestBuildRuntimeSingboxOutboundVLESSRealityIncludesRealityConfig(t *testing.T) {
	config = Config{}
	config.TLSParamPolicy.DefaultALPN = []string{"h2", "http/1.1"}
	node := kernelNodeConfig{Protocol: "vless", Address: "example.com", Port: "443"}
	node.VLESS.UUID = "11111111-1111-1111-1111-111111111111"
	node.VLESS.Security = "reality"
	node.VLESS.ServerName = "example.com"
	node.VLESS.RealityPublicKey = "reality-public-key"
	node.VLESS.RealityShortID = "abcd"
	node.VLESS.Fingerprint = "chrome"

	out, err := buildRuntimeSingboxOutbound(node)
	if err != nil {
		t.Fatalf("expected build success: %v", err)
	}
	tlsRaw, ok := out["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected tls map")
	}
	realityRaw, ok := tlsRaw["reality"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected reality map")
	}
	if realityRaw["public_key"] != "reality-public-key" {
		t.Fatalf("expected reality public key, got %v", realityRaw["public_key"])
	}
	if realityRaw["short_id"] != "abcd" {
		t.Fatalf("expected reality short id, got %v", realityRaw["short_id"])
	}
}

func TestParseKernelNodeConfigInsecureAliases(t *testing.T) {
	vlessEntry := "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=tls&sni=example.com&allow_insecure=true"
	vlessNode, err := parseKernelNodeConfig("vless", vlessEntry, "example.com:443")
	if err != nil {
		t.Fatalf("expected vless parse success: %v", err)
	}
	if !vlessNode.VLESS.AllowInsecure {
		t.Fatalf("expected vless allow_insecure=true to set AllowInsecure=true")
	}

	hy2Entry := "hy2://pass@example.com:443?sni=example.com&allow_insecure=true"
	hy2Node, err := parseKernelNodeConfig("hy2", hy2Entry, "example.com:443")
	if err != nil {
		t.Fatalf("expected hy2 parse success: %v", err)
	}
	if !hy2Node.HY2.AllowInsecure {
		t.Fatalf("expected hy2 allow_insecure=true to set AllowInsecure=true")
	}
}

func TestParseKernelNodeConfigRejectsVLESSRealityWithoutPBK(t *testing.T) {
	_, err := parseKernelNodeConfig("vless", "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&sni=example.com", "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "missing public key") {
		t.Fatalf("expected reality missing public key error, got: %v", err)
	}
}

func TestParseKernelNodeConfigRejectsVLESSVisionWithNonTCP(t *testing.T) {
	_, err := parseKernelNodeConfig("vless", "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&sni=example.com&flow=xtls-rprx-vision&type=ws&pbk=test", "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "vision flow network") {
		t.Fatalf("expected vision network validation error, got: %v", err)
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

func TestProtocolHealthyCounts(t *testing.T) {
	counts := protocolHealthyCounts([]string{
		"http://1.1.1.1:80",
		"socks5://2.2.2.2:1080",
		"vless://11111111-1111-1111-1111-111111111111@vl.example.com:443?encryption=none",
		"vless://22222222-2222-2222-2222-222222222222@vl2.example.com:443?encryption=none",
		"trojan://pass@tr.example.com:443",
	})

	if counts["http"] != 1 || counts["socks5"] != 1 || counts["vless"] != 2 || counts["trojan"] != 1 {
		t.Fatalf("unexpected protocol counts: %#v", counts)
	}
}

func TestEvaluateMainstreamHealthAlertAndSLO(t *testing.T) {
	config = Config{}
	config.Alerting.ZeroMainstreamToleranceCycles = 1
	config.ProtocolSLO.Enabled = true
	config.ProtocolSLO.MinHealthy = map[string]int{"vless": 1, "hy2": 1, "trojan": 1}
	resetRuntimeHealthForTest()

	status1, reasons1 := evaluateMainstreamHealth(nil)
	if status1 != "degraded" {
		t.Fatalf("expected degraded on first empty cycle, got %s (%v)", status1, reasons1)
	}

	status2, reasons2 := evaluateMainstreamHealth(nil)
	if status2 != "alert" {
		t.Fatalf("expected alert on second empty cycle, got %s (%v)", status2, reasons2)
	}

	status3, reasons3 := evaluateMainstreamHealth([]string{
		"vless://33333333-3333-3333-3333-333333333333@vl.example.com:443?encryption=none",
		"hy2://pass@hy.example.com:443?sni=hy.example.com",
		"trojan://pass@tr.example.com:443?sni=tr.example.com",
	})
	if status3 != "ok" || len(reasons3) != 0 {
		t.Fatalf("expected ok with no reasons, got %s (%v)", status3, reasons3)
	}
}

func TestBuildStageFunnelByProtocolIncludesCheckedAndPass(t *testing.T) {
	resetMixedStageMetricsForTest(t)

	mixedStageMetrics.AddInput("vless")
	mixedStageMetrics.AddInput("vless")
	mixedStageMetrics.AddInput("trojan")
	mixedStageMetrics.AddStageResult("vless", "stage1", true, "", 20*time.Millisecond)
	mixedStageMetrics.AddStageResult("vless", "stage1", false, "DP-GEN-201", 0)
	mixedStageMetrics.AddStageResult("vless", "stage2", false, "DP-GEN-201", 0)
	mixedStageMetrics.AddStageResult("trojan", "stage1", false, "DP-TRJ-101", 0)

	funnel := buildStageFunnelByProtocol()
	vless := funnel["vless"]
	if vless["input"] != 2 || vless["stage1"] != 2 || vless["stage2"] != 1 || vless["stage1_pass"] != 1 || vless["stage2_pass"] != 0 {
		t.Fatalf("unexpected vless funnel: %#v", vless)
	}
	trojan := funnel["trojan"]
	if trojan["input"] != 1 || trojan["stage1"] != 1 || trojan["stage2"] != 0 || trojan["stage1_pass"] != 0 || trojan["stage2_pass"] != 0 {
		t.Fatalf("unexpected trojan funnel: %#v", trojan)
	}
}

func TestStagePromMetricsConcurrentWriteConsistency(t *testing.T) {
	m := newStagePromMetrics()
	const workers = 8
	const loops = 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < loops; i++ {
				m.AddInput("ss")
				healthy := (workerID+i)%2 == 0
				m.AddStageResult("ss", "stage1", healthy, "DP-SS-201", time.Millisecond)
			}
		}(w)
	}
	wg.Wait()

	snapshot := m.Snapshot()
	inputRaw, _ := snapshot["input"].(map[string]int64)
	checkedRaw, _ := snapshot["checked"].(map[string]map[string]int64)
	passRaw, _ := snapshot["pass"].(map[string]map[string]int64)

	expectedTotal := int64(workers * loops)
	if inputRaw["ss"] != expectedTotal {
		t.Fatalf("unexpected input total: got=%d want=%d", inputRaw["ss"], expectedTotal)
	}
	if checkedRaw["ss"]["stage1"] != expectedTotal {
		t.Fatalf("unexpected checked total: got=%d want=%d", checkedRaw["ss"]["stage1"], expectedTotal)
	}
	if passRaw["ss"]["stage1"] <= 0 || passRaw["ss"]["stage1"] >= expectedTotal {
		t.Fatalf("unexpected pass total: got=%d expected between 1 and %d", passRaw["ss"]["stage1"], expectedTotal-1)
	}
}

func TestClassifyHealthFailureCoreUnavailable(t *testing.T) {
	err := fmt.Errorf("%w: code=core_unavailable sidecar_addr_missing core=singbox", errMainstreamCoreUnavailable)
	category, reason := classifyHealthFailure(err)
	if category != healthFailureCoreUnavailable || reason != "core_unconfigured" {
		t.Fatalf("unexpected classification: category=%s reason=%s", category, reason)
	}
}

func TestSupportsCoreUnavailableNativeFallbackExcludesMainstreamTCPProtocols(t *testing.T) {
	for _, scheme := range []string{"vless", "vmess", "trojan"} {
		if supportsCoreUnavailableNativeFallback(scheme) {
			t.Fatalf("expected scheme %s to be excluded from core-unavailable native fallback", scheme)
		}
	}
	if !supportsCoreUnavailableNativeFallback("hy2") {
		t.Fatalf("expected hy2 to keep core-unavailable native fallback")
	}
}

func TestExternalKernelHealthCheckAutoStartSidecarRetriesProbe(t *testing.T) {
	originalProbe := sidecarProbeFunc
	originalAutostart := sidecarAutoStartFunc
	resetSidecarProbeCacheForTest()
	t.Cleanup(func() {
		sidecarProbeFunc = originalProbe
		sidecarAutoStartFunc = originalAutostart
		resetSidecarProbeCacheForTest()
	})

	autostartCalls := 0
	probeCalls := 0
	sidecarProbeFunc = func(ctx context.Context, addr string) error {
		probeCalls++
		if autostartCalls == 0 {
			return errors.New("connection refused")
		}
		return nil
	}

	sidecarAutoStartFunc = func(ctx context.Context, coreName, sidecarAddr string) error {
		autostartCalls++
		if coreName != "singbox" {
			t.Fatalf("unexpected core name: %s", coreName)
		}
		if sidecarAddr != "127.0.0.1:19081" {
			t.Fatalf("unexpected sidecar addr: %s", sidecarAddr)
		}
		return nil
	}

	backend := &externalKernelBackend{
		info:        mainstreamCoreInfo{Name: "singbox"},
		sidecarAddr: "127.0.0.1:19081",
	}
	err := backend.HealthCheck(context.Background(), kernelNodeConfig{Protocol: "vless"})
	if err != nil {
		t.Fatalf("expected health check to succeed after autostart, got err=%v", err)
	}
	if autostartCalls != 1 {
		t.Fatalf("expected one autostart attempt, got=%d", autostartCalls)
	}
	if probeCalls < 4 {
		t.Fatalf("expected retries before autostart, got probeCalls=%d", probeCalls)
	}
}

func TestExternalKernelHealthCheckReturnsCoreUnavailableWhenAutostartFails(t *testing.T) {
	originalProbe := sidecarProbeFunc
	originalAutostart := sidecarAutoStartFunc
	resetSidecarProbeCacheForTest()
	t.Cleanup(func() {
		sidecarProbeFunc = originalProbe
		sidecarAutoStartFunc = originalAutostart
		resetSidecarProbeCacheForTest()
	})

	sidecarProbeFunc = func(ctx context.Context, addr string) error {
		return errors.New("connection refused")
	}
	sidecarAutoStartFunc = func(ctx context.Context, coreName, sidecarAddr string) error {
		return errors.New("start failed")
	}

	backend := &externalKernelBackend{
		info:        mainstreamCoreInfo{Name: "singbox"},
		sidecarAddr: "127.0.0.1:19081",
	}
	err := backend.HealthCheck(context.Background(), kernelNodeConfig{Protocol: "vless"})
	if err == nil {
		t.Fatalf("expected core_unavailable error when autostart fails")
	}
	if !strings.Contains(err.Error(), "core_unavailable") {
		t.Fatalf("expected core_unavailable marker, got err=%v", err)
	}
	if !strings.Contains(err.Error(), "sidecar_probe_failed") {
		t.Fatalf("expected sidecar probe failure marker, got err=%v", err)
	}
}

func TestProbeSidecarAddrWithPolicyCachesRecentSuccess(t *testing.T) {
	originalProbe := sidecarProbeFunc
	resetSidecarProbeCacheForTest()
	t.Cleanup(func() {
		sidecarProbeFunc = originalProbe
		resetSidecarProbeCacheForTest()
	})

	calls := 0
	sidecarProbeFunc = func(ctx context.Context, addr string) error {
		calls++
		return nil
	}

	if err := probeSidecarAddrWithPolicy(context.Background(), "127.0.0.1:19081"); err != nil {
		t.Fatalf("expected first probe success, got err=%v", err)
	}
	if err := probeSidecarAddrWithPolicy(context.Background(), "127.0.0.1:19081"); err != nil {
		t.Fatalf("expected cached probe success, got err=%v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one probe call with cache hit, got=%d", calls)
	}
}

func TestProbeSidecarAddrWithPolicyRetriesTransientFailure(t *testing.T) {
	originalProbe := sidecarProbeFunc
	resetSidecarProbeCacheForTest()
	t.Cleanup(func() {
		sidecarProbeFunc = originalProbe
		resetSidecarProbeCacheForTest()
	})

	calls := 0
	sidecarProbeFunc = func(ctx context.Context, addr string) error {
		calls++
		if calls < 3 {
			return errors.New("dial tcp 127.0.0.1:19081: connectex: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
		}
		return nil
	}

	if err := probeSidecarAddrWithPolicy(context.Background(), "127.0.0.1:19081"); err != nil {
		t.Fatalf("expected probe to recover after retries, got err=%v", err)
	}
	if calls != 3 {
		t.Fatalf("expected three attempts for transient failure, got=%d", calls)
	}
}

func TestBuildStageFunnelCoverageAllMainstreamProtocols(t *testing.T) {
	resetMixedStageMetricsForTest(t)
	protocols := []string{"hy2", "hysteria", "hysteria2", "ss", "ssr", "trojan", "tuic", "vless", "vmess"}
	for i, protocol := range protocols {
		mixedStageMetrics.AddInput(protocol)
		stage1Healthy := i%3 != 0
		mixedStageMetrics.AddStageResult(protocol, "stage1", stage1Healthy, "DP-GEN-201", 10*time.Millisecond)
		if stage1Healthy {
			mixedStageMetrics.AddStageResult(protocol, "stage2", i%2 == 0, "DP-GEN-201", 15*time.Millisecond)
		}
	}

	funnel := buildStageFunnelByProtocol()
	for _, protocol := range protocols {
		row, ok := funnel[protocol]
		if !ok {
			t.Fatalf("protocol %s missing in funnel", protocol)
		}
		if row["input"] != 1 {
			t.Fatalf("protocol %s input want=1 got=%d", protocol, row["input"])
		}
		if row["stage1"] != 1 {
			t.Fatalf("protocol %s stage1 checked want=1 got=%d", protocol, row["stage1"])
		}
		if row["stage1_pass"] < 0 || row["stage1_pass"] > 1 {
			t.Fatalf("protocol %s invalid stage1_pass=%d", protocol, row["stage1_pass"])
		}
		if row["stage2_pass"] < 0 || row["stage2_pass"] > row["stage2"] {
			t.Fatalf("protocol %s invalid stage2_pass=%d stage2=%d", protocol, row["stage2_pass"], row["stage2"])
		}
	}
}

type testDirectDialer struct {
	target string
}

func (d *testDirectDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

func TestHealthCheckMixedProxiesTwoStageBoundaryInputZero(t *testing.T) {
	resetMixedStageMetricsForTest(t)
	config = Config{}
	config.HealthCheckTwoStage.Enabled = true
	config.HealthCheckTwoStage.StageOne = HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 1}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 1}
	config.HealthCheckConcurrency = 1

	result := healthCheckMixedProxiesTwoStage(nil)
	if len(result.Healthy) != 0 || len(result.CFPass) != 0 {
		t.Fatalf("expected empty result for input=0, got %#v", result)
	}

	funnel := buildStageFunnelByProtocol()
	if len(funnel) != 0 {
		t.Fatalf("expected empty funnel for input=0, got %#v", funnel)
	}
}

func TestHealthCheckMixedProxiesTwoStageBoundaryInputOne(t *testing.T) {
	resetMixedStageMetricsForTest(t)
	config = Config{}
	config.HealthCheckTwoStage.Enabled = true
	config.HealthCheckTwoStage.StrictMode = boolPtr(false)
	config.HealthCheckTwoStage.StageOne = HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2}
	config.HealthCheckConcurrency = 1
	config.CFChallengeCheck.Enabled = false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	mixedHealthCheckURL = srv.URL
	t.Cleanup(func() {
		mixedHealthCheckURL = defaultMixedHealthCheckURL
	})

	origBuilder := upstreamDialerBuilder
	upstreamDialerBuilder = func(entry string) (UpstreamDialer, string, error) {
		if strings.TrimSpace(entry) == "" {
			return nil, "unknown", fmt.Errorf("empty proxy")
		}
		target := strings.TrimPrefix(srv.URL, "http://")
		return &testDirectDialer{target: target}, "vmess", nil
	}
	t.Cleanup(func() {
		upstreamDialerBuilder = origBuilder
	})

	result := healthCheckMixedProxiesTwoStage([]string{"vmess://stage2.example.com:443?id=44444444-4444-4444-4444-444444444444&net=ws&tls=tls"})
	if len(result.Healthy) != 1 {
		t.Fatalf("expected exactly one healthy proxy for input=1, got=%d", len(result.Healthy))
	}

	funnel := buildStageFunnelByProtocol()
	row, ok := funnel["vmess"]
	if !ok {
		t.Fatalf("expected vmess row in funnel, got %#v", funnel)
	}
	if row["input"] != 1 || row["stage1"] != 1 || row["stage1_pass"] != 1 || row["stage2"] != 1 || row["stage2_pass"] != 1 {
		t.Fatalf("unexpected vmess funnel row: %#v", row)
	}
}

func TestCheckMainstreamProxyHealthStage2RejectsEmptyResponseBody(t *testing.T) {
	config = Config{}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mixedHealthCheckURL = srv.URL
	t.Cleanup(func() {
		mixedHealthCheckURL = defaultMixedHealthCheckURL
	})

	origBuilder := upstreamDialerBuilder
	upstreamDialerBuilder = func(entry string) (UpstreamDialer, string, error) {
		target := strings.TrimPrefix(srv.URL, "http://")
		return &testDirectDialer{target: target}, "vless", nil
	}
	t.Cleanup(func() {
		upstreamDialerBuilder = origBuilder
	})

	result := checkMainstreamProxyHealthStage2("vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=tls&sni=example.com", false, HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2})
	if result.Status.Healthy {
		t.Fatalf("expected stage2 health check to reject empty response body")
	}
	if !strings.Contains(result.Status.ErrorCode, "103") {
		t.Fatalf("expected unreachable error code, got %s", result.Status.ErrorCode)
	}
}

func TestStageFunnelBoundaryLargeValues(t *testing.T) {
	resetMixedStageMetricsForTest(t)
	const total = 120000

	for i := 0; i < total; i++ {
		mixedStageMetrics.AddInput("vless")
		mixedStageMetrics.AddStageResult("vless", "stage1", true, "", time.Millisecond)
		if i%3 != 0 {
			mixedStageMetrics.AddStageResult("vless", "stage2", true, "", 2*time.Millisecond)
		}
	}

	funnel := buildStageFunnelByProtocol()
	row := funnel["vless"]
	if row["input"] != total {
		t.Fatalf("unexpected input total for large value: got=%d want=%d", row["input"], total)
	}
	if row["stage1"] != total || row["stage1_pass"] != total {
		t.Fatalf("unexpected stage1 totals for large value: %#v", row)
	}
	expectedStage2 := int64(total - total/3)
	if row["stage2"] != expectedStage2 || row["stage2_pass"] != expectedStage2 {
		t.Fatalf("unexpected stage2 totals for large value: got stage2=%d stage2_pass=%d want=%d", row["stage2"], row["stage2_pass"], expectedStage2)
	}
}

func TestHealthCheckMixedProxiesTwoStageBoundaryInvalidProtocolFormat(t *testing.T) {
	resetMixedStageMetricsForTest(t)
	config = Config{}
	config.HealthCheckTwoStage.Enabled = true
	config.HealthCheckTwoStage.StageOne = HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 1}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 1, TLSHandshakeThresholdSeconds: 1}
	config.HealthCheckConcurrency = 1

	origBuilder := upstreamDialerBuilder
	upstreamDialerBuilder = func(entry string) (UpstreamDialer, string, error) {
		return nil, "unknown", errors.New("invalid proxy entry")
	}
	t.Cleanup(func() {
		upstreamDialerBuilder = origBuilder
	})

	result := healthCheckMixedProxiesTwoStage([]string{"vmess://%%%invalid-format%%%"})
	if len(result.Healthy) != 0 {
		t.Fatalf("expected no healthy proxies for invalid format, got=%d", len(result.Healthy))
	}

	funnel := buildStageFunnelByProtocol()
	row, ok := funnel["unknown"]
	if !ok {
		t.Fatalf("expected unknown row in funnel for invalid input, got %#v", funnel)
	}
	if row["input"] != 1 || row["stage1"] != 1 || row["stage1_pass"] != 0 || row["stage2"] != 0 || row["stage2_pass"] != 0 {
		t.Fatalf("unexpected unknown funnel row for invalid input: %#v", row)
	}
}

func TestCheckMainstreamProxyHealthStage2NativeFallbackOnCoreUnavailable(t *testing.T) {
	config = Config{}
	config.Detector.Core = "singbox"

	oldSidecar, hadSidecar := os.LookupEnv("DP_SINGBOX_SIDECAR_ADDR")
	_ = os.Unsetenv("DP_SINGBOX_SIDECAR_ADDR")
	t.Cleanup(func() {
		if hadSidecar {
			_ = os.Setenv("DP_SINGBOX_SIDECAR_ADDR", oldSidecar)
		} else {
			_ = os.Unsetenv("DP_SINGBOX_SIDECAR_ADDR")
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			_ = conn.Close()
		}
	}()
	defer close(done)

	stageSettings := HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2}
	entry := fmt.Sprintf("ss://aes-256-gcm:ss-pass@%s", ln.Addr().String())
	result := checkMainstreamProxyHealthStage2(entry, false, stageSettings)
	if !result.Status.Healthy {
		t.Fatalf("expected stage2 fallback to pass, got status=%#v", result.Status)
	}
}

func TestHealthCheckMixedProxiesTwoStageAllDetectedProtocolsStage2NonZero(t *testing.T) {
	resetMixedStageMetricsForTest(t)
	config = Config{}
	config.HealthCheckTwoStage.Enabled = true
	config.HealthCheckTwoStage.StrictMode = boolPtr(false)
	config.HealthCheckTwoStage.StageOne = HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2}
	config.HealthCheckTwoStage.StageTwo = HealthCheckSettings{TotalTimeoutSeconds: 2, TLSHandshakeThresholdSeconds: 2}
	config.HealthCheckConcurrency = 4
	config.CFChallengeCheck.Enabled = false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	mixedHealthCheckURL = srv.URL
	t.Cleanup(func() {
		mixedHealthCheckURL = defaultMixedHealthCheckURL
	})

	origBuilder := upstreamDialerBuilder
	upstreamDialerBuilder = func(entry string) (UpstreamDialer, string, error) {
		target := strings.TrimPrefix(srv.URL, "http://")
		return &testDirectDialer{target: target}, detectProxyScheme(entry, "unknown"), nil
	}
	t.Cleanup(func() {
		upstreamDialerBuilder = origBuilder
	})

	proxies := []string{
		"hy2://pass@hy2.example.com:443?sni=hy2.example.com",
		"hysteria://auth@hy.example.com:443",
		"hysteria2://pass@hy22.example.com:443?sni=hy22.example.com",
		"ss://aes-256-gcm:ss-pass@ss.example.com:8388",
		"ssr://user:pass@ssr.example.com:443",
		"trojan://tr-pass@tr.example.com:443?sni=tr.example.com",
		"tuic://user:pass@tuic.example.com:443",
		"vless://22222222-2222-2222-2222-222222222222@vl.example.com:443?encryption=none&security=tls",
		"vmess://vm.example.com:443?id=11111111-1111-1111-1111-111111111111&net=ws&tls=tls",
	}

	result := healthCheckMixedProxiesTwoStage(proxies)
	if len(result.Healthy) != len(proxies) {
		t.Fatalf("expected all proxies healthy in deterministic test, got=%d want=%d", len(result.Healthy), len(proxies))
	}

	funnel := buildStageFunnelByProtocol()
	for _, protocol := range []string{"hy2", "hysteria", "hysteria2", "ss", "ssr", "trojan", "tuic", "vless", "vmess"} {
		row, ok := funnel[protocol]
		if !ok {
			t.Fatalf("protocol %s missing in funnel: %#v", protocol, funnel)
		}
		if row["stage2_pass"] <= 0 {
			t.Fatalf("protocol %s stage2_pass should be >0, got row=%#v", protocol, row)
		}
	}
}

func TestNormalizeSubscriptionProxyURLSupportsHostPort(t *testing.T) {
	normalized, err := normalizeSubscriptionProxyURL("127.0.0.1:2081")
	if err != nil {
		t.Fatalf("normalizeSubscriptionProxyURL returned error: %v", err)
	}
	if normalized != "http://127.0.0.1:2081" {
		t.Fatalf("unexpected normalized proxy url: %s", normalized)
	}
}

func TestLoadConfigRejectsEmptySubscriptionProxyWhenEnabledWithoutEnvFallback(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + string(os.PathSeparator) + "config.yaml"
	content := strings.Join([]string{
		"proxy_list_urls:",
		"  - \"https://example.com/list.txt\"",
		"subscription_use_env_proxy: false",
		"subscription_proxy:",
		"  enabled: true",
		"  url: \"\"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	_, err := loadConfig(configPath)
	if err == nil {
		t.Fatalf("expected loadConfig to fail for empty subscription_proxy.url when enabled")
	}
	if !strings.Contains(err.Error(), "subscription_proxy.enabled=true requires") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSubscriptionHTTPClientUsesConfiguredProxyURL(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + string(os.PathSeparator) + "config.yaml"
	content := strings.Join([]string{
		"proxy_list_urls:",
		"  - \"https://example.com/list.txt\"",
		"subscription_use_env_proxy: false",
		"subscription_proxy:",
		"  enabled: true",
		"  url: \"127.0.0.1:2081\"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	config = *cfg

	client := subscriptionHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", client.Transport)
	}
	if transport.Proxy == nil {
		t.Fatalf("expected proxy function to be configured")
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	proxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("transport.Proxy returned error: %v", err)
	}
	if proxyURL == nil {
		t.Fatalf("transport.Proxy returned nil proxy url")
	}
	if proxyURL.Scheme != "http" || proxyURL.Host != "127.0.0.1:2081" {
		t.Fatalf("unexpected proxy url: %s", proxyURL.String())
	}
}
