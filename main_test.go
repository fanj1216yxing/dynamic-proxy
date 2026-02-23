package main

import (
	"fmt"
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

func TestProtocolHealthyCounts(t *testing.T) {
	counts := protocolHealthyCounts([]string{
		"http://1.1.1.1:80",
		"socks5://2.2.2.2:1080",
		"vless://uuid@vl.example.com:443?encryption=none",
		"vless://uuid@vl2.example.com:443?encryption=none",
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
		"vless://uuid@vl.example.com:443?encryption=none",
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

func TestBuildStageFunnelCoverageAllMainstreamProtocols(t *testing.T) {
	resetMixedStageMetricsForTest(t)
	protocols := []string{"hy2", "hysteria", "hysteria2", "ss", "ssr", "trojan", "tuic", "vless"}
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
