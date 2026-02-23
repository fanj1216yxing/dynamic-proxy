package main

import (
	"fmt"
	"net"
	"slices"
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
