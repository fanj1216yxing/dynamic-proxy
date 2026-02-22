package main

import (
	"fmt"
	"net"
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
