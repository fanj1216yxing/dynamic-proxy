package main

import (
	"fmt"
	"net"
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
