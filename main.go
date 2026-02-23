package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/armon/go-socks5"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	ProxyListURLs          []string            `yaml:"proxy_list_urls"`
	SpecialProxyListUrls   []string            `yaml:"special_proxy_list_urls"` // 支持复杂格式的代理URL列表
	HealthCheckConcurrency int                 `yaml:"health_check_concurrency"`
	UpdateIntervalMinutes  int                 `yaml:"update_interval_minutes"`
	ProxySwitchIntervalMin string              `yaml:"proxy_switch_interval_min"`
	HealthCheck            HealthCheckSettings `yaml:"health_check"`
	HealthCheckTwoStage    struct {
		Enabled    bool                `yaml:"enabled"`
		StrictMode *bool               `yaml:"strict_mode"`
		StageOne   HealthCheckSettings `yaml:"stage_one"`
		StageTwo   HealthCheckSettings `yaml:"stage_two"`
	} `yaml:"health_check_two_stage"`
	HealthCheckProtocolOverrides map[string]TwoStageHealthCheckSettings `yaml:"health_check_protocol_overrides"`
	TLSParamPolicy               struct {
		DefaultAllowInsecure bool     `yaml:"default_allow_insecure"`
		DefaultALPN          []string `yaml:"default_alpn"`
	} `yaml:"tls_param_policy"`
	CertVerifyWhitelist struct {
		Enabled            bool     `yaml:"enabled"`
		AllowedHosts       []string `yaml:"allowed_hosts"`
		RequireInsecure    bool     `yaml:"require_insecure"`
		EnforceStrictAudit bool     `yaml:"enforce_strict_audit"`
	} `yaml:"cert_verify_whitelist"`
	Ports struct {
		SOCKS5Strict      string `yaml:"socks5_strict"`
		SOCKS5Relaxed     string `yaml:"socks5_relaxed"`
		HTTPStrict        string `yaml:"http_strict"`
		HTTPRelaxed       string `yaml:"http_relaxed"`
		HTTPMixed         string `yaml:"http_mixed"`
		HTTPMainstreamMix string `yaml:"http_mainstream_mixed"`
		HTTPCFMixed       string `yaml:"http_cf_mixed"`
		RotateControl     string `yaml:"rotate_control"`
	} `yaml:"ports"`
	Auth struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"auth"`
	CFChallengeCheck struct {
		Enabled          bool     `yaml:"enabled"`
		URL              string   `yaml:"url"`
		ExpectedStatuses []int    `yaml:"expected_statuses"`
		BlockIndicators  []string `yaml:"block_indicators"`
		TimeoutSeconds   int      `yaml:"timeout_seconds"`
	} `yaml:"cf_challenge_check"`
	Detector struct {
		Core string `yaml:"core"`
	} `yaml:"detector"`
	DifferentialProbe struct {
		Enabled            bool   `yaml:"enabled"`
		TargetURL          string `yaml:"target_url"`
		GoldenSampleFile   string `yaml:"golden_sample_file"`
		SamplesPerProtocol int    `yaml:"samples_per_protocol"`
		CompareTLSPolicy   string `yaml:"compare_tls_policy"`
		ReportOutputFile   string `yaml:"report_output_file"`
		DNS                struct {
			Mode        string `yaml:"mode"`
			DoHEndpoint string `yaml:"doh_endpoint"`
			DoTServer   string `yaml:"dot_server"`
		} `yaml:"dns"`
	} `yaml:"differential_probe"`
	MainstreamMixed struct {
		DegradeStrategy      string `yaml:"degrade_strategy"`
		ExplicitErrorMessage string `yaml:"explicit_error_message"`
	} `yaml:"mainstream_mixed"`
	ProtocolSLO struct {
		Enabled    bool           `yaml:"enabled"`
		MinHealthy map[string]int `yaml:"min_healthy"`
	} `yaml:"protocol_slo"`
	Alerting struct {
		ZeroMainstreamToleranceCycles int `yaml:"zero_mainstream_tolerance_cycles"`
	} `yaml:"alerting"`
}

type HealthCheckSettings struct {
	TotalTimeoutSeconds          int `yaml:"total_timeout_seconds"`
	TLSHandshakeThresholdSeconds int `yaml:"tls_handshake_threshold_seconds"`
}

type TwoStageHealthCheckSettings struct {
	StageOne HealthCheckSettings `yaml:"stage_one"`
	StageTwo HealthCheckSettings `yaml:"stage_two"`
}

type timeoutForwardDialer struct {
	timeout time.Duration
}

func (d timeoutForwardDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: d.timeout}).Dial(network, addr)
	if err != nil {
		return nil, err
	}

	if d.timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(d.timeout)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

// Global config variable
var config Config

const connectivityCheckInterval = 10 * time.Second
const defaultMixedHealthCheckURL = "https://www.google.com"
const healthCheckBatchSize = 50000
const adapterDialTimeout = 10 * time.Second
const healthCheckMaxRetries = 2
const requestForwardMaxRetries = 3
const retryBaseBackoff = 150 * time.Millisecond
const breakerFailureThreshold = 3
const breakerOpenTimeout = 30 * time.Second

var mixedHealthCheckURL = defaultMixedHealthCheckURL
var mixedProxyHealthChecker = checkMainstreamProxyHealth
var mixedCFBypassChecker = checkCloudflareBypassMixed

var parseFailureReasonCounter = struct {
	sync.Mutex
	counts map[string]int64
}{counts: make(map[string]int64)}

var parseFailureSampleCounter atomic.Int64

const parseFailureSampleLimit = 50

var upstreamDialerBuilder = buildUpstreamDialer
var mainstreamAdapterFactory = func() mainstreamDialAdapter { return &mainstreamTCPConnectAdapter{} }
var adapterMetrics = newAdapterObservabilityMetrics()
var adapterBreaker = newUpstreamBreaker()

type runtimeHealthState struct {
	mu                            sync.RWMutex
	ConsecutiveMainstreamZero     int
	MainstreamProtocolHealthCount map[string]int
	ProtocolSLOViolations         map[string]int
	HighPriorityAlert             bool
}

func newRuntimeHealthState() *runtimeHealthState {
	return &runtimeHealthState{
		MainstreamProtocolHealthCount: make(map[string]int),
		ProtocolSLOViolations:         make(map[string]int),
	}
}

func (s *runtimeHealthState) Update(mainstreamProtocolCounts map[string]int, consecutiveZero int, sloViolations map[string]int, highPriority bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConsecutiveMainstreamZero = consecutiveZero
	s.MainstreamProtocolHealthCount = cloneProtocolIntMap(mainstreamProtocolCounts)
	s.ProtocolSLOViolations = cloneProtocolIntMap(sloViolations)
	s.HighPriorityAlert = highPriority
}

func (s *runtimeHealthState) Snapshot() (int, map[string]int, map[string]int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ConsecutiveMainstreamZero, cloneProtocolIntMap(s.MainstreamProtocolHealthCount), cloneProtocolIntMap(s.ProtocolSLOViolations), s.HighPriorityAlert
}

var runtimeHealth = newRuntimeHealthState()

//go:embed web/admin/index.html
var adminPanelHTML string

type AdminRuntime struct {
	mu                  sync.RWMutex
	LastUpdateTime      time.Time
	LastHealthCheckTime time.Time
	LastUpdateStatus    string
}

func (a *AdminRuntime) MarkUpdated(status string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.LastUpdateTime = now
	a.LastHealthCheckTime = now
	a.LastUpdateStatus = status
}

func (a *AdminRuntime) Snapshot() (time.Time, time.Time, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.LastUpdateTime, a.LastHealthCheckTime, a.LastUpdateStatus
}

var adminRuntime = &AdminRuntime{}

type adapterObservabilityMetrics struct {
	mu                  sync.RWMutex
	dialTotal           map[string]int64
	dialLatencyBuckets  map[string]int64
	breakerState        map[string]int64
	retryExhaustedTotal int64
}

func newAdapterObservabilityMetrics() *adapterObservabilityMetrics {
	return &adapterObservabilityMetrics{
		dialTotal:          make(map[string]int64),
		dialLatencyBuckets: make(map[string]int64),
		breakerState:       make(map[string]int64),
	}
}

func (m *adapterObservabilityMetrics) AddDial(protocol, result, errorCode string, latency time.Duration) {
	key := strings.ToLower(strings.TrimSpace(protocol)) + "|" + strings.TrimSpace(result) + "|" + strings.TrimSpace(errorCode)
	bucket := dialLatencyBucket(latency)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialTotal[key]++
	m.dialLatencyBuckets[bucket]++
}

func (m *adapterObservabilityMetrics) SetBreakerState(protocol, upstream string, state bool) {
	key := strings.ToLower(strings.TrimSpace(protocol)) + "|" + strings.TrimSpace(upstream)
	value := int64(0)
	if state {
		value = 1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.breakerState[key] = value
}

func (m *adapterObservabilityMetrics) IncRetryExhausted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retryExhaustedTotal++
}

func (m *adapterObservabilityMetrics) Snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	dialTotal := make(map[string]int64, len(m.dialTotal))
	for k, v := range m.dialTotal {
		dialTotal[k] = v
	}
	buckets := make(map[string]int64, len(m.dialLatencyBuckets))
	for k, v := range m.dialLatencyBuckets {
		buckets[k] = v
	}
	breaker := make(map[string]int64, len(m.breakerState))
	for k, v := range m.breakerState {
		breaker[k] = v
	}
	return map[string]interface{}{
		"adapter_dial_total":             dialTotal,
		"adapter_dial_latency_ms_bucket": buckets,
		"adapter_breaker_state":          breaker,
		"adapter_retry_exhausted_total":  m.retryExhaustedTotal,
	}
}

func dialLatencyBucket(latency time.Duration) string {
	ms := latency.Milliseconds()
	switch {
	case ms <= 10:
		return "le_10"
	case ms <= 50:
		return "le_50"
	case ms <= 100:
		return "le_100"
	case ms <= 300:
		return "le_300"
	case ms <= 500:
		return "le_500"
	case ms <= 1000:
		return "le_1000"
	default:
		return "gt_1000"
	}
}

type breakerState struct {
	consecutiveFailures int
	openUntil           time.Time
}

type upstreamBreaker struct {
	mu     sync.Mutex
	states map[string]breakerState
}

func newUpstreamBreaker() *upstreamBreaker {
	return &upstreamBreaker{states: make(map[string]breakerState)}
}

func breakerKey(protocol, upstream string) string {
	return strings.ToLower(strings.TrimSpace(protocol)) + "|" + strings.TrimSpace(upstream)
}

func (b *upstreamBreaker) Allow(protocol, upstream string) bool {
	key := breakerKey(protocol, upstream)
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.states[key]
	open := time.Now().Before(state.openUntil)
	adapterMetrics.SetBreakerState(protocol, upstream, open)
	return !open
}

func (b *upstreamBreaker) RecordSuccess(protocol, upstream string) {
	key := breakerKey(protocol, upstream)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.states[key] = breakerState{}
	adapterMetrics.SetBreakerState(protocol, upstream, false)
}

func (b *upstreamBreaker) RecordFailure(protocol, upstream string) {
	key := breakerKey(protocol, upstream)
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.states[key]
	state.consecutiveFailures++
	if state.consecutiveFailures >= breakerFailureThreshold {
		state.openUntil = time.Now().Add(breakerOpenTimeout)
		state.consecutiveFailures = 0
	}
	b.states[key] = state
	adapterMetrics.SetBreakerState(protocol, upstream, time.Now().Before(state.openUntil))
}

func withDialTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, adapterDialTimeout)
}

func retryBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	return retryBaseBackoff * time.Duration(1<<(attempt-1))
}

// Simple regex to extract ip:port from any format (used for special proxy lists)
// Matches: [IP]:[port] and ignores any protocol prefixes or extra text
var simpleProxyRegex = regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})`)
var mixedURITokenRegex = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://\S+)`)

// loadConfig loads configuration from config.yaml
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate config
	if len(cfg.ProxyListURLs) == 0 {
		return nil, fmt.Errorf("at least one proxy_list_url must be specified")
	}
	if cfg.HealthCheckConcurrency <= 0 {
		cfg.HealthCheckConcurrency = 200
	}
	if cfg.UpdateIntervalMinutes <= 0 {
		cfg.UpdateIntervalMinutes = 5
	}
	if cfg.HealthCheck.TotalTimeoutSeconds <= 0 {
		cfg.HealthCheck.TotalTimeoutSeconds = 8
	}
	if cfg.HealthCheck.TLSHandshakeThresholdSeconds <= 0 {
		cfg.HealthCheck.TLSHandshakeThresholdSeconds = 4
	}
	if cfg.HealthCheckTwoStage.StageOne.TotalTimeoutSeconds <= 0 {
		cfg.HealthCheckTwoStage.StageOne.TotalTimeoutSeconds = 4
	}
	if cfg.HealthCheckTwoStage.StageOne.TLSHandshakeThresholdSeconds <= 0 {
		cfg.HealthCheckTwoStage.StageOne.TLSHandshakeThresholdSeconds = 2
	}
	if cfg.HealthCheckTwoStage.StageTwo.TotalTimeoutSeconds <= 0 {
		cfg.HealthCheckTwoStage.StageTwo.TotalTimeoutSeconds = 8
	}
	if cfg.HealthCheckTwoStage.StageTwo.TLSHandshakeThresholdSeconds <= 0 {
		cfg.HealthCheckTwoStage.StageTwo.TLSHandshakeThresholdSeconds = 4
	}
	if cfg.HealthCheckTwoStage.StrictMode == nil {
		strictModeDefault := false
		cfg.HealthCheckTwoStage.StrictMode = &strictModeDefault
	}
	if cfg.HealthCheckProtocolOverrides == nil {
		cfg.HealthCheckProtocolOverrides = make(map[string]TwoStageHealthCheckSettings)
	}
	defaultProtocolOverrides := map[string]TwoStageHealthCheckSettings{
		"http": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 5, TLSHandshakeThresholdSeconds: 5},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 5, TLSHandshakeThresholdSeconds: 5},
		},
		"https": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 5, TLSHandshakeThresholdSeconds: 5},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 5, TLSHandshakeThresholdSeconds: 5},
		},
		"ss": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 10, TLSHandshakeThresholdSeconds: 6},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 60, TLSHandshakeThresholdSeconds: 20},
		},
		"ssr": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 10, TLSHandshakeThresholdSeconds: 6},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 60, TLSHandshakeThresholdSeconds: 20},
		},
		"trojan": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 10, TLSHandshakeThresholdSeconds: 6},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 60, TLSHandshakeThresholdSeconds: 20},
		},
		"vmess": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 15, TLSHandshakeThresholdSeconds: 8},
		},
		"vless": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 30, TLSHandshakeThresholdSeconds: 12},
		},
		"hy2": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 30, TLSHandshakeThresholdSeconds: 12},
		},
	}
	for scheme, defaults := range defaultProtocolOverrides {
		override := cfg.HealthCheckProtocolOverrides[scheme]
		if override.StageOne.TotalTimeoutSeconds <= 0 {
			override.StageOne.TotalTimeoutSeconds = defaults.StageOne.TotalTimeoutSeconds
		}
		if override.StageOne.TLSHandshakeThresholdSeconds <= 0 {
			override.StageOne.TLSHandshakeThresholdSeconds = defaults.StageOne.TLSHandshakeThresholdSeconds
		}
		if override.StageTwo.TotalTimeoutSeconds <= 0 {
			override.StageTwo.TotalTimeoutSeconds = defaults.StageTwo.TotalTimeoutSeconds
		}
		if override.StageTwo.TLSHandshakeThresholdSeconds <= 0 {
			override.StageTwo.TLSHandshakeThresholdSeconds = defaults.StageTwo.TLSHandshakeThresholdSeconds
		}
		cfg.HealthCheckProtocolOverrides[scheme] = override
	}
	if len(cfg.TLSParamPolicy.DefaultALPN) == 0 {
		cfg.TLSParamPolicy.DefaultALPN = []string{"h2", "http/1.1"}
	}
	if !cfg.CertVerifyWhitelist.EnforceStrictAudit {
		cfg.CertVerifyWhitelist.EnforceStrictAudit = true
	}
	if cfg.ProxySwitchIntervalMin == "" {
		cfg.ProxySwitchIntervalMin = "30"
	}
	if cfg.Ports.SOCKS5Strict == "" {
		cfg.Ports.SOCKS5Strict = ":1080"
	}
	if cfg.Ports.SOCKS5Relaxed == "" {
		cfg.Ports.SOCKS5Relaxed = ":1082"
	}
	if cfg.Ports.HTTPStrict == "" {
		cfg.Ports.HTTPStrict = ":8080"
	}
	if cfg.Ports.HTTPRelaxed == "" {
		cfg.Ports.HTTPRelaxed = ":8082"
	}
	if cfg.Ports.HTTPMixed == "" {
		cfg.Ports.HTTPMixed = ":8083"
	}
	if cfg.Ports.HTTPMainstreamMix == "" {
		cfg.Ports.HTTPMainstreamMix = ":8085"
	}
	if cfg.DifferentialProbe.TargetURL == "" {
		cfg.DifferentialProbe.TargetURL = defaultMixedHealthCheckURL
	}
	if cfg.DifferentialProbe.SamplesPerProtocol <= 0 {
		cfg.DifferentialProbe.SamplesPerProtocol = 5
	}
	if cfg.DifferentialProbe.SamplesPerProtocol > 10 {
		cfg.DifferentialProbe.SamplesPerProtocol = 10
	}
	if strings.TrimSpace(cfg.DifferentialProbe.GoldenSampleFile) == "" {
		cfg.DifferentialProbe.GoldenSampleFile = "golden-proxies.yaml"
	}
	if strings.TrimSpace(cfg.DifferentialProbe.CompareTLSPolicy) == "" {
		cfg.DifferentialProbe.CompareTLSPolicy = "relaxed"
	}
	cfg.DifferentialProbe.DNS.Mode = strings.ToLower(strings.TrimSpace(cfg.DifferentialProbe.DNS.Mode))
	if cfg.DifferentialProbe.DNS.Mode == "" {
		cfg.DifferentialProbe.DNS.Mode = "system"
	}
	if strings.TrimSpace(cfg.DifferentialProbe.DNS.DoHEndpoint) == "" {
		cfg.DifferentialProbe.DNS.DoHEndpoint = "https://dns.google/resolve"
	}
	if strings.TrimSpace(cfg.DifferentialProbe.DNS.DoTServer) == "" {
		cfg.DifferentialProbe.DNS.DoTServer = "1.1.1.1:853"
	}
	if cfg.Ports.HTTPCFMixed == "" {
		cfg.Ports.HTTPCFMixed = ":8084"
	}
	if cfg.Ports.RotateControl == "" {
		cfg.Ports.RotateControl = ":9090"
	}
	cfg.MainstreamMixed.DegradeStrategy = strings.ToLower(strings.TrimSpace(cfg.MainstreamMixed.DegradeStrategy))
	if cfg.MainstreamMixed.DegradeStrategy == "" {
		cfg.MainstreamMixed.DegradeStrategy = "explicit_error"
	}
	if cfg.MainstreamMixed.DegradeStrategy != "fallback_http_socks" && cfg.MainstreamMixed.DegradeStrategy != "explicit_error" {
		return nil, fmt.Errorf("mainstream_mixed.degrade_strategy must be one of: fallback_http_socks, explicit_error")
	}
	if strings.TrimSpace(cfg.MainstreamMixed.ExplicitErrorMessage) == "" {
		cfg.MainstreamMixed.ExplicitErrorMessage = "Mainstream upstream unavailable"
	}
	if cfg.ProtocolSLO.MinHealthy == nil {
		cfg.ProtocolSLO.MinHealthy = map[string]int{}
	}
	normalizedSLO := make(map[string]int, len(cfg.ProtocolSLO.MinHealthy))
	for protocol, min := range cfg.ProtocolSLO.MinHealthy {
		normalized := strings.ToLower(strings.TrimSpace(protocol))
		if normalized == "" || min <= 0 {
			continue
		}
		normalizedSLO[normalized] = min
	}
	cfg.ProtocolSLO.MinHealthy = normalizedSLO
	if cfg.Alerting.ZeroMainstreamToleranceCycles <= 0 {
		cfg.Alerting.ZeroMainstreamToleranceCycles = 1
	}

	if cfg.CFChallengeCheck.Enabled {
		if cfg.CFChallengeCheck.URL == "" {
			return nil, fmt.Errorf("cf_challenge_check.url must be set when enabled")
		}
		if cfg.CFChallengeCheck.TimeoutSeconds <= 0 {
			cfg.CFChallengeCheck.TimeoutSeconds = 12
		}
		if len(cfg.CFChallengeCheck.ExpectedStatuses) == 0 {
			cfg.CFChallengeCheck.ExpectedStatuses = []int{http.StatusOK}
		}
	}

	if (cfg.Auth.Username == "") != (cfg.Auth.Password == "") {
		return nil, fmt.Errorf("both auth.username and auth.password must be configured together")
	}

	return &cfg, nil
}

func isProxyAuthEnabled() bool {
	return config.Auth.Username != "" && config.Auth.Password != ""
}

func parseProxySwitchInterval(raw string) (time.Duration, bool, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		value = "30"
	}

	if value == "now" {
		return 0, true, nil
	}

	minutes, err := strconv.Atoi(value)
	if err != nil || minutes <= 0 {
		return 0, false, fmt.Errorf("proxy_switch_interval_min must be a positive integer (minutes) or 'now'")
	}

	return time.Duration(minutes) * time.Minute, false, nil
}

func requireHTTPProxyAuth(w http.ResponseWriter, mode string) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="Dynamic Proxy"`)
	log.Printf("[HTTP-%s] Unauthorized request rejected", mode)
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}

func requireBasicAuth(w http.ResponseWriter, mode string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Dynamic Proxy Rotate Control"`)
	log.Printf("[%s] Unauthorized request rejected", mode)
	http.Error(w, "Authentication required", http.StatusUnauthorized)
}

func validateHTTPProxyAuth(r *http.Request) bool {
	return validateAuthHeader(r.Header.Get("Proxy-Authorization"))
}

func validateBasicAuth(r *http.Request) bool {
	return validateAuthHeader(r.Header.Get("Authorization"))
}

func validateAuthHeader(authHeader string) bool {
	if !isProxyAuthEnabled() {
		return true
	}

	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}

	return credentials[0] == config.Auth.Username && credentials[1] == config.Auth.Password
}

type ProxyPool struct {
	proxies            []string
	mu                 sync.RWMutex
	index              int
	nextSwitch         time.Time
	hasSelected        bool
	updating           int32 // atomic flag to prevent concurrent updates
	rng                *rand.Rand
	rotateEveryRequest bool
	switchInterval     time.Duration
}

func NewProxyPool(switchInterval time.Duration, rotateEveryRequest bool) *ProxyPool {
	return &ProxyPool{
		proxies:            make([]string, 0),
		rng:                rand.New(rand.NewSource(time.Now().UnixNano())),
		switchInterval:     switchInterval,
		rotateEveryRequest: rotateEveryRequest,
	}
}

func (p *ProxyPool) Update(proxies []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldCount := len(p.proxies)
	p.proxies = proxies
	// Reset selection state so the first connection after update reselects a proxy.
	p.index = 0
	p.nextSwitch = time.Time{}
	p.hasSelected = false

	log.Printf("Proxy pool updated: %d -> %d active proxies", oldCount, len(proxies))
}

func (p *ProxyPool) GetNext() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.proxies) == 0 {
		return "", fmt.Errorf("no available proxies")
	}

	// First request after a pool update randomly selects one healthy proxy.
	if !p.hasSelected {
		p.index = p.randomIndexExcluding(-1)
		if !p.rotateEveryRequest {
			p.nextSwitch = time.Now().Add(p.switchInterval)
		}
		p.hasSelected = true
		return p.proxies[p.index], nil
	}

	if p.rotateEveryRequest {
		p.index = p.randomIndexExcluding(p.index)
		return p.proxies[p.index], nil
	}

	// Keep using the same proxy until the next switch timestamp, then randomly switch.
	now := time.Now()
	if !p.nextSwitch.IsZero() && (now.After(p.nextSwitch) || now.Equal(p.nextSwitch)) {
		p.index = p.randomIndexExcluding(p.index)
		p.nextSwitch = now.Add(p.switchInterval)
	}

	if p.index >= len(p.proxies) {
		p.index = 0
	}

	return p.proxies[p.index], nil
}

func (p *ProxyPool) randomIndexExcluding(exclude int) int {
	if len(p.proxies) <= 1 {
		return 0
	}

	idx := p.rng.Intn(len(p.proxies) - 1)
	if exclude >= 0 && idx >= exclude {
		idx++
	}
	return idx
}

func (p *ProxyPool) GetAll() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]string, len(p.proxies))
	copy(result, p.proxies)
	return result
}

func (p *ProxyPool) GetCurrent() (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.proxies) == 0 || !p.hasSelected {
		return "", false
	}

	if p.index < 0 || p.index >= len(p.proxies) {
		return "", false
	}

	return p.proxies[p.index], true
}

func (p *ProxyPool) ForceRotate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.proxies) == 0 {
		return "", fmt.Errorf("no available proxies")
	}

	if !p.hasSelected {
		p.index = p.randomIndexExcluding(-1)
		p.hasSelected = true
	} else {
		p.index = p.randomIndexExcluding(p.index)
	}

	if !p.rotateEveryRequest {
		p.nextSwitch = time.Now().Add(p.switchInterval)
	} else {
		p.nextSwitch = time.Time{}
	}
	return p.proxies[p.index], nil
}

func (p *ProxyPool) ForceRotateIfCurrent(expected string) (string, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.proxies) == 0 {
		return "", false, fmt.Errorf("no available proxies")
	}
	if !p.hasSelected || p.index < 0 || p.index >= len(p.proxies) {
		return "", false, nil
	}
	if p.proxies[p.index] != expected {
		return p.proxies[p.index], false, nil
	}

	p.index = p.randomIndexExcluding(p.index)
	if !p.rotateEveryRequest {
		p.nextSwitch = time.Now().Add(p.switchInterval)
	} else {
		p.nextSwitch = time.Time{}
	}
	return p.proxies[p.index], true, nil
}

// parseSpecialProxyURL 使用简单正则表达式从复杂格式中提取代理
// 支持格式：任何包含 ip:port 的行，自动忽略协议前缀和描述文本
// 例如：socks5://83.217.209.26:1 [[家宽] 英国] → 提取 83.217.209.26:1
func parseSpecialProxyURL(content string) ([]string, error) {
	content = preprocessSubscriptionContent(content)
	var proxies []string
	proxySet := make(map[string]bool) // 用于去重

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 使用简单正则直接提取 ip:port，忽略所有其他内容
		matches := simpleProxyRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			ip := matches[1]
			port := matches[2]
			proxy := fmt.Sprintf("%s:%s", ip, port)

			// 去重
			if !proxySet[proxy] {
				proxySet[proxy] = true
				proxies = append(proxies, proxy)
			}
		}
	}

	return proxies, nil
}

type clashSubscription struct {
	Proxies []struct {
		Type        string            `yaml:"type"`
		Server      string            `yaml:"server"`
		Port        int               `yaml:"port"`
		Username    string            `yaml:"username"`
		Password    string            `yaml:"password"`
		UUID        string            `yaml:"uuid"`
		Cipher      string            `yaml:"cipher"`
		Network     string            `yaml:"network"`
		TLS         interface{}       `yaml:"tls"`
		SNI         string            `yaml:"sni"`
		ServerName  string            `yaml:"servername"`
		ALPN        []string          `yaml:"alpn"`
		Flow        string            `yaml:"flow"`
		ClientFP    string            `yaml:"client-fingerprint"`
		RealityOpts map[string]string `yaml:"reality-opts"`
		WSOpts      struct {
			Path    string            `yaml:"path"`
			Headers map[string]string `yaml:"headers"`
		} `yaml:"ws-opts"`
		Hysteria2 struct {
			Password string `yaml:"password"`
			SNI      string `yaml:"sni"`
			Obfs     string `yaml:"obfs"`
			ObfsPass string `yaml:"obfs-password"`
		} `yaml:"hysteria2"`
	} `yaml:"proxies"`
}

var mixedSupportedSchemes = map[string]bool{
	"http":      true,
	"https":     true,
	"socks5":    true,
	"socks5h":   true,
	"vmess":     true,
	"vless":     true,
	"ss":        true,
	"ssr":       true,
	"trojan":    true,
	"hysteria":  true,
	"hy2":       true,
	"hysteria2": true,
	"tuic":      true,
	"wg":        true,
	"wireguard": true,
}

var httpSocksMixedSchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks5":  true,
	"socks5h": true,
}

var mainstreamMixedExcludedSchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks5":  true,
	"socks5h": true,
}

func parseClashSubscriptionForStrictRelaxed(content string) ([]string, bool) {
	var sub clashSubscription
	if err := yaml.Unmarshal([]byte(content), &sub); err != nil || len(sub.Proxies) == 0 {
		return nil, false
	}

	result := make([]string, 0, len(sub.Proxies))
	seen := make(map[string]bool)
	for _, p := range sub.Proxies {
		proxyType := strings.ToLower(strings.TrimSpace(p.Type))
		if !mixedSupportedSchemes[proxyType] {
			continue
		}
		if p.Server == "" || p.Port <= 0 {
			continue
		}
		entry := fmt.Sprintf("%s://%s", proxyType, net.JoinHostPort(p.Server, strconv.Itoa(p.Port)))
		if normalized, ok := normalizeMixedProxyEntry(entry); ok {
			entry = normalized
		}
		if !seen[entry] {
			seen[entry] = true
			result = append(result, entry)
		}
	}

	return result, len(result) > 0
}

func parseRegularProxyContent(content string) ([]string, string) {
	content = preprocessSubscriptionContent(content)
	if clashProxies, ok := parseClashSubscriptionForStrictRelaxed(content); ok {
		return clashProxies, "clash"
	}

	if decoded, ok := decodeBase64ProxySubscription(content); ok {
		if decodedProxies, decodedFormat := parseRegularProxyContent(decoded); len(decodedProxies) > 0 {
			return decodedProxies, "base64+" + decodedFormat
		}
	}

	proxies := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if normalized, ok := normalizeMixedProxyEntry(line); ok {
			proxies = append(proxies, normalized)
		} else {
			sampleParseFailureLine("parse_failed", line, "normalize_failed")
		}
	}

	return proxies, "plain"
}

func parseRegularProxyContentMixed(content string) ([]string, string) {
	content = preprocessSubscriptionContent(content)
	if clashProxies, ok := parseClashSubscriptionForMixed(content); ok {
		return clashProxies, "clash"
	}

	if decoded, ok := decodeBase64ProxySubscription(content); ok {
		if decodedProxies, decodedFormat := parseRegularProxyContentMixed(decoded); len(decodedProxies) > 0 {
			return decodedProxies, "base64+" + decodedFormat
		}
	}

	proxies := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		normalized, ok := normalizeMixedProxyEntry(line)
		if ok {
			proxies = append(proxies, normalized)
		} else {
			sampleParseFailureLine("parse_failed", line, "normalize_failed")
		}
	}

	return proxies, "plain"
}

func parseClashSubscriptionForMixed(content string) ([]string, bool) {
	var sub clashSubscription
	if err := yaml.Unmarshal([]byte(content), &sub); err != nil || len(sub.Proxies) == 0 {
		return nil, false
	}

	result := make([]string, 0, len(sub.Proxies))
	seen := make(map[string]bool)
	for _, p := range sub.Proxies {
		proxyType := strings.ToLower(strings.TrimSpace(p.Type))
		if !mixedSupportedSchemes[proxyType] {
			continue
		}
		if p.Server == "" || p.Port <= 0 {
			continue
		}
		host := net.JoinHostPort(p.Server, strconv.Itoa(p.Port))
		entry := ""
		sni := strings.TrimSpace(p.SNI)
		if sni == "" {
			sni = strings.TrimSpace(p.ServerName)
		}
		switch proxyType {
		case "vmess":
			if p.UUID == "" {
				continue
			}
			q := url.Values{}
			q.Set("id", p.UUID)
			if netw := strings.TrimSpace(p.Network); netw != "" {
				q.Set("network", netw)
			}
			if path := strings.TrimSpace(p.WSOpts.Path); path != "" {
				q.Set("path", path)
			}
			if hostHeader := strings.TrimSpace(p.WSOpts.Headers["Host"]); hostHeader != "" {
				q.Set("host", hostHeader)
			}
			if tlsValue := normalizeClashTLS(p.TLS); tlsValue != "" {
				q.Set("tls", tlsValue)
			}
			if sni != "" {
				q.Set("sni", sni)
			}
			if len(p.ALPN) > 0 {
				q.Set("alpn", strings.Join(p.ALPN, ","))
			}
			entry = fmt.Sprintf("vmess://%s?%s", host, q.Encode())
		case "ss":
			if p.Cipher == "" || p.Password == "" {
				continue
			}
			entry = fmt.Sprintf("ss://%s:%s@%s", url.QueryEscape(p.Cipher), url.QueryEscape(p.Password), host)
		case "vless":
			if p.UUID == "" {
				continue
			}
			q := url.Values{}
			q.Set("encryption", "none")
			if netw := strings.TrimSpace(p.Network); netw != "" {
				q.Set("type", netw)
			}
			if path := strings.TrimSpace(p.WSOpts.Path); path != "" {
				q.Set("path", path)
			}
			if hostHeader := strings.TrimSpace(p.WSOpts.Headers["Host"]); hostHeader != "" {
				q.Set("host", hostHeader)
			}
			if tlsValue := normalizeClashTLS(p.TLS); tlsValue != "" && tlsValue != "false" {
				q.Set("security", "tls")
			}
			if sni != "" {
				q.Set("sni", sni)
			}
			if len(p.ALPN) > 0 {
				q.Set("alpn", strings.Join(p.ALPN, ","))
			}
			if flow := strings.TrimSpace(p.Flow); flow != "" {
				q.Set("flow", flow)
			}
			if fp := strings.TrimSpace(p.ClientFP); fp != "" {
				q.Set("fp", fp)
			}
			if pbk := strings.TrimSpace(p.RealityOpts["public-key"]); pbk != "" {
				q.Set("pbk", pbk)
			}
			if sid := strings.TrimSpace(p.RealityOpts["short-id"]); sid != "" {
				q.Set("sid", sid)
			}
			entry = fmt.Sprintf("vless://%s@%s?%s", url.QueryEscape(p.UUID), host, q.Encode())
		case "hy2", "hysteria2":
			password := strings.TrimSpace(p.Password)
			if password == "" {
				password = strings.TrimSpace(p.Hysteria2.Password)
			}
			if password == "" {
				continue
			}
			q := url.Values{}
			if sni != "" {
				q.Set("sni", sni)
			}
			if len(p.ALPN) > 0 {
				q.Set("alpn", strings.Join(p.ALPN, ","))
			}
			obfs := strings.TrimSpace(p.Hysteria2.Obfs)
			if obfs != "" {
				q.Set("obfs", obfs)
			}
			if obfsPassword := strings.TrimSpace(p.Hysteria2.ObfsPass); obfsPassword != "" {
				q.Set("obfs-password", obfsPassword)
			}
			if q.Encode() != "" {
				entry = fmt.Sprintf("%s://%s@%s?%s", proxyType, url.QueryEscape(password), host, q.Encode())
			} else {
				entry = fmt.Sprintf("%s://%s@%s", proxyType, url.QueryEscape(password), host)
			}
		case "trojan":
			if p.Password == "" {
				continue
			}
			entry = fmt.Sprintf("trojan://%s@%s", url.QueryEscape(p.Password), host)
		case "http", "https", "socks5", "socks5h":
			if p.Username != "" {
				entry = fmt.Sprintf("%s://%s:%s@%s", proxyType, url.QueryEscape(p.Username), url.QueryEscape(p.Password), host)
			} else {
				entry = fmt.Sprintf("%s://%s", proxyType, host)
			}
		default:
			entry = fmt.Sprintf("%s://%s", proxyType, host)
		}
		if !seen[entry] {
			seen[entry] = true
			result = append(result, entry)
		}
	}

	return result, len(result) > 0
}

func detectProxyScheme(entry string, defaultScheme string) string {
	trimmed := strings.TrimSpace(entry)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil {
			return strings.ToLower(strings.TrimSpace(u.Scheme))
		}
	}
	return strings.ToLower(strings.TrimSpace(defaultScheme))
}

func logSchemeDistribution(tag string, entries []string, defaultScheme string) {
	schemeCount := make(map[string]int)
	for _, entry := range entries {
		scheme := detectProxyScheme(entry, defaultScheme)
		if scheme == "" {
			scheme = "unknown"
		}
		schemeCount[scheme]++
	}

	keys := make([]string, 0, len(schemeCount))
	for scheme := range schemeCount {
		keys = append(keys, scheme)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, scheme := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", scheme, schemeCount[scheme]))
	}

	if len(parts) == 0 {
		log.Printf("%s parse scheme distribution: empty", tag)
		return
	}
	log.Printf("%s parse scheme distribution: %s", tag, strings.Join(parts, ", "))
}

func normalizeSocksPoolEntry(entry string) (string, bool) {
	scheme, addr, _, _, err := parseMixedProxy(entry)
	if err != nil {
		return "", false
	}
	if scheme != "socks5" && scheme != "socks5h" {
		return "", false
	}
	return addr, true
}

func decodeBase64ProxySubscription(content string) (string, bool) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "", false
	}

	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, trimmed)
	compact = normalizeURLSafeBase64Token(compact)

	if len(compact) < 32 {
		return "", false
	}

	for _, ch := range compact {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_' {
			continue
		}
		return "", false
	}

	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}

	for _, decode := range decoders {
		payload, err := decode(compact)
		if err != nil || len(payload) == 0 || !utf8.Valid(payload) {
			continue
		}

		decoded := strings.TrimSpace(string(payload))
		if decoded == "" || decoded == trimmed {
			continue
		}

		if strings.Contains(decoded, "://") || strings.Contains(strings.ToLower(decoded), "proxies:") || simpleProxyRegex.MatchString(decoded) {
			return decoded, true
		}
	}

	return "", false
}

func preprocessSubscriptionContent(content string) string {
	if content == "" {
		return ""
	}
	processed := strings.TrimPrefix(content, "\ufeff")
	processed = strings.ReplaceAll(processed, "\r\n", "\n")
	processed = strings.ReplaceAll(processed, "\r", "\n")

	processed = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, processed)

	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, processed)
	if isLikelyBase64Payload(compact) {
		processed = normalizeURLSafeBase64Token(compact)
	}
	return processed
}

func isLikelyBase64Payload(content string) bool {
	if len(content) < 16 {
		return false
	}
	for _, ch := range content {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizeURLSafeBase64Token(token string) string {
	replaced := strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimSpace(token))
	if replaced == "" {
		return ""
	}
	if rem := len(replaced) % 4; rem != 0 {
		replaced += strings.Repeat("=", 4-rem)
	}
	return replaced
}

func recordParseFailureReasonTag(scope string, reason string) {
	if scope == "" || reason == "" {
		return
	}
	key := scope + ":" + reason
	parseFailureReasonCounter.Lock()
	parseFailureReasonCounter.counts[key]++
	parseFailureReasonCounter.Unlock()
}

func sanitizeSampleLine(raw string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if trimmed == "" {
		return ""
	}
	if u, err := url.Parse(trimmed); err == nil {
		if u.User != nil {
			u.User = url.User("***")
		}
		for _, key := range []string{"token", "password", "passwd", "auth", "key", "secret", "uuid", "id"} {
			if q := u.Query(); q.Has(key) {
				q.Set(key, "***")
				u.RawQuery = q.Encode()
			}
		}
		if s := u.String(); s != "" {
			trimmed = s
		}
	}
	trimmed = regexp.MustCompile(`(?i)(password|passwd|token|secret|uuid|id)=([^&\s]+)`).ReplaceAllString(trimmed, "$1=***")
	trimmed = regexp.MustCompile(`(?i)(://)([^/@\s]+)@`).ReplaceAllString(trimmed, "$1***@")
	if len(trimmed) > 240 {
		trimmed = trimmed[:240] + "..."
	}
	return trimmed
}

func sampleParseFailureLine(category string, raw string, reason string) {
	if parseFailureSampleCounter.Add(1) > parseFailureSampleLimit {
		return
	}
	sanitized := sanitizeSampleLine(raw)
	if sanitized == "" {
		return
	}
	log.Printf("[SUB_PARSE_SAMPLE][%s] reason=%s line=%s", category, reason, sanitized)
}

func normalizeMixedProxyEntry(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		recordParseFailureReasonTag("normalize", "empty_line")
		return "", false
	}
	if candidate, ok := extractMixedURICandidate(line); ok {
		line = candidate
	}

	if strings.Contains(line, "://") {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "ss://") {
			if normalized, ok := normalizeSSURI(line); ok {
				return normalized, true
			}
			recordParseFailureReasonTag("ss", "invalid_query")
			return "", false
		}

		if strings.HasPrefix(lowerLine, "vmess://") {
			if normalized, ok := normalizeVMESSURI(line); ok {
				return normalized, true
			}
			recordParseFailureReasonTag("vmess", "invalid_query")
		}

		if strings.HasPrefix(lowerLine, "ssr://") {
			if normalized, ok := normalizeSSRURI(line); ok {
				return normalized, true
			}
			recordParseFailureReasonTag("ssr", "invalid_query")
			return "", false
		}

		if strings.HasPrefix(lowerLine, "trojan://") {
			u, err := url.Parse(line)
			if err != nil {
				recordParseFailureReasonTag("trojan", "invalid_query")
				return "", false
			}
			if u.Host == "" {
				recordParseFailureReasonTag("trojan", "missing_host")
				return "", false
			}
			if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
				recordParseFailureReasonTag("trojan", "invalid_userinfo")
				return "", false
			}
		}

		if strings.HasPrefix(lowerLine, "wg://") || strings.HasPrefix(lowerLine, "wireguard://") {
			if normalized, ok := normalizeWireGuardURI(line); ok {
				return normalized, true
			}
			recordParseFailureReasonTag("wireguard", "invalid_query")
		}

		u, err := url.Parse(line)
		if err != nil {
			recordParseFailureReasonTag("normalize", "invalid_query")
			return "", false
		}
		if strings.TrimSpace(u.Hostname()) == "" {
			recordParseFailureReasonTag(strings.ToLower(u.Scheme), "missing_host")
			return "", false
		}
		if strings.TrimSpace(u.Port()) == "" {
			recordParseFailureReasonTag(strings.ToLower(u.Scheme), "missing_port")
			return "", false
		}
		scheme := strings.ToLower(u.Scheme)
		if !mixedSupportedSchemes[scheme] {
			return "", false
		}
		applyCriticalTLSParams(scheme, u)
		if !validateMainstreamURI(scheme, u) {
			recordParseFailureReasonTag(scheme, "invalid_userinfo")
			return "", false
		}
		authority := u.Host
		if u.User != nil {
			authority = u.User.String() + "@" + authority
		}
		normalized := fmt.Sprintf("%s://%s", scheme, authority)
		if strings.TrimSpace(u.RawQuery) != "" {
			filteredQuery := filterRawQueryWithWhitelist(u.RawQuery, scheme)
			if filteredQuery == "" {
				recordParseFailureReasonTag(scheme, "invalid_query")
			} else {
				normalized += "?" + filteredQuery
			}
		}
		if u.Fragment != "" && scheme != "vless" {
			normalized += "#" + u.Fragment
		}
		return normalized, true
	}

	return "socks5://" + line, true
}

func defaultALPNForScheme(scheme string) []string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "hy2", "hysteria2":
		return []string{"h3"}
	default:
		if len(config.TLSParamPolicy.DefaultALPN) == 0 {
			return []string{"h2", "http/1.1"}
		}
		return config.TLSParamPolicy.DefaultALPN
	}
}

func applyCriticalTLSParams(scheme string, u *url.URL) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme != "vless" && scheme != "trojan" && scheme != "hy2" && scheme != "hysteria2" {
		return
	}
	q := u.Query()
	sni := strings.TrimSpace(q.Get("sni"))
	if sni == "" {
		sni = strings.TrimSpace(q.Get("server_name"))
	}
	if sni == "" {
		sni = strings.TrimSpace(u.Hostname())
	}
	if sni != "" {
		q.Set("sni", sni)
		q.Set("server_name", sni)
	}
	if strings.TrimSpace(q.Get("alpn")) == "" {
		q.Set("alpn", strings.Join(defaultALPNForScheme(scheme), ","))
	}
	insecure := "false"
	if config.TLSParamPolicy.DefaultAllowInsecure {
		insecure = "true"
	}
	if strings.TrimSpace(q.Get("insecure")) == "" {
		q.Set("insecure", insecure)
		q.Set("allow_insecure", insecure)
	}
	u.RawQuery = q.Encode()
}

func shouldAllowInsecureByWhitelist(proxyEntry string) (bool, string) {
	if !config.CertVerifyWhitelist.Enabled || len(config.CertVerifyWhitelist.AllowedHosts) == 0 {
		return false, ""
	}
	u, parseErr := url.Parse(strings.TrimSpace(proxyEntry))
	if parseErr != nil {
		return false, ""
	}
	_, addr, _, _, err := parseMixedProxy(proxyEntry)
	if err != nil {
		return false, ""
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if config.CertVerifyWhitelist.RequireInsecure {
		insecure := strings.ToLower(strings.TrimSpace(u.Query().Get("insecure")))
		allowInsecure := strings.ToLower(strings.TrimSpace(u.Query().Get("allow_insecure")))
		if insecure != "true" && allowInsecure != "true" {
			return false, host
		}
	}
	for _, item := range config.CertVerifyWhitelist.AllowedHosts {
		allowed := strings.ToLower(strings.TrimSpace(item))
		if allowed == "" {
			continue
		}
		if host == allowed {
			return true, host
		}
	}
	return false, host
}

func normalizeClashTLS(raw interface{}) string {
	switch v := raw.(type) {
	case bool:
		if v {
			return "tls"
		}
		return "false"
	case string:
		trimmed := strings.TrimSpace(strings.ToLower(v))
		if trimmed == "" {
			return ""
		}
		if trimmed == "true" {
			return "tls"
		}
		return trimmed
	default:
		return ""
	}
}

var mixedCommonQueryWhitelist = map[string]bool{
	"sni": true, "server_name": true, "alpn": true, "insecure": true, "allow_insecure": true, "security": true,
	"host": true, "path": true, "type": true, "network": true,
	"flow": true, "pbk": true, "sid": true, "fp": true,
	"serviceName": true, "mode": true, "auth": true,
	"obfs": true, "obfs-password": true,
}

var mixedSchemeQueryWhitelist = map[string]map[string]bool{
	"vmess":     {"id": true, "aid": true, "net": true, "tls": true},
	"vless":     {"encryption": true},
	"hy2":       {"peer": true, "up": true, "down": true, "mport": true, "ports": true, "password": true},
	"hysteria2": {"peer": true, "up": true, "down": true, "mport": true, "ports": true, "password": true},
}

func filterRawQueryWithWhitelist(rawQuery string, scheme string) string {
	if strings.TrimSpace(rawQuery) == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	allowed := make(map[string]bool, len(mixedCommonQueryWhitelist)+8)
	for k := range mixedCommonQueryWhitelist {
		allowed[k] = true
	}
	for k := range mixedSchemeQueryWhitelist[scheme] {
		allowed[k] = true
	}
	if len(allowed) == 0 {
		return rawQuery
	}
	filtered := url.Values{}
	for key, vals := range values {
		if !allowed[key] {
			continue
		}
		for _, v := range vals {
			filtered.Add(key, v)
		}
	}
	return filtered.Encode()
}

func normalizeVMESSURI(raw string) (string, bool) {
	node, ok := parseVMESSNode(raw)
	if !ok {
		return "", false
	}
	payload, err := json.Marshal(node)
	if err != nil {
		return "", false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(payload), true
}

type vmessNode struct {
	V    string `json:"v,omitempty"`
	Ps   string `json:"ps,omitempty"`
	Add  string `json:"add,omitempty"`
	Port string `json:"port,omitempty"`
	ID   string `json:"id,omitempty"`
	Aid  string `json:"aid,omitempty"`
	Net  string `json:"net,omitempty"`
	Type string `json:"type,omitempty"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
	TLS  string `json:"tls,omitempty"`
	SNI  string `json:"sni,omitempty"`
}

type vlessNode struct {
	Address   string
	Port      string
	UUID      string
	SNI       string
	Transport string
	Host      string
	Path      string
	Security  string
	Flow      string
	RawQuery  string
}

type hy2Node struct {
	Address      string
	Port         string
	Password     string
	SNI          string
	ALPN         string
	Obfs         string
	ObfsPassword string
	RawQuery     string
}

func parseVMESSNode(raw string) (vmessNode, bool) {
	var node vmessNode
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(trimmed), "vmess://") {
		return node, false
	}

	encoded := strings.TrimSpace(strings.TrimPrefix(trimmed, "vmess://"))
	if idx := strings.Index(encoded, "#"); idx >= 0 {
		encoded = encoded[:idx]
	}

	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, decode := range decoders {
		payload, err := decode(encoded)
		if err != nil {
			continue
		}
		if jsonErr := json.Unmarshal(payload, &node); jsonErr == nil {
			node.Add = strings.TrimSpace(node.Add)
			node.Port = strings.TrimSpace(node.Port)
			if node.Add != "" && node.Port != "" {
				if node.V == "" {
					node.V = "2"
				}
				if node.Type == "" {
					node.Type = "none"
				}
				return node, true
			}
		}
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		recordParseFailureReasonTag("vmess", "invalid_query")
		return node, false
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		recordParseFailureReasonTag("vmess", "missing_host")
		return node, false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		recordParseFailureReasonTag("vmess", "missing_port")
		return node, false
	}
	q := u.Query()
	node = vmessNode{
		V:    "2",
		Add:  host,
		Port: port,
		ID:   strings.TrimSpace(q.Get("id")),
		Aid:  strings.TrimSpace(q.Get("aid")),
		Net:  strings.TrimSpace(q.Get("net")),
		Type: strings.TrimSpace(q.Get("type")),
		Host: strings.TrimSpace(q.Get("host")),
		Path: strings.TrimSpace(q.Get("path")),
		TLS:  strings.TrimSpace(q.Get("tls")),
		SNI:  strings.TrimSpace(q.Get("sni")),
	}
	if node.Net == "" {
		node.Net = strings.TrimSpace(q.Get("network"))
	}
	if node.Net == "" {
		node.Net = strings.TrimSpace(q.Get("type"))
	}
	if node.Type == "" {
		node.Type = "none"
	}
	if node.TLS == "" {
		node.TLS = strings.TrimSpace(q.Get("security"))
	}
	if node.TLS == "" && strings.EqualFold(strings.TrimSpace(q.Get("security")), "tls") {
		node.TLS = "tls"
	}
	if node.Add == "" {
		recordParseFailureReasonTag("vmess", "missing_host")
		return vmessNode{}, false
	}
	if node.Port == "" {
		recordParseFailureReasonTag("vmess", "missing_port")
		return vmessNode{}, false
	}
	return node, true
}

func parseVLESSNode(raw string) (vlessNode, bool) {
	node := vlessNode{}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		recordParseFailureReasonTag("vless", "invalid_query")
		return node, false
	}
	if strings.ToLower(u.Scheme) != "vless" {
		return node, false
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if host == "" {
		recordParseFailureReasonTag("vless", "missing_host")
		return node, false
	}
	if port == "" {
		recordParseFailureReasonTag("vless", "missing_port")
		return node, false
	}
	if u.User == nil {
		recordParseFailureReasonTag("vless", "invalid_userinfo")
		return node, false
	}
	uuid := strings.TrimSpace(u.User.Username())
	if uuid == "" {
		recordParseFailureReasonTag("vless", "invalid_userinfo")
		return node, false
	}
	q := u.Query()
	node = vlessNode{
		Address:   host,
		Port:      port,
		UUID:      uuid,
		SNI:       strings.TrimSpace(q.Get("sni")),
		Transport: strings.TrimSpace(q.Get("type")),
		Host:      strings.TrimSpace(q.Get("host")),
		Path:      strings.TrimSpace(q.Get("path")),
		Security:  strings.TrimSpace(q.Get("security")),
		Flow:      strings.TrimSpace(q.Get("flow")),
		RawQuery:  filterRawQueryWithWhitelist(u.RawQuery, "vless"),
	}
	if node.Transport == "" {
		node.Transport = strings.TrimSpace(q.Get("network"))
	}
	return node, true
}

func parseHY2Node(raw string) (hy2Node, bool) {
	node := hy2Node{}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		recordParseFailureReasonTag("hy2", "invalid_query")
		return node, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "hy2" && scheme != "hysteria2" {
		return node, false
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if host == "" {
		recordParseFailureReasonTag(scheme, "missing_host")
		return node, false
	}
	if port == "" {
		recordParseFailureReasonTag(scheme, "missing_port")
		return node, false
	}
	if u.User == nil {
		recordParseFailureReasonTag(scheme, "invalid_userinfo")
		return node, false
	}
	password := strings.TrimSpace(u.User.Username())
	if password == "" {
		recordParseFailureReasonTag(scheme, "invalid_userinfo")
		return node, false
	}
	q := u.Query()
	node = hy2Node{
		Address:      host,
		Port:         port,
		Password:     password,
		SNI:          strings.TrimSpace(q.Get("sni")),
		ALPN:         strings.TrimSpace(q.Get("alpn")),
		Obfs:         strings.TrimSpace(q.Get("obfs")),
		ObfsPassword: strings.TrimSpace(q.Get("obfs-password")),
		RawQuery:     filterRawQueryWithWhitelist(u.RawQuery, scheme),
	}
	if node.SNI == "" {
		node.SNI = strings.TrimSpace(q.Get("peer"))
	}
	return node, true
}

func normalizeSSRURI(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(trimmed), "ssr://") {
		return "", false
	}

	encoded := strings.TrimSpace(strings.TrimPrefix(trimmed, "ssr://"))
	fragment := ""
	if idx := strings.Index(encoded, "#"); idx >= 0 {
		fragment = encoded[idx:]
		encoded = encoded[:idx]
	}
	if encoded == "" {
		return "", false
	}

	payload, err := decodeFlexibleBase64(encoded)
	if err != nil || len(payload) == 0 {
		return "", false
	}

	// SSR payload must remain fully reversible; only normalize base64 variant.
	canonical := encodeBase64URLNoPadding(payload)
	if canonical == "" {
		return "", false
	}
	return "ssr://" + canonical + fragment, true
}

func normalizeWireGuardURI(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	encoded := strings.TrimPrefix(strings.TrimPrefix(trimmed, "wg://"), "wireguard://")
	if idx := strings.Index(encoded, "#"); idx >= 0 {
		encoded = encoded[:idx]
	}
	if encoded == "" {
		return "", false
	}
	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		payload, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", false
		}
	}
	decoded := string(payload)
	if !strings.Contains(decoded, "PrivateKey") || !strings.Contains(decoded, "PublicKey") {
		return "", false
	}
	endpoint := ""
	privateKey := ""
	for _, line := range strings.Split(decoded, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Endpoint") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				endpoint = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "PrivateKey") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				privateKey = strings.TrimSpace(parts[1])
			}
		}
	}
	if endpoint == "" {
		return "", false
	}
	return fmt.Sprintf("wg://%s@%s", url.QueryEscape(privateKey), endpoint), true
}

func validateMainstreamURI(scheme string, u *url.URL) bool {
	query := u.Query()
	switch scheme {
	case "vless":
		if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
			return false
		}
		if strings.TrimSpace(query.Get("sni")) == "" || strings.TrimSpace(query.Get("alpn")) == "" {
			return false
		}
		return true
	case "trojan", "hy2", "hysteria2":
		if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
			return false
		}
		if strings.TrimSpace(query.Get("sni")) == "" || strings.TrimSpace(query.Get("alpn")) == "" {
			return false
		}
		return true
	case "hysteria":
		return strings.TrimSpace(query.Get("auth")) != ""
	case "tuic":
		if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
			return false
		}
		password, ok := u.User.Password()
		return ok && strings.TrimSpace(password) != ""
	default:
		return true
	}

	return true
}

func normalizeSSURI(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", false
	}
	pluginQuery := filterSSPluginQuery(u.RawQuery)
	fragment := strings.TrimSpace(u.Fragment)

	if u.Host != "" && (u.User != nil || strings.Contains(u.Host, ":")) {
		authority := u.Host
		if u.User != nil {
			authority = u.User.String() + "@" + authority
		}
		normalized := "ss://" + authority
		if pluginQuery != "" {
			normalized += "?" + pluginQuery
		}
		if fragment != "" {
			normalized += "#" + fragment
		}
		return normalized, true
	}

	payload := strings.TrimPrefix(trimmed, "ss://")
	if i := strings.IndexAny(payload, "?#"); i >= 0 {
		payload = payload[:i]
	}
	decoded, err := decodeFlexibleBase64(payload)
	if err != nil || len(decoded) == 0 {
		return "", false
	}

	decodedURL, err := url.Parse("ss://" + string(decoded))
	if err != nil || decodedURL.Host == "" {
		return "", false
	}
	authority := decodedURL.Host
	if decodedURL.User != nil {
		authority = decodedURL.User.String() + "@" + authority
	}
	normalized := "ss://" + authority
	if pluginQuery != "" {
		normalized += "?" + pluginQuery
	}
	if fragment != "" {
		normalized += "#" + fragment
	}
	return normalized, true
}

func decodeFlexibleBase64(v string) ([]byte, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return nil, fmt.Errorf("empty base64 payload")
	}
	decoders := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	}
	for _, decode := range decoders {
		payload, err := decode(trimmed)
		if err == nil {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

func encodeBase64URLNoPadding(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func extractMixedURICandidate(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false
	}
	matches := mixedURITokenRegex.FindStringSubmatch(trimmed)
	if len(matches) < 2 {
		return "", false
	}
	candidate := strings.Trim(matches[1], `"'()[]{}<>,;`)
	if candidate == "" {
		return "", false
	}
	return candidate, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
func parseBoolWithDefault(raw string, def bool) bool {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return v
}

func filterSSPluginQuery(rawQuery string) string {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	allowed := url.Values{}
	for _, key := range []string{"plugin", "plugin-opts"} {
		for _, v := range q[key] {
			if strings.TrimSpace(v) != "" {
				allowed.Add(key, v)
			}
		}
	}
	return allowed.Encode()
}

func resolveMixedDialTarget(scheme string, addr string) (dialScheme string, dialAddr string, useAuth bool) {
	return scheme, addr, true
}

type UpstreamDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type dialPhase struct {
	ProxyDial  time.Duration
	TCPConnect time.Duration
}

type dialPhaseContextKey struct{}

func withDialPhase(ctx context.Context) (context.Context, *dialPhase) {
	phase := &dialPhase{}
	return context.WithValue(ctx, dialPhaseContextKey{}, phase), phase
}

func setDialPhase(ctx context.Context, phase dialPhase) {
	v := ctx.Value(dialPhaseContextKey{})
	recorder, ok := v.(*dialPhase)
	if !ok || recorder == nil {
		return
	}
	*recorder = phase
}

type socksUpstreamDialer struct {
	proxyAddr string
	auth      *proxy.Auth
}

func (d *socksUpstreamDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()
	start := time.Now()
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timeout = remaining
	}

	forward := timeoutForwardDialer{timeout: timeout}
	dialer, err := proxy.SOCKS5("tcp", d.proxyAddr, d.auth, forward)
	if err != nil {
		return nil, err
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, dialErr := dialer.Dial(network, addr)
		resultCh <- dialResult{conn: conn, err: dialErr}
	}()

	select {
	case <-ctx.Done():
		adapterMetrics.AddDial("socks5", "error", "deadline_exceeded", time.Since(start))
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			adapterMetrics.AddDial("socks5", "error", "dial_failed", time.Since(start))
			return nil, result.err
		}
		dialCost := time.Since(start)
		setDialPhase(ctx, dialPhase{ProxyDial: dialCost, TCPConnect: dialCost})
		if deadline, ok := ctx.Deadline(); ok {
			_ = result.conn.SetDeadline(deadline)
		}
		adapterMetrics.AddDial("socks5", "success", "", dialCost)
		return result.conn, nil
	}
}

type httpConnectUpstreamDialer struct {
	proxyScheme     string
	proxyAddr       string
	proxyAuthHeader string
}

func (d *httpConnectUpstreamDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network %s for HTTP upstream", network)
	}
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()
	start := time.Now()
	conn, err := dialTargetThroughHTTPProxy(ctx, d.proxyScheme, d.proxyAddr, d.proxyAuthHeader, addr)
	if err != nil {
		adapterMetrics.AddDial(d.proxyScheme, "error", "connect_failed", time.Since(start))
		return nil, err
	}
	adapterMetrics.AddDial(d.proxyScheme, "success", "", time.Since(start))
	return conn, nil
}

var errMainstreamAdapterUnavailable = errors.New("mainstream upstream adapter unavailable")
var errMainstreamCoreUnavailable = errors.New("mainstream core unavailable")

type kernelNodeConfig struct {
	Core     string
	Protocol string
	Name     string
	Address  string
	Port     string

	SS struct {
		Cipher     string
		Password   string
		Plugin     string
		PluginOpts string
	}

	SSR struct {
		Cipher        string
		Password      string
		Protocol      string
		ProtocolParam string
		Obfs          string
		ObfsParam     string
	}

	Trojan struct {
		Password      string
		SNI           string
		ALPN          []string
		AllowInsecure bool
		Network       string
		Path          string
		Host          string
	}

	VMESS struct {
		UUID       string
		AlterID    int
		Security   string
		Network    string
		Host       string
		Path       string
		TLS        bool
		ServerName string
	}

	VLESS struct {
		UUID          string
		Flow          string
		Network       string
		Host          string
		Path          string
		Security      string
		ServerName    string
		AllowInsecure bool
	}

	HY2 struct {
		Password      string
		ServerName    string
		ALPN          string
		Obfs          string
		ObfsPassword  string
		AllowInsecure bool
	}
}

type mainstreamCoreInfo struct {
	Name        string
	Version     string
	Build       string
	ProtocolCap map[string]bool
}

type mainstreamCoreBackend interface {
	DialContext(ctx context.Context, node kernelNodeConfig, network, addr string) (net.Conn, error)
	Info() mainstreamCoreInfo
}

type mainstreamHealthAwareBackend interface {
	HealthCheck(ctx context.Context, node kernelNodeConfig) error
}

type tcpConnectCoreBackend struct {
	info mainstreamCoreInfo
}

func (b *tcpConnectCoreBackend) DialContext(ctx context.Context, _ kernelNodeConfig, network, addr string) (net.Conn, error) {
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (b *tcpConnectCoreBackend) Info() mainstreamCoreInfo {
	return b.info
}

type embeddedSSBackend struct {
	info mainstreamCoreInfo
}

func (b *embeddedSSBackend) HealthCheck(ctx context.Context, node kernelNodeConfig) error {
	if node.Protocol != "ss" {
		return fmt.Errorf("embedded ss backend unsupported protocol=%s", node.Protocol)
	}
	if strings.TrimSpace(node.SS.Cipher) == "" || strings.TrimSpace(node.SS.Password) == "" {
		return fmt.Errorf("embedded ss backend missing cipher/password")
	}
	return nil
}

func (b *embeddedSSBackend) DialContext(ctx context.Context, node kernelNodeConfig, network, addr string) (net.Conn, error) {
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()
	if network != "tcp" {
		return nil, fmt.Errorf("embedded ss backend unsupported network=%s", network)
	}
	if err := b.HealthCheck(ctx, node); err != nil {
		return nil, err
	}

	proxyConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(node.Address, node.Port))
	if err != nil {
		return nil, err
	}

	h := fnv.New64a()
	_, _ = h.Write([]byte(node.SS.Cipher + ":" + node.SS.Password))
	handshake := fmt.Sprintf("EMBEDDED-SS/1 cipher=%s auth=%x target=%s\n", node.SS.Cipher, h.Sum64(), addr)
	if _, err := io.WriteString(proxyConn, handshake); err != nil {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("embedded ss handshake failed: %w", err)
	}

	return proxyConn, nil
}

func (b *embeddedSSBackend) Info() mainstreamCoreInfo {
	return b.info
}

func performNativeProtocolHealthCheck(ctx context.Context, node kernelNodeConfig) error {
	address := net.JoinHostPort(node.Address, node.Port)
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("native dial failed: %w", err)
	}
	defer conn.Close()

	switch node.Protocol {
	case "ss":
		if strings.TrimSpace(node.SS.Cipher) == "" || strings.TrimSpace(node.SS.Password) == "" {
			return fmt.Errorf("ss cipher/password missing")
		}
		return nil
	case "vmess":
		if !node.VMESS.TLS {
			return nil
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: firstNonEmpty(node.VMESS.ServerName, node.Address), InsecureSkipVerify: true})
		defer tlsConn.Close()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("vmess tls handshake failed: %w", err)
		}
		return nil
	case "vless":
		if strings.EqualFold(node.VLESS.Security, "tls") || strings.EqualFold(node.VLESS.Security, "reality") {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: firstNonEmpty(node.VLESS.ServerName, node.Address), InsecureSkipVerify: node.VLESS.AllowInsecure})
			defer tlsConn.Close()
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return fmt.Errorf("vless tls handshake failed: %w", err)
			}
		}
		return nil
	case "hy2", "hysteria2":
		tlsConn := tls.Client(conn, &tls.Config{ServerName: firstNonEmpty(node.HY2.ServerName, node.Address), InsecureSkipVerify: node.HY2.AllowInsecure, NextProtos: nonEmptyALPN(node.HY2.ALPN)})
		defer tlsConn.Close()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("hy2 tls handshake failed: %w", err)
		}
		return nil
	default:
		return nil
	}
}

func nonEmptyALPN(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type externalKernelNodeConfig struct {
	Protocol string
	Name     string
	Server   string
	Port     string

	Shadowsocks struct {
		Cipher   string
		Password string
	}

	ShadowsocksR struct {
		Cipher        string
		Password      string
		Protocol      string
		ProtocolParam string
		Obfs          string
		ObfsParam     string
	}

	Trojan struct {
		Password      string
		SNI           string
		ALPN          []string
		AllowInsecure bool
		Network       string
		Path          string
		Host          string
	}
}

func mapKernelNodeToExternal(node kernelNodeConfig) externalKernelNodeConfig {
	out := externalKernelNodeConfig{Protocol: node.Protocol, Name: node.Name, Server: node.Address, Port: node.Port}
	out.Shadowsocks.Cipher = node.SS.Cipher
	out.Shadowsocks.Password = node.SS.Password
	out.ShadowsocksR.Cipher = node.SSR.Cipher
	out.ShadowsocksR.Password = node.SSR.Password
	out.ShadowsocksR.Protocol = node.SSR.Protocol
	out.ShadowsocksR.ProtocolParam = node.SSR.ProtocolParam
	out.ShadowsocksR.Obfs = node.SSR.Obfs
	out.ShadowsocksR.ObfsParam = node.SSR.ObfsParam
	out.Trojan.Password = node.Trojan.Password
	out.Trojan.SNI = node.Trojan.SNI
	out.Trojan.ALPN = append([]string(nil), node.Trojan.ALPN...)
	out.Trojan.AllowInsecure = node.Trojan.AllowInsecure
	out.Trojan.Network = node.Trojan.Network
	out.Trojan.Path = node.Trojan.Path
	out.Trojan.Host = node.Trojan.Host
	return out
}

type externalKernelBackend struct {
	info                 mainstreamCoreInfo
	sidecarAddr          string
	healthCheckCmd       string
	protocolHealthChecks map[string]string
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (b *externalKernelBackend) protocolHealthCommand(protocol string) string {
	if b.protocolHealthChecks == nil {
		return ""
	}
	return strings.TrimSpace(b.protocolHealthChecks[strings.ToLower(strings.TrimSpace(protocol))])
}

func runKernelHealthCommand(ctx context.Context, cmd string) error {
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	out, err := exec.CommandContext(ctx, "bash", "-lc", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("health check command failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (b *externalKernelBackend) HealthCheck(ctx context.Context, node kernelNodeConfig) error {
	if strings.TrimSpace(b.sidecarAddr) == "" {
		return fmt.Errorf("%w: code=core_unavailable sidecar_addr_missing core=%s", errMainstreamCoreUnavailable, b.info.Name)
	}

	if cmd := b.protocolHealthCommand(node.Protocol); cmd != "" {
		if err := runKernelHealthCommand(ctx, cmd); err != nil {
			return fmt.Errorf("%w: code=core_unavailable protocol=%s %v", errMainstreamCoreUnavailable, node.Protocol, err)
		}
		return nil
	}
	if strings.TrimSpace(b.healthCheckCmd) != "" {
		if err := runKernelHealthCommand(ctx, b.healthCheckCmd); err != nil {
			return fmt.Errorf("%w: code=core_unavailable %v", errMainstreamCoreUnavailable, err)
		}
		return nil
	}

	probeConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", b.sidecarAddr)
	if err != nil {
		return fmt.Errorf("%w: code=core_unavailable sidecar_probe_failed=%v", errMainstreamCoreUnavailable, err)
	}
	_ = probeConn.Close()
	return nil
}

func (b *externalKernelBackend) DialContext(ctx context.Context, node kernelNodeConfig, network, addr string) (net.Conn, error) {
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()
	if network != "tcp" {
		return nil, fmt.Errorf("external kernel backend unsupported network=%s", network)
	}
	if err := b.HealthCheck(ctx, node); err != nil {
		return nil, err
	}

	_ = mapKernelNodeToExternal(node)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", b.sidecarAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: code=core_unavailable sidecar_dial_failed=%v", errMainstreamCoreUnavailable, err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", addr, addr)
	if _, err := io.WriteString(conn, connectReq); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("external kernel CONNECT write failed: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("external kernel CONNECT response invalid: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("external kernel CONNECT failed status=%s", resp.Status)
	}
	_ = resp.Body.Close()
	return &bufferedConn{Conn: conn, r: br}, nil
}

func (b *externalKernelBackend) Info() mainstreamCoreInfo {
	return b.info
}

func defaultCoreProtocolMatrix() map[string]bool {
	return map[string]bool{
		"vmess":      true,
		"vless":      true,
		"hy2":        true,
		"hysteria":   true,
		"hysteria2":  true,
		"trojan":     true,
		"ss":         true,
		"ss2022":     true,
		"ssr":        true,
		"trojan-go":  true,
		"ssr-plugin": true,
		"tuic":       true,
		"wireguard":  true,
	}
}

func resolveMainstreamCoreBackend(core string) (mainstreamCoreBackend, bool) {
	core = strings.ToLower(strings.TrimSpace(core))
	if core == "" {
		return nil, false
	}

	matrix := defaultCoreProtocolMatrix()
	switch core {
	case "mihomo":
		return &externalKernelBackend{info: mainstreamCoreInfo{Name: "mihomo", Version: "builtin", Build: "dynamic-proxy", ProtocolCap: matrix}, sidecarAddr: strings.TrimSpace(os.Getenv("DP_MIHOMO_SIDECAR_ADDR")), healthCheckCmd: strings.TrimSpace(os.Getenv("DP_MIHOMO_HEALTHCHECK_CMD")), protocolHealthChecks: map[string]string{"ss": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_SS_CMD")), "ssr": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_SSR_CMD")), "trojan": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_TROJAN_CMD"))}}, true
	case "meta":
		return &externalKernelBackend{info: mainstreamCoreInfo{Name: "meta", Version: "builtin", Build: "dynamic-proxy", ProtocolCap: matrix}, sidecarAddr: strings.TrimSpace(os.Getenv("DP_META_SIDECAR_ADDR")), healthCheckCmd: strings.TrimSpace(os.Getenv("DP_META_HEALTHCHECK_CMD")), protocolHealthChecks: map[string]string{"ss": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_SS_CMD")), "ssr": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_SSR_CMD")), "trojan": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_TROJAN_CMD"))}}, true
	case "singbox", "sing-box":
		return &externalKernelBackend{info: mainstreamCoreInfo{Name: "singbox", Version: "builtin", Build: "dynamic-proxy", ProtocolCap: matrix}, sidecarAddr: strings.TrimSpace(os.Getenv("DP_SINGBOX_SIDECAR_ADDR")), healthCheckCmd: strings.TrimSpace(os.Getenv("DP_SINGBOX_HEALTHCHECK_CMD")), protocolHealthChecks: map[string]string{"ss": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_SS_CMD")), "ssr": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_SSR_CMD")), "trojan": strings.TrimSpace(os.Getenv("DP_HEALTHCHECK_TROJAN_CMD"))}}, true
	case "embedded-ss", "embedded_ss":
		return &embeddedSSBackend{info: mainstreamCoreInfo{Name: "embedded-ss", Version: "builtin", Build: "dynamic-proxy", ProtocolCap: matrix}}, true
	default:
		return &tcpConnectCoreBackend{info: mainstreamCoreInfo{Name: core, Version: "unknown", Build: "dynamic-proxy", ProtocolCap: matrix}}, true
	}
}

func resolveCoreSidecarEnvNames(core string) (sidecarEnv string, healthcheckEnv string) {
	core = strings.ToLower(strings.TrimSpace(core))
	switch core {
	case "mihomo":
		return "DP_MIHOMO_SIDECAR_ADDR", "DP_MIHOMO_HEALTHCHECK_CMD"
	case "meta":
		return "DP_META_SIDECAR_ADDR", "DP_META_HEALTHCHECK_CMD"
	case "singbox", "sing-box":
		return "DP_SINGBOX_SIDECAR_ADDR", "DP_SINGBOX_HEALTHCHECK_CMD"
	default:
		return "", ""
	}
}

func logCoreCapabilitySelfCheckSummary(core string) {
	core = strings.ToLower(strings.TrimSpace(core))
	if core == "" {
		log.Printf("[CORE-SELF-CHECK] core_type=unset risk=core_unconfigured detector.core is empty")
		return
	}

	sidecarEnv, healthcheckEnv := resolveCoreSidecarEnvNames(core)
	sidecarAddr := ""
	coreHealthcheck := ""
	if sidecarEnv != "" {
		sidecarAddr = strings.TrimSpace(os.Getenv(sidecarEnv))
	}
	if healthcheckEnv != "" {
		coreHealthcheck = strings.TrimSpace(os.Getenv(healthcheckEnv))
	}

	protocolEnvNames := map[string]string{
		"ss":     "DP_HEALTHCHECK_SS_CMD",
		"ssr":    "DP_HEALTHCHECK_SSR_CMD",
		"trojan": "DP_HEALTHCHECK_TROJAN_CMD",
	}
	protocols := []string{"ss", "ssr", "trojan"}
	checks := make([]string, 0, len(protocols))
	missing := make([]string, 0)
	for _, protocol := range protocols {
		envName := protocolEnvNames[protocol]
		configured := strings.TrimSpace(os.Getenv(envName)) != ""
		checks = append(checks, fmt.Sprintf("%s:%t", protocol, configured))
		if !configured {
			missing = append(missing, envName)
		}
	}

	risk := "ok"
	riskReasons := make([]string, 0)
	if sidecarEnv != "" && sidecarAddr == "" {
		risk = "core_unconfigured"
		riskReasons = append(riskReasons, fmt.Sprintf("%s missing", sidecarEnv))
	}
	if len(missing) > 0 {
		riskReasons = append(riskReasons, "protocol healthcheck commands missing: "+strings.Join(missing, ","))
	}

	if sidecarAddr == "" {
		sidecarAddr = "<empty>"
	}
	log.Printf("[CORE-SELF-CHECK] core_type=%s sidecar_addr=%s sidecar_env=%s core_healthcheck_cmd=%t protocol_healthchecks={%s} risk=%s",
		core,
		sidecarAddr,
		sidecarEnv,
		coreHealthcheck != "",
		strings.Join(checks, " "),
		risk,
	)
	if len(riskReasons) > 0 {
		log.Printf("[CORE-SELF-CHECK] detail=%s", strings.Join(riskReasons, "; "))
	}
}

func parseKernelNodeConfig(proxyScheme, proxyEntry, proxyAddr string) (kernelNodeConfig, error) {
	node := kernelNodeConfig{Protocol: strings.ToLower(strings.TrimSpace(proxyScheme)), Name: proxyEntry}
	host, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return kernelNodeConfig{}, fmt.Errorf("invalid upstream host:port %s: %w", proxyAddr, err)
	}
	node.Address = host
	node.Port = port

	switch node.Protocol {
	case "ss":
		u, err := url.Parse(proxyEntry)
		if err != nil {
			return kernelNodeConfig{}, fmt.Errorf("invalid ss entry: %w", err)
		}
		username := ""
		password := ""
		if u.User != nil {
			username = u.User.Username()
			password, _ = u.User.Password()
		}
		if username != "" && password == "" {
			if decoded, decErr := decodeFlexibleBase64(username); decErr == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					username = parts[0]
					password = parts[1]
				}
			}
		}
		node.SS.Cipher = username
		node.SS.Password = password
		q := u.Query()
		node.SS.Plugin = strings.TrimSpace(q.Get("plugin"))
		node.SS.PluginOpts = strings.TrimSpace(q.Get("plugin-opts"))
		if node.SS.Cipher == "" || node.SS.Password == "" {
			return kernelNodeConfig{}, fmt.Errorf("invalid ss entry missing cipher/password")
		}
	case "ssr":
		n, ok := parseSSRNodeForKernel(proxyEntry)
		if !ok {
			return kernelNodeConfig{}, fmt.Errorf("invalid ssr entry")
		}
		node.Address = n.Server
		node.Port = n.Port
		node.SSR.Cipher = n.Method
		node.SSR.Password = n.Password
		node.SSR.Protocol = n.Protocol
		node.SSR.ProtocolParam = n.ProtocolParam
		node.SSR.Obfs = n.Obfs
		node.SSR.ObfsParam = n.ObfsParam
	case "trojan":
		n, ok := parseTrojanNodeForKernel(proxyEntry)
		if !ok {
			return kernelNodeConfig{}, fmt.Errorf("invalid trojan entry")
		}
		node.Address = n.Address
		node.Port = n.Port
		node.Trojan.Password = n.Password
		node.Trojan.SNI = n.SNI
		node.Trojan.ALPN = append([]string(nil), n.ALPN...)
		node.Trojan.AllowInsecure = n.Insecure
		node.Trojan.Network = n.Network
		node.Trojan.Path = n.Path
		node.Trojan.Host = n.Host
	case "vmess":
		n, ok := parseVMESSNode(proxyEntry)
		if !ok {
			return kernelNodeConfig{}, fmt.Errorf("invalid vmess entry")
		}
		node.Address = n.Add
		node.Port = n.Port
		node.VMESS.UUID = strings.TrimSpace(n.ID)
		if aid, err := strconv.Atoi(strings.TrimSpace(n.Aid)); err == nil {
			node.VMESS.AlterID = aid
		}
		node.VMESS.Security = firstNonEmpty(strings.TrimSpace(n.Type), "auto")
		node.VMESS.Network = firstNonEmpty(strings.TrimSpace(n.Net), "tcp")
		node.VMESS.Host = strings.TrimSpace(n.Host)
		node.VMESS.Path = strings.TrimSpace(n.Path)
		node.VMESS.ServerName = firstNonEmpty(strings.TrimSpace(n.SNI), strings.TrimSpace(n.Host), strings.TrimSpace(n.Add))
		node.VMESS.TLS = strings.EqualFold(strings.TrimSpace(n.TLS), "tls")
	case "vless":
		n, ok := parseVLESSNode(proxyEntry)
		if !ok {
			return kernelNodeConfig{}, fmt.Errorf("invalid vless entry")
		}
		node.Address = n.Address
		node.Port = n.Port
		node.VLESS.UUID = n.UUID
		node.VLESS.Flow = n.Flow
		node.VLESS.Network = firstNonEmpty(n.Transport, "tcp")
		node.VLESS.Host = n.Host
		node.VLESS.Path = n.Path
		node.VLESS.Security = n.Security
		node.VLESS.ServerName = firstNonEmpty(n.SNI, n.Host, n.Address)
		node.VLESS.AllowInsecure = strings.Contains(strings.ToLower(n.RawQuery), "insecure=1") || strings.Contains(strings.ToLower(n.RawQuery), "allowinsecure=1")
	case "hy2", "hysteria2":
		n, ok := parseHY2Node(proxyEntry)
		if !ok {
			return kernelNodeConfig{}, fmt.Errorf("invalid hy2 entry")
		}
		node.Address = n.Address
		node.Port = n.Port
		node.HY2.Password = n.Password
		node.HY2.ServerName = firstNonEmpty(n.SNI, n.Address)
		node.HY2.ALPN = n.ALPN
		node.HY2.Obfs = n.Obfs
		node.HY2.ObfsPassword = n.ObfsPassword
		node.HY2.AllowInsecure = strings.Contains(strings.ToLower(n.RawQuery), "insecure=1") || strings.Contains(strings.ToLower(n.RawQuery), "allowinsecure=1")
	}

	if err := validateKernelNodeConfig(node); err != nil {
		return kernelNodeConfig{}, err
	}

	return node, nil
}

func validateKernelNodeConfig(node kernelNodeConfig) error {
	if strings.TrimSpace(node.Protocol) == "" {
		return fmt.Errorf("invalid kernel node: missing protocol")
	}
	if strings.TrimSpace(node.Address) == "" {
		return fmt.Errorf("invalid kernel node: missing address")
	}
	port, err := strconv.Atoi(strings.TrimSpace(node.Port))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid kernel node: port out of range")
	}
	switch node.Protocol {
	case "ss":
		if strings.TrimSpace(node.SS.Cipher) == "" || strings.TrimSpace(node.SS.Password) == "" {
			return fmt.Errorf("invalid ss entry missing cipher/password")
		}
	case "ssr":
		if strings.TrimSpace(node.SSR.Cipher) == "" || strings.TrimSpace(node.SSR.Password) == "" || strings.TrimSpace(node.SSR.Protocol) == "" || strings.TrimSpace(node.SSR.Obfs) == "" {
			return fmt.Errorf("invalid ssr entry missing required fields")
		}
	case "trojan":
		if strings.TrimSpace(node.Trojan.Password) == "" {
			return fmt.Errorf("invalid trojan entry missing password")
		}
		for _, alpn := range node.Trojan.ALPN {
			if strings.TrimSpace(alpn) == "" || strings.ContainsAny(alpn, " \t\n") {
				return fmt.Errorf("invalid trojan alpn value")
			}
		}
		network := strings.ToLower(strings.TrimSpace(node.Trojan.Network))
		if network != "" && network != "ws" && network != "tcp" {
			return fmt.Errorf("invalid trojan network type: %s", network)
		}
		if network == "ws" {
			if strings.TrimSpace(node.Trojan.Path) == "" || !strings.HasPrefix(node.Trojan.Path, "/") {
				return fmt.Errorf("invalid trojan ws path")
			}
		}
	case "vmess":
		if strings.TrimSpace(node.VMESS.UUID) == "" {
			return fmt.Errorf("invalid vmess entry missing id")
		}
	case "vless":
		if strings.TrimSpace(node.VLESS.UUID) == "" {
			return fmt.Errorf("invalid vless entry missing uuid")
		}
	case "hy2", "hysteria2":
		if strings.TrimSpace(node.HY2.Password) == "" {
			return fmt.Errorf("invalid hy2 entry missing password")
		}
	}
	return nil
}

type ssrKernelNode struct {
	Server        string
	Port          string
	Protocol      string
	Method        string
	Obfs          string
	Password      string
	ProtocolParam string
	ObfsParam     string
}

func parseSSRNodeForKernel(raw string) (ssrKernelNode, bool) {
	node := ssrKernelNode{}
	trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "ssr://"))
	if trimmed == "" {
		return node, false
	}
	if idx := strings.Index(trimmed, "#"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	payload, err := decodeFlexibleBase64(trimmed)
	if err != nil {
		return node, false
	}
	decoded := string(payload)
	parts := strings.SplitN(decoded, "/?", 2)
	head := strings.Split(parts[0], ":")
	if len(head) < 6 {
		return node, false
	}
	pwdBytes, err := decodeFlexibleBase64(head[5])
	if err != nil {
		return node, false
	}
	node = ssrKernelNode{Server: head[0], Port: head[1], Protocol: head[2], Method: head[3], Obfs: head[4], Password: string(pwdBytes)}
	if len(parts) == 2 {
		q, _ := url.ParseQuery(parts[1])
		if v := strings.TrimSpace(q.Get("protoparam")); v != "" {
			if b, e := decodeFlexibleBase64(v); e == nil {
				node.ProtocolParam = string(b)
			}
		}
		if v := strings.TrimSpace(q.Get("obfsparam")); v != "" {
			if b, e := decodeFlexibleBase64(v); e == nil {
				node.ObfsParam = string(b)
			}
		}
	}
	return node, true
}

type trojanKernelNode struct {
	Address  string
	Port     string
	Password string
	SNI      string
	ALPN     []string
	Insecure bool
	Network  string
	Path     string
	Host     string
}

func parseTrojanNodeForKernel(raw string) (trojanKernelNode, bool) {
	node := trojanKernelNode{}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || strings.ToLower(u.Scheme) != "trojan" || u.User == nil {
		return node, false
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	password := strings.TrimSpace(u.User.Username())
	if host == "" || port == "" || password == "" {
		return node, false
	}
	q := u.Query()
	node = trojanKernelNode{
		Address:  host,
		Port:     port,
		Password: password,
		SNI:      strings.TrimSpace(q.Get("sni")),
		Insecure: parseBoolWithDefault(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure")), false),
		Network:  strings.TrimSpace(q.Get("type")),
		Path:     strings.TrimSpace(q.Get("path")),
		Host:     strings.TrimSpace(q.Get("host")),
	}
	alpn := strings.TrimSpace(q.Get("alpn"))
	if alpn != "" {
		for _, item := range strings.Split(alpn, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				node.ALPN = append(node.ALPN, item)
			}
		}
	}
	return node, true
}

func protocolCapString(capMap map[string]bool) string {
	if len(capMap) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(capMap))
	for k, enabled := range capMap {
		if enabled {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "none"
	}
	return strings.Join(keys, ",")
}

type mainstreamDialAdapter interface {
	DialContext(ctx context.Context, proxyScheme, proxyEntry, proxyAddr, network, addr string) (net.Conn, error)
}

type mainstreamUpstreamDialer struct {
	proxyScheme string
	proxyEntry  string
	proxyAddr   string
	adapter     mainstreamDialAdapter
}

func (d *mainstreamUpstreamDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()
	start := time.Now()
	if d.adapter == nil {
		adapterMetrics.AddDial(d.proxyScheme, "error", "adapter_unavailable", time.Since(start))
		return nil, fmt.Errorf("%w: %s", errMainstreamAdapterUnavailable, d.proxyScheme)
	}
	if checker, ok := d.adapter.(interface {
		CheckAvailability(ctx context.Context, proxyScheme, proxyEntry, proxyAddr string) error
	}); ok {
		if err := checker.CheckAvailability(ctx, d.proxyScheme, d.proxyEntry, d.proxyAddr); err != nil {
			adapterMetrics.AddDial(d.proxyScheme, "error", "core_unavailable", time.Since(start))
			return nil, err
		}
	}
	conn, err := d.adapter.DialContext(ctx, d.proxyScheme, d.proxyEntry, d.proxyAddr, network, addr)
	if err != nil {
		adapterMetrics.AddDial(d.proxyScheme, "error", "dial_failed", time.Since(start))
		return nil, err
	}
	adapterMetrics.AddDial(d.proxyScheme, "success", "", time.Since(start))
	return conn, nil
}

type mainstreamTCPConnectAdapter struct{}

func (a *mainstreamTCPConnectAdapter) CheckAvailability(ctx context.Context, proxyScheme, proxyEntry, proxyAddr string) error {
	proxyScheme = strings.ToLower(strings.TrimSpace(proxyScheme))
	if proxyScheme == "ssr" || proxyScheme == "trojan" {
		cmdEnv := map[string]string{"ssr": "DP_HEALTHCHECK_SSR_CMD", "trojan": "DP_HEALTHCHECK_TROJAN_CMD"}
		cmd := strings.TrimSpace(os.Getenv(cmdEnv[proxyScheme]))
		if cmd == "" {
			return fmt.Errorf("%w: %s health check command not configured", errMainstreamCoreUnavailable, proxyScheme)
		}
		return runKernelHealthCommand(ctx, cmd)
	}

	backend, ok := resolveMainstreamCoreBackend(config.Detector.Core)
	if !ok {
		if proxyScheme == "vmess" || proxyScheme == "vless" || proxyScheme == "hy2" || proxyScheme == "hysteria2" || proxyScheme == "ss" {
			node, err := parseKernelNodeConfig(proxyScheme, proxyEntry, proxyAddr)
			if err != nil {
				return err
			}
			return performNativeProtocolHealthCheck(ctx, node)
		}
		return fmt.Errorf("%w: detector.core is empty", errMainstreamAdapterUnavailable)
	}
	node, err := parseKernelNodeConfig(proxyScheme, proxyEntry, proxyAddr)
	if err != nil {
		return err
	}
	if proxyScheme == "vmess" || proxyScheme == "vless" || proxyScheme == "hy2" || proxyScheme == "hysteria2" || (proxyScheme == "ss" && strings.EqualFold(backend.Info().Name, "embedded-ss")) {
		return performNativeProtocolHealthCheck(ctx, node)
	}
	node.Core = backend.Info().Name
	if healthAware, ok := backend.(mainstreamHealthAwareBackend); ok {
		if err := healthAware.HealthCheck(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

func (a *mainstreamTCPConnectAdapter) DialContext(ctx context.Context, proxyScheme, proxyEntry, proxyAddr, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network %s for mainstream upstream", network)
	}

	backend, ok := resolveMainstreamCoreBackend(config.Detector.Core)
	if !ok {
		return nil, fmt.Errorf("%w: detector.core is empty", errMainstreamAdapterUnavailable)
	}

	node, err := parseKernelNodeConfig(proxyScheme, proxyEntry, proxyAddr)
	if err != nil {
		return nil, err
	}
	node.Core = backend.Info().Name
	return backend.DialContext(ctx, node, network, addr)
}

func newMainstreamUpstreamDialer(proxyScheme, proxyEntry, proxyAddr string) UpstreamDialer {
	return &mainstreamUpstreamDialer{
		proxyScheme: proxyScheme,
		proxyEntry:  proxyEntry,
		proxyAddr:   proxyAddr,
		adapter:     mainstreamAdapterFactory(),
	}
}

func buildUpstreamDialer(entry string) (UpstreamDialer, string, error) {
	scheme, addr, auth, httpAuthHeader, err := parseMixedProxy(entry)
	if err != nil {
		return nil, "", err
	}

	dialScheme, dialAddr, useAuth := resolveMixedDialTarget(scheme, addr)
	if !useAuth {
		auth = nil
		httpAuthHeader = ""
	}

	switch dialScheme {
	case "socks5", "socks5h":
		return &socksUpstreamDialer{proxyAddr: dialAddr, auth: auth}, scheme, nil
	case "http", "https":
		return &httpConnectUpstreamDialer{proxyScheme: dialScheme, proxyAddr: dialAddr, proxyAuthHeader: httpAuthHeader}, scheme, nil
	case "vmess", "vless", "hy2", "hysteria", "hysteria2", "trojan", "ss", "ssr", "tuic", "wg", "wireguard":
		return newMainstreamUpstreamDialer(scheme, entry, dialAddr), scheme, nil
	default:
		return nil, scheme, fmt.Errorf("unknown upstream proxy scheme: %s", scheme)
	}
}

func parseSpecialProxyURLMixed(content string) []string {
	content = preprocessSubscriptionContent(content)
	proxies := make([]string, 0)
	proxySet := make(map[string]bool)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if normalized, ok := normalizeMixedProxyEntry(line); ok {
			if !proxySet[normalized] {
				proxySet[normalized] = true
				proxies = append(proxies, normalized)
			}
			continue
		}
		sampleParseFailureLine("parse_failed", line, "normalize_failed")

		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "ss://") || strings.Contains(lowerLine, "ssr://") || strings.Contains(lowerLine, "trojan://") {
			log.Printf("parse_failed: skip malformed mainstream line without fallback: %s", line)
			sampleParseFailureLine("parse_failed", line, "malformed_mainstream")
			continue
		}

		matches := simpleProxyRegex.FindStringSubmatch(line)
		if len(matches) < 3 {
			sampleParseFailureLine("unknown", line, "unsupported_format")
			continue
		}

		scheme := "socks5"
		switch {
		case strings.Contains(lowerLine, "https://"):
			scheme = "https"
		case strings.Contains(lowerLine, "http://"):
			scheme = "http"
		case strings.Contains(lowerLine, "socks5h://"):
			scheme = "socks5h"
		case strings.Contains(lowerLine, "socks5://"):
			scheme = "socks5"
		}

		entry := fmt.Sprintf("%s://%s:%s", scheme, matches[1], matches[2])
		if !proxySet[entry] {
			proxySet[entry] = true
			proxies = append(proxies, entry)
		}
	}

	return proxies
}

func fetchProxyList() ([]string, error) {
	log.Println("fetchProxyList: strict/relaxed SOCKS pool only (socks5/socks5h)")
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Disable certificate verification
			},
		},
	}

	allProxies := make([]string, 0)
	proxySet := make(map[string]bool) // 用于去重

	// 处理普通代理URL（简单格式）
	for _, url := range config.ProxyListURLs {
		log.Printf("Fetching proxy list from regular URL: %s", url)

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("Warning: Failed to fetch from %s: %v", url, err)
			continue // 继续尝试其他URL
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from %s", resp.StatusCode, url)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from %s: %v", url, err)
			continue
		}

		content := string(body)
		parsedProxies, format := parseRegularProxyContent(content)
		logSchemeDistribution(fmt.Sprintf("regular URL %s", url), parsedProxies, "socks5")
		count := 0
		skippedNonSocks := 0
		for _, parsed := range parsedProxies {
			normalized, ok := normalizeSocksPoolEntry(parsed)
			if !ok {
				skippedNonSocks++
				continue
			}
			if !proxySet[normalized] {
				proxySet[normalized] = true
				allProxies = append(allProxies, normalized)
				count++
			}
		}

		log.Printf("Fetched %d proxies from regular URL %s (format=%s, skipped_non_socks=%d)", count, url, format, skippedNonSocks)
	}

	// 处理特殊代理URL（复杂格式）
	for _, url := range config.SpecialProxyListUrls {
		log.Printf("Fetching proxy list from special URL: %s", url)

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("Warning: Failed to fetch from special URL %s: %v", url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from special URL %s", resp.StatusCode, url)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from special URL %s: %v", url, err)
			continue
		}

		content := string(body)
		// 使用特殊解析函数处理复杂格式
		specialProxies, err := parseSpecialProxyURL(content)
		if err != nil {
			log.Printf("Warning: Error parsing special proxies from %s: %v", url, err)
			continue
		}
		logSchemeDistribution(fmt.Sprintf("special URL %s", url), specialProxies, "socks5")

		count := 0
		for _, proxy := range specialProxies {
			if !proxySet[proxy] {
				proxySet[proxy] = true
				allProxies = append(allProxies, proxy)
				count++
			}
		}

		log.Printf("Fetched %d proxies from special URL %s", count, url)
	}

	if len(allProxies) == 0 {
		return nil, fmt.Errorf("no proxies fetched from any source")
	}

	log.Printf("Total unique proxies fetched: %d", len(allProxies))
	return allProxies, nil
}

func fetchMixedProxyList() ([]string, error) {
	log.Println("fetchMixedProxyList: mixed multi-scheme pool (http/https/socks and mainstream schemes)")
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	allProxies := make([]string, 0)
	proxySet := make(map[string]bool)

	for _, sourceURL := range config.ProxyListURLs {
		log.Printf("Fetching mixed proxy list from regular URL: %s", sourceURL)
		resp, err := client.Get(sourceURL)
		if err != nil {
			log.Printf("Warning: Failed to fetch from %s: %v", sourceURL, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from %s", resp.StatusCode, sourceURL)
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from %s: %v", sourceURL, err)
			continue
		}

		parsedProxies, format := parseRegularProxyContentMixed(string(body))
		logSchemeDistribution(fmt.Sprintf("mixed regular URL %s", sourceURL), parsedProxies, "socks5")
		count := 0
		for _, parsed := range parsedProxies {
			if !proxySet[parsed] {
				proxySet[parsed] = true
				allProxies = append(allProxies, parsed)
				count++
			}
		}
		log.Printf("Fetched %d mixed proxies from regular URL %s (format=%s)", count, sourceURL, format)
	}

	for _, sourceURL := range config.SpecialProxyListUrls {
		log.Printf("Fetching mixed proxy list from special URL: %s", sourceURL)
		resp, err := client.Get(sourceURL)
		if err != nil {
			log.Printf("Warning: Failed to fetch from special URL %s: %v", sourceURL, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from special URL %s", resp.StatusCode, sourceURL)
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from special URL %s: %v", sourceURL, err)
			continue
		}

		specialProxies := parseSpecialProxyURLMixed(string(body))
		logSchemeDistribution(fmt.Sprintf("mixed special URL %s", sourceURL), specialProxies, "socks5")
		count := 0
		for _, parsed := range specialProxies {
			if !proxySet[parsed] {
				proxySet[parsed] = true
				allProxies = append(allProxies, parsed)
				count++
			}
		}
		log.Printf("Fetched %d mixed proxies from special URL %s", count, sourceURL)
	}

	if len(allProxies) == 0 {
		return nil, fmt.Errorf("no mixed proxies fetched from any source")
	}

	log.Printf("Total unique mixed proxies fetched: %d", len(allProxies))
	return allProxies, nil
}

func fetchAndProcessSocksProxyBatches(batchSize int, onBatch func([]string)) error {
	if batchSize <= 0 {
		batchSize = healthCheckBatchSize
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	seen := make(map[string]bool)
	batch := make([]string, 0, batchSize)
	totalUnique := 0

	flush := func() {
		if len(batch) == 0 {
			return
		}
		onBatch(batch)
		batch = make([]string, 0, batchSize)
	}

	handleProxy := func(proxy string) {
		if proxy == "" || seen[proxy] {
			return
		}
		seen[proxy] = true
		totalUnique++
		batch = append(batch, proxy)
		if len(batch) >= batchSize {
			flush()
		}
	}

	for _, sourceURL := range config.ProxyListURLs {
		log.Printf("Fetching proxy list from regular URL: %s", sourceURL)
		resp, err := client.Get(sourceURL)
		if err != nil {
			log.Printf("Warning: Failed to fetch from %s: %v", sourceURL, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from %s", resp.StatusCode, sourceURL)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from %s: %v", sourceURL, err)
			continue
		}

		parsedProxies, format := parseRegularProxyContent(string(body))
		logSchemeDistribution(fmt.Sprintf("regular URL %s", sourceURL), parsedProxies, "socks5")
		added := 0
		skippedNonSocks := 0
		for _, parsed := range parsedProxies {
			normalized, ok := normalizeSocksPoolEntry(parsed)
			if !ok {
				skippedNonSocks++
				continue
			}
			before := totalUnique
			handleProxy(normalized)
			if totalUnique > before {
				added++
			}
		}
		log.Printf("Fetched %d proxies from regular URL %s (format=%s, skipped_non_socks=%d)", added, sourceURL, format, skippedNonSocks)
	}

	for _, sourceURL := range config.SpecialProxyListUrls {
		log.Printf("Fetching proxy list from special URL: %s", sourceURL)
		resp, err := client.Get(sourceURL)
		if err != nil {
			log.Printf("Warning: Failed to fetch from special URL %s: %v", sourceURL, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from special URL %s", resp.StatusCode, sourceURL)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from special URL %s: %v", sourceURL, err)
			continue
		}

		specialProxies, err := parseSpecialProxyURL(string(body))
		if err != nil {
			log.Printf("Warning: Error parsing special proxies from %s: %v", sourceURL, err)
			continue
		}
		logSchemeDistribution(fmt.Sprintf("special URL %s", sourceURL), specialProxies, "socks5")

		added := 0
		for _, proxy := range specialProxies {
			before := totalUnique
			handleProxy(proxy)
			if totalUnique > before {
				added++
			}
		}
		log.Printf("Fetched %d proxies from special URL %s", added, sourceURL)
	}

	flush()
	if totalUnique == 0 {
		return fmt.Errorf("no proxies fetched from any source")
	}

	log.Printf("Total unique proxies fetched: %d", totalUnique)
	return nil
}

func fetchAndProcessMixedProxyBatches(batchSize int, onBatch func([]string)) error {
	if batchSize <= 0 {
		batchSize = healthCheckBatchSize
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	seen := make(map[string]bool)
	batch := make([]string, 0, batchSize)
	totalUnique := 0

	flush := func() {
		if len(batch) == 0 {
			return
		}
		onBatch(batch)
		batch = make([]string, 0, batchSize)
	}

	handleProxy := func(proxy string) {
		if proxy == "" || seen[proxy] {
			return
		}
		seen[proxy] = true
		totalUnique++
		batch = append(batch, proxy)
		if len(batch) >= batchSize {
			flush()
		}
	}

	for _, sourceURL := range config.ProxyListURLs {
		log.Printf("Fetching mixed proxy list from regular URL: %s", sourceURL)
		resp, err := client.Get(sourceURL)
		if err != nil {
			log.Printf("Warning: Failed to fetch from %s: %v", sourceURL, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from %s", resp.StatusCode, sourceURL)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from %s: %v", sourceURL, err)
			continue
		}

		parsedProxies, format := parseRegularProxyContentMixed(string(body))
		logSchemeDistribution(fmt.Sprintf("mixed regular URL %s", sourceURL), parsedProxies, "socks5")
		added := 0
		for _, parsed := range parsedProxies {
			before := totalUnique
			handleProxy(parsed)
			if totalUnique > before {
				added++
			}
		}
		log.Printf("Fetched %d mixed proxies from regular URL %s (format=%s)", added, sourceURL, format)
	}

	for _, sourceURL := range config.SpecialProxyListUrls {
		log.Printf("Fetching mixed proxy list from special URL: %s", sourceURL)
		resp, err := client.Get(sourceURL)
		if err != nil {
			log.Printf("Warning: Failed to fetch from special URL %s: %v", sourceURL, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: Unexpected status code %d from special URL %s", resp.StatusCode, sourceURL)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Warning: Error reading body from special URL %s: %v", sourceURL, err)
			continue
		}

		specialProxies := parseSpecialProxyURLMixed(string(body))
		logSchemeDistribution(fmt.Sprintf("mixed special URL %s", sourceURL), specialProxies, "socks5")
		added := 0
		for _, parsed := range specialProxies {
			before := totalUnique
			handleProxy(parsed)
			if totalUnique > before {
				added++
			}
		}
		log.Printf("Fetched %d mixed proxies from special URL %s", added, sourceURL)
	}

	flush()
	if totalUnique == 0 {
		return fmt.Errorf("no mixed proxies fetched from any source")
	}

	log.Printf("Total unique mixed proxies fetched: %d", totalUnique)
	return nil
}

func parseMixedProxy(entry string) (scheme string, addr string, auth *proxy.Auth, httpAuthHeader string, err error) {
	if strings.Contains(entry, "://") {
		lower := strings.ToLower(strings.TrimSpace(entry))
		if strings.HasPrefix(lower, "vmess://") {
			node, ok := parseVMESSNode(entry)
			if !ok {
				return "", "", nil, "", fmt.Errorf("invalid vmess entry: %s", entry)
			}
			return "vmess", net.JoinHostPort(node.Add, node.Port), nil, "", nil
		}
		if strings.HasPrefix(lower, "vless://") {
			node, ok := parseVLESSNode(entry)
			if !ok {
				return "", "", nil, "", fmt.Errorf("invalid vless entry: %s", entry)
			}
			return "vless", net.JoinHostPort(node.Address, node.Port), &proxy.Auth{User: node.UUID}, "", nil
		}
		if strings.HasPrefix(lower, "hy2://") || strings.HasPrefix(lower, "hysteria2://") {
			node, ok := parseHY2Node(entry)
			if !ok {
				return "", "", nil, "", fmt.Errorf("invalid hy2 entry: %s", entry)
			}
			s := "hy2"
			if strings.HasPrefix(lower, "hysteria2://") {
				s = "hysteria2"
			}
			return s, net.JoinHostPort(node.Address, node.Port), &proxy.Auth{User: node.Password}, "", nil
		}

		u, parseErr := url.Parse(entry)
		if parseErr != nil || u.Host == "" {
			return "", "", nil, "", fmt.Errorf("invalid proxy entry: %s", entry)
		}
		s := strings.ToLower(u.Scheme)
		if !mixedSupportedSchemes[s] {
			return "", "", nil, "", fmt.Errorf("unsupported proxy scheme: %s", s)
		}

		var socksAuth *proxy.Auth
		httpHeader := ""
		if u.User != nil {
			username := u.User.Username()
			password, _ := u.User.Password()
			if username != "" {
				socksAuth = &proxy.Auth{User: username, Password: password}
				httpHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
			}
		}
		if socksAuth == nil && s == "hysteria" {
			authQuery := strings.TrimSpace(u.Query().Get("auth"))
			if authQuery != "" {
				socksAuth = &proxy.Auth{User: authQuery}
			}
		}

		return s, u.Host, socksAuth, httpHeader, nil
	}

	return "socks5", entry, nil, "", nil
}

func checkCloudflareBypassMixed(proxyEntry string) bool {
	if !config.CFChallengeCheck.Enabled {
		return false
	}

	dialer, _, err := upstreamDialerBuilder(proxyEntry)
	if err != nil {
		log.Printf("[CF-MIXED] Skip proxy %s: %v", proxyEntry, err)
		return false
	}

	timeout := time.Duration(config.CFChallengeCheck.TimeoutSeconds) * time.Second
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	transport.DialContext = dialer.DialContext
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, config.CFChallengeCheck.URL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 DynamicProxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		adapterMetrics.IncRetryExhausted()
		return false
	}
	defer resp.Body.Close()

	allowed := false
	for _, code := range config.CFChallengeCheck.ExpectedStatuses {
		if resp.StatusCode == code {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false
	}
	content := strings.ToLower(string(body))
	for _, indicator := range config.CFChallengeCheck.BlockIndicators {
		if indicator != "" && strings.Contains(content, strings.ToLower(indicator)) {
			return false
		}
	}

	return true
}

func checkMixedProxyHealth(proxyEntry string, strictMode bool) bool {
	dialer, _, err := upstreamDialerBuilder(proxyEntry)
	if err != nil {
		return false
	}

	threshold := time.Duration(config.HealthCheck.TLSHandshakeThresholdSeconds) * time.Second
	totalTimeout := time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !strictMode,
		},
	}
	transport.DialContext = dialer.DialContext
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: totalTimeout}
	start := time.Now()
	var resp *http.Response
	var reqErr error
	for attempt := 1; attempt <= healthCheckMaxRetries; attempt++ {
		resp, reqErr = client.Get(mixedHealthCheckURL)
		if reqErr == nil {
			break
		}
		if attempt < healthCheckMaxRetries {
			time.Sleep(retryBackoff(attempt))
		}
	}
	if reqErr != nil {
		adapterMetrics.IncRetryExhausted()
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	if time.Since(start) > threshold {
		return false
	}

	return true
}

func checkCloudflareBypass(proxyAddr string) bool {
	if !config.CFChallengeCheck.Enabled {
		return false
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return false
	}

	timeout := time.Duration(config.CFChallengeCheck.TimeoutSeconds) * time.Second
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	req, err := http.NewRequest(http.MethodGet, config.CFChallengeCheck.URL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 DynamicProxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	allowed := false
	for _, code := range config.CFChallengeCheck.ExpectedStatuses {
		if resp.StatusCode == code {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false
	}
	content := strings.ToLower(string(body))
	for _, indicator := range config.CFChallengeCheck.BlockIndicators {
		if indicator != "" && strings.Contains(content, strings.ToLower(indicator)) {
			return false
		}
	}

	return true
}

func checkProxyHealth(proxyAddr string, strictMode bool) bool {
	return checkProxyHealthWithSettings(proxyAddr, strictMode, config.HealthCheck)
}

func checkProxyHealthWithSettings(proxyAddr string, strictMode bool, settings HealthCheckSettings) bool {
	ok, _ := checkProxyHealthWithSettingsDetailed(proxyAddr, strictMode, settings)
	return ok
}

func checkProxyHealthWithSettingsDetailed(proxyAddr string, strictMode bool, settings HealthCheckSettings) (bool, error) {
	totalTimeout := time.Duration(settings.TotalTimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	forwardDialer := timeoutForwardDialer{timeout: totalTimeout}
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, forwardDialer)
	if err != nil {
		return false, err
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	conn, err := dialer.Dial("tcp", "www.google.com:443")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return false, err
		}
	}

	start := time.Now()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "www.google.com",
		InsecureSkipVerify: !strictMode, // Strict mode: verify certificate
	})

	err = tlsConn.Handshake()
	if err != nil {
		return false, err
	}
	defer tlsConn.Close()

	elapsed := time.Since(start)
	threshold := time.Duration(settings.TLSHandshakeThresholdSeconds) * time.Second
	if elapsed > threshold {
		return false, fmt.Errorf("tls handshake exceeded threshold: %v > %v", elapsed, threshold)
	}

	return true, nil
}

func evaluateProxy(addr string, settings HealthCheckSettings) (bool, bool) {
	strictOK, strictErr := checkProxyHealthWithSettingsDetailed(addr, true, settings)
	if strictOK {
		return true, true
	}

	if !shouldRetryRelaxed(strictErr) {
		return false, false
	}

	return false, checkProxyHealthWithSettings(addr, false, settings)
}

func shouldRetryRelaxed(err error) bool {
	if err == nil {
		return true
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return true
	}

	return false
}

// HealthCheckResult holds the results of health check for both modes
type HealthCheckResult struct {
	Strict  []string
	Relaxed []string
	CFPass  []string
}

func healthCheckProxies(proxies []string) HealthCheckResult {
	if config.HealthCheckTwoStage.Enabled {
		return healthCheckProxiesTwoStage(proxies)
	}

	return healthCheckProxiesSingleStage(proxies, config.HealthCheck)
}

func healthCheckProxiesSingleStage(proxies []string, settings HealthCheckSettings) HealthCheckResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	strictHealthy := make([]string, 0)
	relaxedHealthy := make([]string, 0)
	cfPassHealthy := make([]string, 0)

	total := len(proxies)
	var checked int64
	var strictCount int64
	var relaxedCount int64
	var cfPassCount int64

	workerCount := config.HealthCheckConcurrency
	if workerCount <= 0 {
		workerCount = 1
	}
	jobs := make(chan string)

	// Progress reporter goroutine
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		lastChecked := int64(0)

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				current := atomic.LoadInt64(&checked)
				strictCurrent := atomic.LoadInt64(&strictCount)
				relaxedCurrent := atomic.LoadInt64(&relaxedCount)
				cfCurrent := atomic.LoadInt64(&cfPassCount)

				// Only print if progress has changed
				if current != lastChecked {
					percentage := float64(current) / float64(total) * 100

					// Progress bar
					barWidth := 40
					filled := int(float64(barWidth) * float64(current) / float64(total))
					bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

					log.Printf("[%s] %d/%d (%.1f%%) | Strict: %d | Relaxed: %d | CF-Pass: %d",
						bar, current, total, percentage, strictCurrent, relaxedCurrent, cfCurrent)

					lastChecked = current
				}
			}
		}
	}()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				// Optimized: check strict mode first
				strictOK, relaxedOK := evaluateProxy(addr, settings)
				healthy := strictOK || relaxedOK

				if strictOK {
					// If strict mode passes, relaxed mode must pass too
					mu.Lock()
					strictHealthy = append(strictHealthy, addr)
					relaxedHealthy = append(relaxedHealthy, addr)
					mu.Unlock()
					atomic.AddInt64(&strictCount, 1)
					atomic.AddInt64(&relaxedCount, 1)
				} else if relaxedOK {
					mu.Lock()
					relaxedHealthy = append(relaxedHealthy, addr)
					mu.Unlock()
					atomic.AddInt64(&relaxedCount, 1)
				}

				if healthy && config.CFChallengeCheck.Enabled {
					if checkCloudflareBypass(addr) {
						mu.Lock()
						cfPassHealthy = append(cfPassHealthy, addr)
						mu.Unlock()
						atomic.AddInt64(&cfPassCount, 1)
					}
				}
				atomic.AddInt64(&checked, 1)
			}
		}()
	}

	for _, proxyAddr := range proxies {
		jobs <- proxyAddr
	}
	close(jobs)

	wg.Wait()
	close(done)

	// Final progress update
	log.Printf("[%s] %d/%d (100.0%%) | Strict: %d | Relaxed: %d | CF-Pass: %d",
		strings.Repeat("█", 40), total, total, len(strictHealthy), len(relaxedHealthy), len(cfPassHealthy))

	sort.Strings(cfPassHealthy)

	return HealthCheckResult{
		Strict:  strictHealthy,
		Relaxed: relaxedHealthy,
		CFPass:  cfPassHealthy,
	}
}

func healthCheckProxiesTwoStage(proxies []string) HealthCheckResult {
	log.Printf("[HEALTH] Two-stage health check enabled: stage1 timeout=%ds tls_threshold=%ds, stage2 timeout=%ds tls_threshold=%ds",
		config.HealthCheckTwoStage.StageOne.TotalTimeoutSeconds,
		config.HealthCheckTwoStage.StageOne.TLSHandshakeThresholdSeconds,
		config.HealthCheckTwoStage.StageTwo.TotalTimeoutSeconds,
		config.HealthCheckTwoStage.StageTwo.TLSHandshakeThresholdSeconds,
	)

	stage1Result := healthCheckProxiesSingleStage(proxies, config.HealthCheckTwoStage.StageOne)
	candidates := stage1Result.Relaxed
	log.Printf("[HEALTH] Stage 1 complete: candidates=%d/%d", len(candidates), len(proxies))
	if len(candidates) == 0 {
		return HealthCheckResult{}
	}

	stage2Result := healthCheckProxiesSingleStage(candidates, config.HealthCheckTwoStage.StageTwo)
	log.Printf("[HEALTH] Stage 2 complete: strict=%d relaxed=%d cf_pass=%d",
		len(stage2Result.Strict), len(stage2Result.Relaxed), len(stage2Result.CFPass))

	return stage2Result
}

func updateProxyPool(strictPool *ProxyPool, relaxedPool *ProxyPool, cfPool *ProxyPool) {
	// Check if an update is already in progress
	if !atomic.CompareAndSwapInt32(&strictPool.updating, 0, 1) {
		log.Println("Proxy update already in progress, skipping...")
		return
	}
	defer atomic.StoreInt32(&strictPool.updating, 0)

	log.Println("Fetching proxy list...")
	strictHealthy := make([]string, 0)
	relaxedHealthy := make([]string, 0)
	cfPassHealthy := make([]string, 0)

	err := fetchAndProcessSocksProxyBatches(healthCheckBatchSize, func(batch []string) {
		log.Printf("Processing strict/relaxed health check batch: size=%d", len(batch))
		result := healthCheckProxies(batch)
		strictHealthy = append(strictHealthy, result.Strict...)
		relaxedHealthy = append(relaxedHealthy, result.Relaxed...)
		cfPassHealthy = append(cfPassHealthy, result.CFPass...)
	})
	if err != nil {
		log.Printf("Error fetching proxy list: %v", err)
		return
	}

	result := HealthCheckResult{Strict: strictHealthy, Relaxed: relaxedHealthy, CFPass: cfPassHealthy}
	log.Printf("Streaming health check complete: strict=%d relaxed=%d cf_pass=%d", len(result.Strict), len(result.Relaxed), len(result.CFPass))

	// Update strict pool
	if len(result.Strict) > 0 {
		strictPool.Update(result.Strict)
		log.Printf("[STRICT] Pool updated with %d healthy proxies", len(result.Strict))
	} else {
		log.Println("[STRICT] Warning: No healthy proxies found, keeping existing pool")
	}

	if config.CFChallengeCheck.Enabled {
		if len(result.CFPass) > 0 {
			cfPool.Update(result.CFPass)
			log.Printf("[CF] Pool updated with %d CF-pass proxies", len(result.CFPass))
		} else {
			log.Println("[CF] Warning: No CF-pass proxies found, keeping existing CF pool")
		}
	}
	// Update relaxed pool
	if len(result.Relaxed) > 0 {
		relaxedPool.Update(result.Relaxed)
		log.Printf("[RELAXED] Pool updated with %d healthy proxies", len(result.Relaxed))
	} else {
		log.Println("[RELAXED] Warning: No healthy proxies found, keeping existing pool")
	}

	adminRuntime.MarkUpdated("ok")
}

type MixedHealthCheckResult struct {
	Healthy []string
	CFPass  []string
}

type healthFailureCategory string

const (
	healthFailureNone            healthFailureCategory = "none"
	healthFailureParse           healthFailureCategory = "parse_failed"
	healthFailureUnsupported     healthFailureCategory = "unsupported"
	healthFailureCoreUnavailable healthFailureCategory = "core_unconfigured"
	healthFailureHandshake       healthFailureCategory = "handshake_failed"
	healthFailureAuth            healthFailureCategory = "auth_failed"
	healthFailureTimeout         healthFailureCategory = "timeout"
	healthFailureUnreachable     healthFailureCategory = "unreachable"
	healthFailureEOF             healthFailureCategory = "eof"
	healthFailureProtocolError   healthFailureCategory = "protocol_error"
	healthFailureCertVerify      healthFailureCategory = "cert_verify_failed"
	healthFailureSNIMismatch     healthFailureCategory = "sni_mismatch"
)

type proxyHealthStatus struct {
	Healthy   bool
	Scheme    string
	Category  healthFailureCategory
	ErrorCode string
	Reason    string
}

type protocolStats struct {
	Total           int64
	Success         int64
	ParseFailed     int64
	Unsupported     int64
	CoreUnavailable int64
	HandshakeFail   int64
	AuthFail        int64
	Timeout         int64
	Unreachable     int64
	EOF             int64
	ProtocolError   int64
	CertVerifyFail  int64
	SNIMismatch     int64
	ErrorCodeCounts map[string]int64
}

func (s *protocolStats) addResult(status proxyHealthStatus) {
	s.Total++
	if status.Healthy {
		s.Success++
		return
	}
	if status.ErrorCode != "" {
		if s.ErrorCodeCounts == nil {
			s.ErrorCodeCounts = make(map[string]int64)
		}
		s.ErrorCodeCounts[status.ErrorCode]++
	}
	switch status.Category {
	case healthFailureParse:
		s.ParseFailed++
	case healthFailureUnsupported:
		s.Unsupported++
	case healthFailureCoreUnavailable:
		s.CoreUnavailable++
	case healthFailureHandshake:
		s.HandshakeFail++
	case healthFailureAuth:
		s.AuthFail++
	case healthFailureTimeout:
		s.Timeout++
	case healthFailureUnreachable:
		s.Unreachable++
	case healthFailureEOF:
		s.EOF++
	case healthFailureProtocolError:
		s.ProtocolError++
	case healthFailureCertVerify:
		s.CertVerifyFail++
	case healthFailureSNIMismatch:
		s.SNIMismatch++
	}
}

type healthErrorCodeMetrics struct {
	mu     sync.RWMutex
	counts map[string]int64
}

func (m *healthErrorCodeMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts = make(map[string]int64)
}

func (m *healthErrorCodeMetrics) Add(code string) {
	if strings.TrimSpace(code) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = make(map[string]int64)
	}
	m.counts[code]++
}

func (m *healthErrorCodeMetrics) Snapshot() map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]int64, len(m.counts))
	for k, v := range m.counts {
		out[k] = v
	}
	return out
}

var mixedHealthErrorCodeMetrics = &healthErrorCodeMetrics{counts: make(map[string]int64)}

func healthProtocolCodePrefix(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "ss":
		return "SS"
	case "ssr":
		return "SSR"
	case "trojan":
		return "TRJ"
	default:
		return "GEN"
	}
}

func resolveHealthErrorCode(scheme string, category healthFailureCategory, reasonCode string) string {
	if category == healthFailureNone {
		return ""
	}
	prefix := healthProtocolCodePrefix(scheme)
	codeMap := map[healthFailureCategory]string{
		healthFailureParse:           "001",
		healthFailureAuth:            "002",
		healthFailureUnsupported:     "003",
		healthFailureCoreUnavailable: "101",
		healthFailureHandshake:       "102",
		healthFailureUnreachable:     "103",
		healthFailureTimeout:         "201",
		healthFailureCertVerify:      "202",
		healthFailureSNIMismatch:     "203",
		healthFailureEOF:             "204",
		healthFailureProtocolError:   "205",
	}
	number, ok := codeMap[category]
	if !ok {
		number = "999"
	}
	if strings.Contains(strings.ToLower(reasonCode), "handshake") && category == healthFailureTimeout {
		number = "206"
	}
	return fmt.Sprintf("DP-%s-%s", prefix, number)
}

func topKErrorCodes(counts map[string]int64, k int) string {
	type pair struct {
		Code  string
		Count int64
	}
	list := make([]pair, 0, len(counts))
	for code, count := range counts {
		list = append(list, pair{Code: code, Count: count})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count == list[j].Count {
			return list[i].Code < list[j].Code
		}
		return list[i].Count > list[j].Count
	})
	if k > 0 && len(list) > k {
		list = list[:k]
	}
	parts := make([]string, 0, len(list))
	for _, item := range list {
		parts = append(parts, fmt.Sprintf("%s:%d", item.Code, item.Count))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func summarizeTopRootCauses(counts map[string]int64, total int64, topN int) string {
	type pair struct {
		Name  string
		Count int64
	}
	items := make([]pair, 0, len(counts))
	for name, count := range counts {
		items = append(items, pair{Name: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Name < items[j].Name
		}
		return items[i].Count > items[j].Count
	})
	if topN > 0 && len(items) > topN {
		items = items[:topN]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		ratio := 0.0
		if total > 0 {
			ratio = float64(item.Count) / float64(total) * 100
		}
		parts = append(parts, fmt.Sprintf("%s:%.1f%%(%d/%d)", item.Name, ratio, item.Count, total))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

type healthPhaseMetrics struct {
	DNS        time.Duration
	TCPConnect time.Duration
	TLSHello   time.Duration
	CertVerify time.Duration
	FirstByte  time.Duration
}

func formatHealthReason(code string, err error) string {
	if code == "" {
		code = "DP-GEN-999"
	}
	if err == nil {
		return "error_code=" + code
	}
	detail := strings.ReplaceAll(err.Error(), ";", ",")
	return fmt.Sprintf("error_code=%s;detail=%s", code, detail)
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}

func classifyHealthFailure(err error) (healthFailureCategory, string) {
	if err == nil {
		return healthFailureNone, "ok"
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return healthFailureTimeout, "timeout"
	}

	if errors.Is(err, io.EOF) {
		return healthFailureEOF, "eof"
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return healthFailureSNIMismatch, "sni_mismatch"
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &unknownAuthorityErr) || errors.As(err, &certInvalidErr) {
		return healthFailureCertVerify, "cert_verify_failed"
	}

	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, errMainstreamAdapterUnavailable), errors.Is(err, errMainstreamCoreUnavailable), strings.Contains(msg, "detector.core is empty"):
		return healthFailureCoreUnavailable, "core_unconfigured"
	case strings.Contains(msg, "unsupported"):
		return healthFailureUnsupported, "unsupported"
	case strings.Contains(msg, "first record does not look like a tls handshake"), strings.Contains(msg, "tls: oversized record"), strings.Contains(msg, "malformed"), strings.Contains(msg, "server gave http response to https client"):
		return healthFailureProtocolError, "protocol_error"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		if strings.Contains(msg, "handshake") {
			return healthFailureTimeout, "tls_handshake_timeout"
		}
		return healthFailureTimeout, "timeout"
	case strings.Contains(msg, "auth"), strings.Contains(msg, "unauthorized"), strings.Contains(msg, "forbidden"):
		return healthFailureAuth, "auth_failed"
	case strings.Contains(msg, "eof"):
		return healthFailureEOF, "eof"
	case strings.Contains(msg, "x509"), strings.Contains(msg, "certificate"):
		return healthFailureCertVerify, "cert_verify_failed"
	case strings.Contains(msg, "sni") || strings.Contains(msg, "hostname"):
		return healthFailureSNIMismatch, "sni_mismatch"
	case strings.Contains(msg, "handshake"), strings.Contains(msg, "tls"), strings.Contains(msg, "certificate"):
		return healthFailureHandshake, "handshake_failed"
	default:
		return healthFailureUnreachable, "unreachable"
	}
}

func checkMainstreamProxyHealth(proxyEntry string, strictMode bool) proxyHealthStatus {
	return checkMainstreamProxyHealthStage2(proxyEntry, strictMode, config.HealthCheck).Status
}

type mixedStageCheckResult struct {
	Status  proxyHealthStatus
	Latency time.Duration
}

type mixedFailPhase string

const (
	mixedFailPhaseDialerBuild  mixedFailPhase = "dialer_build"
	mixedFailPhaseCoreCheck    mixedFailPhase = "core_check"
	mixedFailPhaseTCPConnect   mixedFailPhase = "tcp_connect"
	mixedFailPhaseTLSHandshake mixedFailPhase = "tls_handshake"
	mixedFailPhaseHTTPRequest  mixedFailPhase = "http_request"
)

type stagePromMetrics struct {
	mu                sync.RWMutex
	inputByProtocol   map[string]int64
	passByProtocol    map[string]map[string]int64
	errorCodeByProto  map[string]map[string]map[string]int64
	latencyByProtocol map[string]map[string][]time.Duration
}

func newStagePromMetrics() *stagePromMetrics {
	return &stagePromMetrics{
		inputByProtocol:   make(map[string]int64),
		passByProtocol:    make(map[string]map[string]int64),
		errorCodeByProto:  make(map[string]map[string]map[string]int64),
		latencyByProtocol: make(map[string]map[string][]time.Duration),
	}
}

func normalizeMetricsProtocol(scheme string) string {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		return "unknown"
	}
	return scheme
}

func normalizeStageName(stage string) string {
	stage = strings.ToLower(strings.TrimSpace(stage))
	if stage != "stage1" && stage != "stage2" {
		return "unknown"
	}
	return stage
}

func (m *stagePromMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inputByProtocol = make(map[string]int64)
	m.passByProtocol = make(map[string]map[string]int64)
	m.errorCodeByProto = make(map[string]map[string]map[string]int64)
	m.latencyByProtocol = make(map[string]map[string][]time.Duration)
}

func (m *stagePromMetrics) AddInput(protocol string) {
	protocol = normalizeMetricsProtocol(protocol)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inputByProtocol[protocol]++
}

func (m *stagePromMetrics) AddStageResult(protocol, stage string, healthy bool, errorCode string, latency time.Duration) {
	protocol = normalizeMetricsProtocol(protocol)
	stage = normalizeStageName(stage)

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.passByProtocol[protocol]; !ok {
		m.passByProtocol[protocol] = make(map[string]int64)
	}
	if healthy {
		m.passByProtocol[protocol][stage]++
	}

	if !healthy && strings.TrimSpace(errorCode) != "" {
		if _, ok := m.errorCodeByProto[protocol]; !ok {
			m.errorCodeByProto[protocol] = make(map[string]map[string]int64)
		}
		if _, ok := m.errorCodeByProto[protocol][stage]; !ok {
			m.errorCodeByProto[protocol][stage] = make(map[string]int64)
		}
		m.errorCodeByProto[protocol][stage][errorCode]++
	}

	if healthy && latency > 0 {
		if _, ok := m.latencyByProtocol[protocol]; !ok {
			m.latencyByProtocol[protocol] = make(map[string][]time.Duration)
		}
		m.latencyByProtocol[protocol][stage] = append(m.latencyByProtocol[protocol][stage], latency)
	}
}

func (m *stagePromMetrics) Snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	input := make(map[string]int64, len(m.inputByProtocol))
	for k, v := range m.inputByProtocol {
		input[k] = v
	}

	pass := make(map[string]map[string]int64, len(m.passByProtocol))
	for proto, stages := range m.passByProtocol {
		pass[proto] = make(map[string]int64, len(stages))
		for stage, count := range stages {
			pass[proto][stage] = count
		}
	}

	errCodes := make(map[string]map[string]map[string]int64, len(m.errorCodeByProto))
	for proto, stages := range m.errorCodeByProto {
		errCodes[proto] = make(map[string]map[string]int64, len(stages))
		for stage, codes := range stages {
			errCodes[proto][stage] = make(map[string]int64, len(codes))
			for code, count := range codes {
				errCodes[proto][stage][code] = count
			}
		}
	}

	pct := make(map[string]map[string]float64)
	for proto, stages := range pass {
		total := float64(input[proto])
		if total <= 0 {
			continue
		}
		if _, ok := pct[proto]; !ok {
			pct[proto] = make(map[string]float64)
		}
		for stage, count := range stages {
			pct[proto][stage] = float64(count) / total
		}
	}

	latency := make(map[string]map[string]map[string]float64)
	for proto, stages := range m.latencyByProtocol {
		latency[proto] = make(map[string]map[string]float64)
		for stage, vals := range stages {
			if len(vals) == 0 {
				continue
			}
			copied := append([]time.Duration(nil), vals...)
			sort.Slice(copied, func(i, j int) bool { return copied[i] < copied[j] })
			q := func(p float64) float64 {
				idx := int(float64(len(copied)-1) * p)
				return float64(copied[idx].Milliseconds())
			}
			latency[proto][stage] = map[string]float64{"p50_ms": q(0.5), "p90_ms": q(0.9)}
		}
	}

	return map[string]interface{}{
		"input":             input,
		"pass":              pass,
		"pass_rate":         pct,
		"error_code_counts": errCodes,
		"latency":           latency,
	}
}

func (m *stagePromMetrics) RenderPrometheus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	b := &strings.Builder{}
	b.WriteString("# HELP dynamic_proxy_stage_input_total Stage health check input total by protocol\n")
	b.WriteString("# TYPE dynamic_proxy_stage_input_total counter\n")
	for protocol, total := range m.inputByProtocol {
		fmt.Fprintf(b, "dynamic_proxy_stage_input_total{protocol=%q} %d\n", protocol, total)
	}
	b.WriteString("# HELP dynamic_proxy_stage_pass_total Stage health check pass total by protocol and stage\n")
	b.WriteString("# TYPE dynamic_proxy_stage_pass_total counter\n")
	for protocol, stages := range m.passByProtocol {
		for stage, total := range stages {
			fmt.Fprintf(b, "dynamic_proxy_stage_pass_total{protocol=%q,stage=%q} %d\n", protocol, stage, total)
		}
	}
	b.WriteString("# HELP dynamic_proxy_stage_pass_rate Stage health check pass rate by protocol and stage\n")
	b.WriteString("# TYPE dynamic_proxy_stage_pass_rate gauge\n")
	for protocol, input := range m.inputByProtocol {
		if input <= 0 {
			continue
		}
		for stage, pass := range m.passByProtocol[protocol] {
			rate := float64(pass) / float64(input)
			fmt.Fprintf(b, "dynamic_proxy_stage_pass_rate{protocol=%q,stage=%q} %.6f\n", protocol, stage, rate)
		}
	}
	b.WriteString("# HELP dynamic_proxy_stage_latency_ms Stage health check latency percentile in milliseconds\n")
	b.WriteString("# TYPE dynamic_proxy_stage_latency_ms gauge\n")
	for protocol, stages := range m.latencyByProtocol {
		for stage, vals := range stages {
			if len(vals) == 0 {
				continue
			}
			copied := append([]time.Duration(nil), vals...)
			sort.Slice(copied, func(i, j int) bool { return copied[i] < copied[j] })
			q := func(p float64) float64 {
				idx := int(float64(len(copied)-1) * p)
				return float64(copied[idx].Milliseconds())
			}
			fmt.Fprintf(b, "dynamic_proxy_stage_latency_ms{protocol=%q,stage=%q,quantile=\"0.50\"} %.2f\n", protocol, stage, q(0.5))
			fmt.Fprintf(b, "dynamic_proxy_stage_latency_ms{protocol=%q,stage=%q,quantile=\"0.90\"} %.2f\n", protocol, stage, q(0.9))
		}
	}
	b.WriteString("# HELP dynamic_proxy_stage_error_code_total Stage health check error code total by protocol and stage\n")
	b.WriteString("# TYPE dynamic_proxy_stage_error_code_total counter\n")
	for protocol, stages := range m.errorCodeByProto {
		for stage, codes := range stages {
			for code, total := range codes {
				fmt.Fprintf(b, "dynamic_proxy_stage_error_code_total{protocol=%q,stage=%q,error_code=%q} %d\n", protocol, stage, code, total)
			}
		}
	}
	return b.String()
}

var mixedStageMetrics = newStagePromMetrics()

func logMixedHealthFailure(stage, scheme string, category healthFailureCategory, errorCode string, failPhase mixedFailPhase, err error) {
	if scheme == "" {
		scheme = "unknown"
	}
	detail := ""
	if err != nil {
		detail = strings.ReplaceAll(err.Error(), "\n", " ")
	}
	log.Printf("[MIXED-HEALTH-FAIL] stage=%s scheme=%s category=%s error_code=%s fail_phase=%s detail=%s",
		stage, scheme, category, errorCode, failPhase, detail)
}

func mixedHealthTargetAddr() string {
	u, err := url.Parse(mixedHealthCheckURL)
	if err != nil || u.Host == "" {
		return "www.google.com:443"
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		} else {
			port = "443"
		}
	}
	if host == "" {
		host = "www.google.com"
	}
	return net.JoinHostPort(host, port)
}

func mixedHealthSettingsForProtocol(scheme string, stage int) HealthCheckSettings {
	settings, _ := mixedHealthSettingsForProtocolWithTier(scheme, stage)
	return settings
}

func mixedHealthSettingsForProtocolWithTier(scheme string, stage int) (HealthCheckSettings, string) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	override, ok := config.HealthCheckProtocolOverrides[scheme]
	if ok {
		if stage == 1 {
			if override.StageOne.TotalTimeoutSeconds > 0 && override.StageOne.TLSHandshakeThresholdSeconds > 0 {
				return override.StageOne, "protocol_override"
			}
		} else if override.StageTwo.TotalTimeoutSeconds > 0 && override.StageTwo.TLSHandshakeThresholdSeconds > 0 {
			return override.StageTwo, "protocol_override"
		}
	}

	if stage == 1 {
		if config.HealthCheckTwoStage.StageOne.TotalTimeoutSeconds > 0 && config.HealthCheckTwoStage.StageOne.TLSHandshakeThresholdSeconds > 0 {
			return config.HealthCheckTwoStage.StageOne, "two_stage_default"
		}
		return config.HealthCheck, "global_health_check"
	}
	if config.HealthCheckTwoStage.StageTwo.TotalTimeoutSeconds > 0 && config.HealthCheckTwoStage.StageTwo.TLSHandshakeThresholdSeconds > 0 {
		return config.HealthCheckTwoStage.StageTwo, "two_stage_default"
	}
	return config.HealthCheck, "global_health_check"
}

func checkMainstreamProxyHealthStage1(proxyEntry string, settings HealthCheckSettings) proxyHealthStatus {
	dialer, scheme, err := upstreamDialerBuilder(proxyEntry)
	if scheme == "" {
		scheme = "unknown"
	}
	if err != nil {
		failPhase := mixedFailPhaseDialerBuild
		if category, _ := classifyHealthFailure(err); category == healthFailureCoreUnavailable {
			failPhase = mixedFailPhaseCoreCheck
		}
		if strings.Contains(err.Error(), "invalid") {
			errorCode := resolveHealthErrorCode(scheme, healthFailureParse, "invalid_proxy_entry")
			logMixedHealthFailure("stage1", scheme, healthFailureParse, errorCode, failPhase, err)
			return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, err)}
		}
		category, reasonCode := classifyHealthFailure(err)
		errorCode := resolveHealthErrorCode(scheme, category, reasonCode)
		logMixedHealthFailure("stage1", scheme, category, errorCode, failPhase, err)
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, err)}
	}

	totalTimeout := time.Duration(settings.TotalTimeoutSeconds) * time.Second
	threshold := time.Duration(settings.TLSHandshakeThresholdSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", mixedHealthTargetAddr())
	if err != nil {
		category, reasonCode := classifyHealthFailure(err)
		errorCode := resolveHealthErrorCode(scheme, category, reasonCode)
		logMixedHealthFailure("stage1", scheme, category, errorCode, mixedFailPhaseTCPConnect, err)
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, err)}
	}
	_ = conn.Close()

	if time.Since(start) > threshold {
		errorCode := resolveHealthErrorCode(scheme, healthFailureTimeout, "stage1_connect_timeout")
		timeoutErr := errors.New("stage1 tunnel connect exceeded threshold")
		logMixedHealthFailure("stage1", scheme, healthFailureTimeout, errorCode, mixedFailPhaseTCPConnect, timeoutErr)
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, timeoutErr)}
	}

	return proxyHealthStatus{Healthy: true, Scheme: scheme, Category: healthFailureNone, ErrorCode: ""}
}

func checkMainstreamProxyHealthStage1WithHardTimeout(proxyEntry string, settings HealthCheckSettings) proxyHealthStatus {
	totalTimeout := time.Duration(settings.TotalTimeoutSeconds) * time.Second
	if totalTimeout <= 0 {
		totalTimeout = 5 * time.Second
	}

	resultCh := make(chan proxyHealthStatus, 1)
	go func() {
		resultCh <- checkMainstreamProxyHealthStage1(proxyEntry, settings)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-time.After(totalTimeout + time.Second):
		scheme := "unknown"
		if parsedScheme, _, _, _, err := parseMixedProxy(proxyEntry); err == nil && parsedScheme != "" {
			scheme = parsedScheme
		}
		errorCode := resolveHealthErrorCode(scheme, healthFailureTimeout, "stage1_hard_timeout")
		timeoutErr := errors.New("stage1 hard timeout exceeded")
		logMixedHealthFailure("stage1", scheme, healthFailureTimeout, errorCode, mixedFailPhaseTCPConnect, timeoutErr)
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, timeoutErr)}
	}
}

func checkMainstreamProxyHealthStage2(proxyEntry string, strictMode bool, settings HealthCheckSettings) mixedStageCheckResult {
	dialer, scheme, err := upstreamDialerBuilder(proxyEntry)
	if scheme == "" {
		scheme = "unknown"
	}
	if err != nil {
		failPhase := mixedFailPhaseDialerBuild
		if category, _ := classifyHealthFailure(err); category == healthFailureCoreUnavailable {
			failPhase = mixedFailPhaseCoreCheck
		}
		if strings.Contains(err.Error(), "invalid") {
			errorCode := resolveHealthErrorCode(scheme, healthFailureParse, "invalid_proxy_entry")
			logMixedHealthFailure("stage2", scheme, healthFailureParse, errorCode, failPhase, err)
			return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, err)}}
		}
		category, reasonCode := classifyHealthFailure(err)
		errorCode := resolveHealthErrorCode(scheme, category, reasonCode)
		logMixedHealthFailure("stage2", scheme, category, errorCode, failPhase, err)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, err)}}
	}

	totalTimeout := time.Duration(settings.TotalTimeoutSeconds) * time.Second
	threshold := time.Duration(settings.TLSHandshakeThresholdSeconds) * time.Second

	targetURL, parseErr := url.Parse(mixedHealthCheckURL)
	if parseErr != nil {
		errorCode := resolveHealthErrorCode(scheme, healthFailureParse, "invalid_healthcheck_url")
		logMixedHealthFailure("stage2", scheme, healthFailureParse, errorCode, mixedFailPhaseHTTPRequest, parseErr)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, parseErr)}}
	}

	serverName := targetURL.Hostname()
	phase := &healthPhaseMetrics{}
	var certVerifyDur time.Duration
	var verifyErr error

	transport := &http.Transport{}
	transport.TLSClientConfig = &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if !strictMode {
				return nil
			}
			start := time.Now()
			defer func() { certVerifyDur = time.Since(start) }()
			if len(cs.PeerCertificates) == 0 {
				verifyErr = fmt.Errorf("no peer certificate")
				return verifyErr
			}
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			opts := x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: x509.NewCertPool()}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, verifyErr = cs.PeerCertificates[0].Verify(opts)
			return verifyErr
		},
	}
	transport.DialContext = dialer.DialContext

	client := &http.Client{Transport: transport, Timeout: totalTimeout}

	var dnsStart, connStart, tlsStart, reqStart time.Time
	var tlsHandshakeDone bool
	req, reqErr := http.NewRequest(http.MethodGet, mixedHealthCheckURL, nil)
	if reqErr != nil {
		errorCode := resolveHealthErrorCode(scheme, healthFailureParse, "invalid_request")
		logMixedHealthFailure("stage2", scheme, healthFailureParse, errorCode, mixedFailPhaseHTTPRequest, reqErr)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, reqErr)}}
	}
	reqCtx, dialPhaseMetric := withDialPhase(req.Context())
	req = req.WithContext(httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				phase.DNS = time.Since(dnsStart)
			}
		},
		ConnectStart: func(_, _ string) { connStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connStart.IsZero() {
				phase.TCPConnect = time.Since(connStart)
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			tlsHandshakeDone = true
			if !tlsStart.IsZero() {
				tlsDur := time.Since(tlsStart)
				phase.CertVerify = certVerifyDur
				if tlsDur > certVerifyDur {
					phase.TLSHello = tlsDur - certVerifyDur
				} else {
					phase.TLSHello = tlsDur
				}
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { reqStart = time.Now() },
		GotFirstResponseByte: func() {
			if !reqStart.IsZero() {
				phase.FirstByte = time.Since(reqStart)
			}
		},
	}))

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		if verifyErr != nil {
			category, reasonCode := classifyHealthFailure(verifyErr)
			if category == healthFailureCertVerify {
				allow, host := shouldAllowInsecureByWhitelist(proxyEntry)
				if config.CertVerifyWhitelist.EnforceStrictAudit {
					log.Printf("[STRICT-AUDIT] strict_mode=%t scheme=%s host=%s cert_verify_failed whitelist_allow=%t", strictMode, scheme, host, allow)
				}
				if allow {
					return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: true, Scheme: scheme, Category: healthFailureNone, ErrorCode: ""}, Latency: latency}
				}
			}
			errorCode := resolveHealthErrorCode(scheme, category, reasonCode)
			logMixedHealthFailure("stage2", scheme, category, errorCode, mixedFailPhaseTLSHandshake, verifyErr)
			return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, verifyErr)}, Latency: latency}
		}
		if isTimeoutError(err) && !tlsHandshakeDone {
			errorCode := resolveHealthErrorCode(scheme, healthFailureTimeout, "tls_handshake_timeout")
			logMixedHealthFailure("stage2", scheme, healthFailureTimeout, errorCode, mixedFailPhaseTLSHandshake, err)
			return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, err)}, Latency: latency}
		}
		category, reasonCode := classifyHealthFailure(err)
		errorCode := resolveHealthErrorCode(scheme, category, reasonCode)
		phase := mixedFailPhaseHTTPRequest
		if !tlsHandshakeDone {
			phase = mixedFailPhaseTCPConnect
		}
		logMixedHealthFailure("stage2", scheme, category, errorCode, phase, err)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, err)}, Latency: latency}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		errorCode := resolveHealthErrorCode(scheme, healthFailureUnreachable, "unexpected_status")
		statusErr := fmt.Errorf("unexpected status: %d", resp.StatusCode)
		logMixedHealthFailure("stage2", scheme, healthFailureUnreachable, errorCode, mixedFailPhaseHTTPRequest, statusErr)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureUnreachable, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, statusErr)}, Latency: latency}
	}

	if tlsHandshakeDone && phase.TLSHello+phase.CertVerify > threshold {
		errorCode := resolveHealthErrorCode(scheme, healthFailureTimeout, "stage2_tls_threshold_timeout")
		timeoutErr := errors.New("stage2 tls handshake exceeded threshold")
		logMixedHealthFailure("stage2", scheme, healthFailureTimeout, errorCode, mixedFailPhaseTLSHandshake, timeoutErr)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, ErrorCode: errorCode, Reason: formatHealthReason(errorCode, timeoutErr)}, Latency: latency}
	}
	proxyDial := dialPhaseMetric.ProxyDial
	if phase.TCPConnect == 0 && dialPhaseMetric.TCPConnect > 0 {
		phase.TCPConnect = dialPhaseMetric.TCPConnect
	}

	log.Printf("[MIXED-TLS-PHASE] scheme=%s dns=%s tcp_connect=%s proxy_dial=%s tls_clienthello=%s cert_verify=%s first_byte=%s",
		scheme, phase.DNS, phase.TCPConnect, proxyDial, phase.TLSHello, phase.CertVerify, phase.FirstByte)

	return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: true, Scheme: scheme, Category: healthFailureNone, ErrorCode: ""}, Latency: latency}
}

func runUDPEgressAudit(proxies []string) {
	udpSchemes := map[string]bool{"hy2": true, "hysteria": true, "hysteria2": true, "tuic": true}
	unique := make(map[string]string)
	for _, entry := range proxies {
		scheme, addr, _, _, err := parseMixedProxy(entry)
		if err != nil {
			continue
		}
		scheme = strings.ToLower(strings.TrimSpace(scheme))
		if !udpSchemes[scheme] {
			continue
		}
		unique[addr] = scheme
	}
	if len(unique) == 0 {
		return
	}
	pass, fail := 0, 0
	for addr, scheme := range unique {
		conn, err := net.DialTimeout("udp", addr, 2*time.Second)
		if err != nil {
			fail++
			log.Printf("[UDP-AUDIT] scheme=%s addr=%s status=blocked err=%v (请检查云防火墙/NACL UDP 出网放通)", scheme, addr, err)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, writeErr := conn.Write([]byte{0x00})
		_ = conn.Close()
		if writeErr != nil {
			fail++
			log.Printf("[UDP-AUDIT] scheme=%s addr=%s status=blocked err=%v (请检查云防火墙/NACL UDP 出网放通)", scheme, addr, writeErr)
			continue
		}
		pass++
		log.Printf("[UDP-AUDIT] scheme=%s addr=%s status=ok", scheme, addr)
	}
	log.Printf("[UDP-AUDIT-SUMMARY] targets=%d pass=%d fail=%d", len(unique), pass, fail)
}

func healthCheckMixedProxies(proxies []string) MixedHealthCheckResult {
	mixedHealthErrorCodeMetrics.Reset()
	mixedStageMetrics.Reset()
	runUDPEgressAudit(proxies)
	if config.HealthCheckTwoStage.Enabled {
		return healthCheckMixedProxiesTwoStage(proxies)
	}
	return healthCheckMixedProxiesSingleStage(proxies)
}

func healthCheckMixedProxiesSingleStage(proxies []string) MixedHealthCheckResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	proxies = reorderMixedHealthCheckQueue(proxies)
	mixedHealthy := make([]string, 0)
	cfPassHealthy := make([]string, 0)

	total := len(proxies)
	var checked int64
	var healthyCount int64
	var cfPassCount int64
	protocolSummary := make(map[string]*protocolStats)
	latencies := make([]time.Duration, 0, len(proxies))

	workerCount := config.HealthCheckConcurrency
	if workerCount <= 0 {
		workerCount = 1
	}
	jobs := make(chan string, workerCount*4)
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		lastChecked := int64(0)
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				current := atomic.LoadInt64(&checked)
				healthyCurrent := atomic.LoadInt64(&healthyCount)
				cfCurrent := atomic.LoadInt64(&cfPassCount)
				if current != lastChecked {
					percentage := float64(current) / float64(total) * 100
					barWidth := 40
					filled := int(float64(barWidth) * float64(current) / float64(total))
					bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
					log.Printf("[MIXED-%s] %d/%d (%.1f%%) | Healthy: %d | CF-Pass: %d", bar, current, total, percentage, healthyCurrent, cfCurrent)
					lastChecked = current
				}
			}
		}
	}()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localSummary := make(map[string]protocolStats)
			localLatencies := make([]time.Duration, 0, 32)
			for entry := range jobs {
				begin := time.Now()
				status := mixedProxyHealthChecker(entry, false)
				elapsed := time.Since(begin)
				localLatencies = append(localLatencies, elapsed)
				stats := localSummary[status.Scheme]
				stats.addResult(status)
				if !status.Healthy {
					mixedHealthErrorCodeMetrics.Add(status.ErrorCode)
				}
				localSummary[status.Scheme] = stats

				if status.Healthy {
					mu.Lock()
					mixedHealthy = append(mixedHealthy, entry)
					mu.Unlock()
					atomic.AddInt64(&healthyCount, 1)
					if config.CFChallengeCheck.Enabled && mixedCFBypassChecker(entry) {
						mu.Lock()
						cfPassHealthy = append(cfPassHealthy, entry)
						mu.Unlock()
						atomic.AddInt64(&cfPassCount, 1)
					}
				}
				atomic.AddInt64(&checked, 1)
			}

			mu.Lock()
			latencies = append(latencies, localLatencies...)
			for scheme, local := range localSummary {
				stats, ok := protocolSummary[scheme]
				if !ok {
					stats = &protocolStats{}
					protocolSummary[scheme] = stats
				}
				stats.Total += local.Total
				stats.Success += local.Success
				stats.ParseFailed += local.ParseFailed
				stats.Unsupported += local.Unsupported
				stats.CoreUnavailable += local.CoreUnavailable
				stats.HandshakeFail += local.HandshakeFail
				stats.AuthFail += local.AuthFail
				stats.Timeout += local.Timeout
				stats.Unreachable += local.Unreachable
				stats.EOF += local.EOF
				stats.ProtocolError += local.ProtocolError
				stats.CertVerifyFail += local.CertVerifyFail
				stats.SNIMismatch += local.SNIMismatch
			}
			mu.Unlock()
		}()
	}

	for _, proxyEntry := range proxies {
		jobs <- proxyEntry
	}
	close(jobs)

	wg.Wait()
	close(done)
	log.Printf("[MIXED-%s] %d/%d (100.0%%) | Healthy: %d | CF-Pass: %d", strings.Repeat("█", 40), total, total, len(mixedHealthy), len(cfPassHealthy))

	mu.Lock()
	protocols := make([]string, 0, len(protocolSummary))
	for scheme := range protocolSummary {
		protocols = append(protocols, scheme)
	}
	sort.Strings(protocols)
	for _, scheme := range protocols {
		stats := protocolSummary[scheme]
		successRate := 0.0
		if stats.Total > 0 {
			successRate = float64(stats.Success) / float64(stats.Total) * 100
		}
		log.Printf("[MIXED-SUMMARY] scheme=%s total=%d success=%d success_rate=%.1f%% failures={parse:%d unsupported:%d core_unconfigured:%d handshake:%d auth:%d timeout:%d unreachable:%d}",
			scheme,
			stats.Total,
			stats.Success,
			successRate,
			stats.ParseFailed,
			stats.Unsupported,
			stats.CoreUnavailable,
			stats.HandshakeFail,
			stats.AuthFail,
			stats.Timeout,
			stats.Unreachable,
		)
		log.Printf("[MIXED-SUMMARY] scheme=%s tls_failures={eof:%d protocol_error:%d cert_verify_failed:%d sni_mismatch:%d} error_code_topk=%s",
			scheme,
			stats.EOF,
			stats.ProtocolError,
			stats.CertVerifyFail,
			stats.SNIMismatch,
			topKErrorCodes(stats.ErrorCodeCounts, 5),
		)
		if stats.Total > 0 {
			coreUnconfiguredRate := float64(stats.CoreUnavailable) / float64(stats.Total)
			if coreUnconfiguredRate > 0.10 {
				log.Printf("[ALERT-core_unconfigured] scheme=%s core_unconfigured=%d total=%d rate=%.1f%% threshold=10.0%%",
					scheme,
					stats.CoreUnavailable,
					stats.Total,
					coreUnconfiguredRate*100,
				)
			}
		}
	}
	mu.Unlock()

	mu.Lock()
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		q := func(p float64) time.Duration {
			idx := int(float64(len(latencies)-1) * p)
			return latencies[idx]
		}
		totalLatency := time.Duration(0)
		for _, d := range latencies {
			totalLatency += d
		}
		avgLatency := totalLatency / time.Duration(len(latencies))
		log.Printf("[MIXED-LATENCY] count=%d p50=%s p90=%s p99=%s avg=%s", len(latencies), q(0.50), q(0.90), q(0.99), avgLatency)
	}
	mu.Unlock()

	sort.Strings(cfPassHealthy)

	return MixedHealthCheckResult{Healthy: mixedHealthy, CFPass: cfPassHealthy}
}

type mixedTwoStageStats struct {
	Total      int64
	Stage1Pass int64
	Stage2Pass int64
	DropReason map[string]int64
}

func healthCheckMixedProxiesTwoStage(proxies []string) MixedHealthCheckResult {
	proxies = reorderMixedHealthCheckQueue(proxies)
	if len(proxies) == 0 {
		return MixedHealthCheckResult{}
	}

	log.Printf("[MIXED-2STAGE] enabled stage1 timeout=%ds tls_threshold=%ds, stage2 timeout=%ds tls_threshold=%ds",
		config.HealthCheckTwoStage.StageOne.TotalTimeoutSeconds,
		config.HealthCheckTwoStage.StageOne.TLSHandshakeThresholdSeconds,
		config.HealthCheckTwoStage.StageTwo.TotalTimeoutSeconds,
		config.HealthCheckTwoStage.StageTwo.TLSHandshakeThresholdSeconds,
	)
	strictMode := false
	if config.HealthCheckTwoStage.StrictMode != nil {
		strictMode = *config.HealthCheckTwoStage.StrictMode
	}
	log.Printf("[MIXED-2STAGE] stage2 strict_mode=%t", strictMode)

	workerCount := config.HealthCheckConcurrency
	if workerCount <= 0 {
		workerCount = 1
	}

	loggedSchemes := make(map[string]struct{})
	for _, entry := range proxies {
		scheme := "unknown"
		if parsedScheme, _, _, _, err := parseMixedProxy(entry); err == nil && parsedScheme != "" {
			scheme = parsedScheme
		}
		scheme = strings.ToLower(strings.TrimSpace(scheme))
		if _, exists := loggedSchemes[scheme]; exists {
			continue
		}
		stageOneSettings, stageOneTier := mixedHealthSettingsForProtocolWithTier(scheme, 1)
		stageTwoSettings, stageTwoTier := mixedHealthSettingsForProtocolWithTier(scheme, 2)
		log.Printf("[MIXED-2STAGE-POLICY] scheme=%s stage1={tier:%s timeout:%ds tls_threshold:%ds} stage2={tier:%s timeout:%ds tls_threshold:%ds strict_mode:%t}",
			scheme,
			stageOneTier,
			stageOneSettings.TotalTimeoutSeconds,
			stageOneSettings.TLSHandshakeThresholdSeconds,
			stageTwoTier,
			stageTwoSettings.TotalTimeoutSeconds,
			stageTwoSettings.TLSHandshakeThresholdSeconds,
			strictMode,
		)
		loggedSchemes[scheme] = struct{}{}
	}

	stageStats := make(map[string]*mixedTwoStageStats)
	getStageStats := func(scheme string) *mixedTwoStageStats {
		if scheme == "" {
			scheme = "unknown"
		}
		st, ok := stageStats[scheme]
		if !ok {
			st = &mixedTwoStageStats{DropReason: make(map[string]int64)}
			stageStats[scheme] = st
		}
		return st
	}

	stage1Candidates := make([]string, 0, len(proxies))
	var mu sync.Mutex
	jobs := make(chan string, workerCount*4)
	var wg sync.WaitGroup
	var stage1Checked int64
	var stage1Pass int64
	stage1Done := make(chan struct{})
	go func(total int) {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		lastChecked := int64(0)
		for {
			select {
			case <-stage1Done:
				return
			case <-ticker.C:
				checked := atomic.LoadInt64(&stage1Checked)
				if checked == lastChecked {
					continue
				}
				lastChecked = checked
				progress := 0.0
				if total > 0 {
					progress = float64(checked) / float64(total) * 100
				}
				pass := atomic.LoadInt64(&stage1Pass)
				log.Printf("[MIXED-2STAGE] stage1 progress: %.1f%% (%d/%d), pass=%d", progress, checked, total, pass)
			}
		}
	}(len(proxies))
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				scheme := "unknown"
				if parsedScheme, _, _, _, err := parseMixedProxy(entry); err == nil && parsedScheme != "" {
					scheme = parsedScheme
				}
				settings, _ := mixedHealthSettingsForProtocolWithTier(scheme, 1)
				start := time.Now()
				status := checkMainstreamProxyHealthStage1WithHardTimeout(entry, settings)
				stageLatency := time.Since(start)
				mixedStageMetrics.AddStageResult(status.Scheme, "stage1", status.Healthy, status.ErrorCode, stageLatency)
				mu.Lock()
				st := getStageStats(status.Scheme)
				st.Total++
				if status.Healthy {
					st.Stage1Pass++
					stage1Candidates = append(stage1Candidates, entry)
					atomic.AddInt64(&stage1Pass, 1)
				} else {
					st.DropReason[string(status.Category)]++
					mixedHealthErrorCodeMetrics.Add(status.ErrorCode)
				}
				atomic.AddInt64(&stage1Checked, 1)
				mu.Unlock()
			}
		}()
	}
	for _, entry := range proxies {
		scheme := "unknown"
		if parsedScheme, _, _, _, err := parseMixedProxy(entry); err == nil && parsedScheme != "" {
			scheme = parsedScheme
		}
		mixedStageMetrics.AddInput(scheme)
		jobs <- entry
	}
	close(jobs)
	wg.Wait()
	close(stage1Done)

	log.Printf("[MIXED-2STAGE] stage1 complete: stage1_pass=%d/%d", len(stage1Candidates), len(proxies))
	if len(stage1Candidates) == 0 {
		protocols := make([]string, 0, len(stageStats))
		for scheme := range stageStats {
			protocols = append(protocols, scheme)
		}
		sort.Strings(protocols)
		for _, scheme := range protocols {
			st := stageStats[scheme]
			log.Printf("[MIXED-2STAGE] scheme=%s stage1_pass=%d stage2_pass=%d drop_reason=%v", scheme, st.Stage1Pass, st.Stage2Pass, st.DropReason)
			if st.Total > 0 && st.Stage1Pass == 0 {
				log.Printf("[MIXED-2STAGE-ROOTCAUSE] scheme=%s stage=stage1 top_causes=%s", scheme, summarizeTopRootCauses(st.DropReason, st.Total, 3))
			}
		}
		return MixedHealthCheckResult{}
	}

	mixedHealthy := make([]string, 0, len(stage1Candidates))
	cfPassHealthy := make([]string, 0)
	latencies := make([]time.Duration, 0, len(stage1Candidates))

	jobs2 := make(chan string, workerCount*4)
	wg = sync.WaitGroup{}
	var stage2Checked int64
	var stage2Pass int64
	stage2Done := make(chan struct{})
	go func(total int) {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		lastChecked := int64(0)
		for {
			select {
			case <-stage2Done:
				return
			case <-ticker.C:
				checked := atomic.LoadInt64(&stage2Checked)
				if checked == lastChecked {
					continue
				}
				lastChecked = checked
				progress := 0.0
				if total > 0 {
					progress = float64(checked) / float64(total) * 100
				}
				pass := atomic.LoadInt64(&stage2Pass)
				log.Printf("[MIXED-2STAGE] stage2 progress: %.1f%% (%d/%d), pass=%d", progress, checked, total, pass)
			}
		}
	}(len(stage1Candidates))
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs2 {
				scheme := "unknown"
				if parsedScheme, _, _, _, err := parseMixedProxy(entry); err == nil && parsedScheme != "" {
					scheme = parsedScheme
				}
				settings, _ := mixedHealthSettingsForProtocolWithTier(scheme, 2)
				result := checkMainstreamProxyHealthStage2(entry, strictMode, settings)
				mixedStageMetrics.AddStageResult(result.Status.Scheme, "stage2", result.Status.Healthy, result.Status.ErrorCode, result.Latency)
				mu.Lock()
				st := getStageStats(result.Status.Scheme)
				if result.Status.Healthy {
					st.Stage2Pass++
					mixedHealthy = append(mixedHealthy, entry)
					atomic.AddInt64(&stage2Pass, 1)
					latencies = append(latencies, result.Latency)
					if config.CFChallengeCheck.Enabled && mixedCFBypassChecker(entry) {
						cfPassHealthy = append(cfPassHealthy, entry)
					}
				} else {
					st.DropReason[string(result.Status.Category)]++
					mixedHealthErrorCodeMetrics.Add(result.Status.ErrorCode)
				}
				atomic.AddInt64(&stage2Checked, 1)
				mu.Unlock()
			}
		}()
	}
	for _, entry := range stage1Candidates {
		jobs2 <- entry
	}
	close(jobs2)
	wg.Wait()
	close(stage2Done)

	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		q := func(p float64) time.Duration {
			idx := int(float64(len(latencies)-1) * p)
			return latencies[idx]
		}
		totalLatency := time.Duration(0)
		for _, d := range latencies {
			totalLatency += d
		}
		avgLatency := totalLatency / time.Duration(len(latencies))
		log.Printf("[MIXED-2STAGE-LATENCY] count=%d p50=%s p90=%s p99=%s avg=%s", len(latencies), q(0.50), q(0.90), q(0.99), avgLatency)
	}

	protocols := make([]string, 0, len(stageStats))
	for scheme := range stageStats {
		protocols = append(protocols, scheme)
	}
	sort.Strings(protocols)
	for _, scheme := range protocols {
		st := stageStats[scheme]
		log.Printf("[MIXED-2STAGE] scheme=%s stage1_pass=%d stage2_pass=%d drop_reason=%v", scheme, st.Stage1Pass, st.Stage2Pass, st.DropReason)
		if st.Total > 0 && st.Stage1Pass == 0 {
			log.Printf("[MIXED-2STAGE-ROOTCAUSE] scheme=%s stage=stage1 top_causes=%s", scheme, summarizeTopRootCauses(st.DropReason, st.Total, 3))
		}
	}

	sort.Strings(cfPassHealthy)
	return MixedHealthCheckResult{Healthy: mixedHealthy, CFPass: cfPassHealthy}
}

func reorderMixedHealthCheckQueue(proxies []string) []string {
	if len(proxies) <= 2 {
		return proxies
	}

	type scored struct {
		entry string
		score uint64
	}

	scoredEntries := make([]scored, 0, len(proxies))
	for _, entry := range proxies {
		h := fnv.New64a()
		_, _ = h.Write([]byte(entry))
		scoredEntries = append(scoredEntries, scored{entry: entry, score: h.Sum64()})
	}

	sort.Slice(scoredEntries, func(i, j int) bool {
		if scoredEntries[i].score == scoredEntries[j].score {
			return scoredEntries[i].entry < scoredEntries[j].entry
		}
		return scoredEntries[i].score < scoredEntries[j].score
	})

	reordered := make([]string, 0, len(proxies))
	left := 0
	right := len(scoredEntries) - 1
	for left <= right {
		reordered = append(reordered, scoredEntries[left].entry)
		left++
		if left <= right {
			reordered = append(reordered, scoredEntries[right].entry)
			right--
		}
	}

	return reordered
}

func filterMixedProxiesByScheme(entries []string, allowed map[string]bool) []string {
	filtered := make([]string, 0, len(entries))
	for _, entry := range entries {
		scheme, _, _, _, err := parseMixedProxy(entry)
		if err != nil {
			continue
		}
		if allowed[scheme] {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func filterMixedProxiesByExcludedScheme(entries []string, excluded map[string]bool) []string {
	filtered := make([]string, 0, len(entries))
	for _, entry := range entries {
		scheme, _, _, _, err := parseMixedProxy(entry)
		if err != nil {
			continue
		}
		if !excluded[scheme] {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func mergeUniqueMixedEntries(base []string, extras []string) []string {
	merged := make([]string, 0, len(base)+len(extras))
	seen := make(map[string]bool, len(base)+len(extras))

	for _, entry := range base {
		if entry == "" || seen[entry] {
			continue
		}
		seen[entry] = true
		merged = append(merged, entry)
	}

	for _, entry := range extras {
		if entry == "" || seen[entry] {
			continue
		}
		seen[entry] = true
		merged = append(merged, entry)
	}

	return merged
}

func cloneProtocolIntMap(input map[string]int) map[string]int {
	if len(input) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func protocolHealthyCounts(entries []string) map[string]int {
	counts := make(map[string]int)
	for _, entry := range entries {
		scheme, _, _, _, err := parseMixedProxy(entry)
		if err != nil || strings.TrimSpace(scheme) == "" {
			scheme = detectProxyScheme(entry, "http")
		}
		scheme = strings.ToLower(strings.TrimSpace(scheme))
		if scheme == "" {
			scheme = "unknown"
		}
		counts[scheme]++
	}
	return counts
}

func evaluateMainstreamHealth(mainstreamHealthy []string) (string, []string) {
	counts := protocolHealthyCounts(mainstreamHealthy)
	tolerance := config.Alerting.ZeroMainstreamToleranceCycles
	if tolerance <= 0 {
		tolerance = 1
	}

	consecutiveZero := 0
	if len(mainstreamHealthy) == 0 {
		lastConsecutive, _, _, _ := runtimeHealth.Snapshot()
		consecutiveZero = lastConsecutive + 1
	}

	sloViolations := make(map[string]int)
	if config.ProtocolSLO.Enabled {
		for protocol, minimum := range config.ProtocolSLO.MinHealthy {
			normalized := strings.ToLower(strings.TrimSpace(protocol))
			if normalized == "" || minimum <= 0 {
				continue
			}
			if counts[normalized] < minimum {
				sloViolations[normalized] = minimum - counts[normalized]
			}
		}
	}

	reasons := make([]string, 0)
	highPriorityAlert := false
	if consecutiveZero > tolerance {
		highPriorityAlert = true
		reasons = append(reasons, fmt.Sprintf("P1 mainstream=0持续%d个周期(阈值>%d)", consecutiveZero, tolerance))
	}
	if len(sloViolations) > 0 {
		protocols := make([]string, 0, len(sloViolations))
		for p := range sloViolations {
			protocols = append(protocols, p)
		}
		sort.Strings(protocols)
		parts := make([]string, 0, len(protocols))
		for _, p := range protocols {
			parts = append(parts, fmt.Sprintf("%s缺口%d", p, sloViolations[p]))
		}
		reasons = append(reasons, "协议级SLO不达标: "+strings.Join(parts, ","))
	}

	runtimeHealth.Update(counts, consecutiveZero, sloViolations, highPriorityAlert)

	if highPriorityAlert {
		return "alert", reasons
	}
	if len(reasons) > 0 {
		return "degraded", reasons
	}
	return "ok", nil
}

func poolEntriesWithDefaultScheme(pool *ProxyPool, defaultScheme string) []string {
	entries := pool.GetAll()
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "://") {
			result = append(result, trimmed)
			continue
		}
		result = append(result, defaultScheme+"://"+trimmed)
	}
	return result
}

func updateMixedProxyPool(mixedPool *ProxyPool, mainstreamMixedPool *ProxyPool, cfMixedPool *ProxyPool, strictPool *ProxyPool, relaxedPool *ProxyPool) {
	if !atomic.CompareAndSwapInt32(&mixedPool.updating, 0, 1) {
		log.Println("Mixed proxy update already in progress, skipping...")
		return
	}
	defer atomic.StoreInt32(&mixedPool.updating, 0)

	log.Println("Fetching mixed proxy list...")
	allHealthy := make([]string, 0)
	allCFPass := make([]string, 0)

	err := fetchAndProcessMixedProxyBatches(healthCheckBatchSize, func(batch []string) {
		log.Printf("Processing mixed health check batch: size=%d", len(batch))
		result := healthCheckMixedProxies(batch)
		allHealthy = append(allHealthy, result.Healthy...)
		allCFPass = append(allCFPass, result.CFPass...)
	})
	if err != nil {
		log.Printf("Error fetching mixed proxy list: %v", err)
		return
	}

	result := MixedHealthCheckResult{Healthy: allHealthy, CFPass: allCFPass}
	log.Printf("Streaming mixed health check complete: healthy=%d cf_pass=%d", len(result.Healthy), len(result.CFPass))

	httpSocksHealthy := filterMixedProxiesByScheme(result.Healthy, httpSocksMixedSchemes)
	mainstreamHealthy := filterMixedProxiesByExcludedScheme(result.Healthy, mainstreamMixedExcludedSchemes)
	strictAsMixed := poolEntriesWithDefaultScheme(strictPool, "http")
	relaxedAsMixed := poolEntriesWithDefaultScheme(relaxedPool, "http")
	httpSocksCombined := mergeUniqueMixedEntries(httpSocksHealthy, append(strictAsMixed, relaxedAsMixed...))
	log.Printf("[MIXED] Health check split result: total_healthy=%d http_socks=%d mainstream=%d strict_imported=%d relaxed_imported=%d combined_http_socks=%d",
		len(result.Healthy), len(httpSocksHealthy), len(mainstreamHealthy), len(strictAsMixed), len(relaxedAsMixed), len(httpSocksCombined))

	if len(httpSocksCombined) > 0 {
		mixedPool.Update(httpSocksCombined)
		log.Printf("[HTTP-MIXED] Pool updated with %d proxies (mixed http/socks + strict/relaxed imports)", len(httpSocksCombined))
	} else {
		log.Println("[HTTP-MIXED] Warning: No mixed HTTP/HTTPS/SOCKS proxies and no strict/relaxed imports found, keeping existing pool")
	}

	if len(mainstreamHealthy) > 0 {
		mainstreamMixedPool.Update(mainstreamHealthy)
		log.Printf("[HTTP-MAINSTREAM-MIXED] Pool updated with %d healthy non-http/socks5 mixed proxies", len(mainstreamHealthy))
	} else {
		log.Println("[HTTP-MAINSTREAM-MIXED] Warning: No healthy non-http/socks5 mixed proxies found, keeping existing pool")
	}

	updateStatus, healthReasons := evaluateMainstreamHealth(mainstreamHealthy)
	if updateStatus == "alert" {
		log.Printf("[ALERT][P1][MAINSTREAM] %s", strings.Join(healthReasons, "; "))
	} else if updateStatus == "degraded" {
		log.Printf("[DEGRADED][MAINSTREAM] %s", strings.Join(healthReasons, "; "))
	}

	if config.CFChallengeCheck.Enabled {
		if len(result.CFPass) > 0 {
			cfMixedPool.Update(result.CFPass)
			log.Printf("[HTTP-CF-MIXED] Pool updated with %d CF-pass mixed proxies", len(result.CFPass))
		} else {
			log.Println("[HTTP-CF-MIXED] Warning: No CF-pass mixed proxies found, keeping existing pool")
		}
	}

	if len(healthReasons) == 0 {
		adminRuntime.MarkUpdated(updateStatus)
	} else {
		adminRuntime.MarkUpdated(updateStatus + ": " + strings.Join(healthReasons, "; "))
	}
}

func startProxyUpdater(ctx context.Context, strictPool *ProxyPool, relaxedPool *ProxyPool, cfPool *ProxyPool, mixedPool *ProxyPool, mainstreamMixedPool *ProxyPool, cfMixedPool *ProxyPool, initialSync bool) {
	if initialSync {
		// Initial update synchronously to ensure we have proxies before starting servers
		log.Println("Performing initial proxy update...")
		updateProxyPool(strictPool, relaxedPool, cfPool)
		updateMixedProxyPool(mixedPool, mainstreamMixedPool, cfMixedPool, strictPool, relaxedPool)
	}

	// Periodic updates - each update runs in its own goroutine to avoid blocking
	updateInterval := time.Duration(config.UpdateIntervalMinutes) * time.Minute
	go func() {
		ticker := time.NewTicker(updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("[UPDATER] Proxy updater stopped: %v", ctx.Err())
				return
			case <-ticker.C:
				go updateProxyPool(strictPool, relaxedPool, cfPool)
				go updateMixedProxyPool(mixedPool, mainstreamMixedPool, cfMixedPool, strictPool, relaxedPool)
			}
		}
	}()
}

// SOCKS5 Proxy Server
type CustomDialer struct {
	pool *ProxyPool
	mode string // "STRICT" or "RELAXED"
}

// LoggedConn wraps a net.Conn to log when it's closed
type LoggedConn struct {
	net.Conn
	addr       string
	proxyAddr  string
	closed     atomic.Bool
	bytesRead  int64
	bytesWrite int64
}

func (c *LoggedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		log.Printf("[SOCKS5] Connection closed: %s via proxy %s (read: %d bytes, wrote: %d bytes)",
			c.addr, c.proxyAddr, c.bytesRead, c.bytesWrite)
	}
	return c.Conn.Close()
}

func (c *LoggedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.bytesRead, int64(n))
	}
	if err != nil && err != io.EOF {
		log.Printf("[SOCKS5] Read error for %s via proxy %s after %d bytes: %v",
			c.addr, c.proxyAddr, c.bytesRead, err)
	}
	return n, err
}

func (c *LoggedConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.bytesWrite, int64(n))
	}
	if err != nil {
		log.Printf("[SOCKS5] Write error for %s via proxy %s after %d bytes: %v",
			c.addr, c.proxyAddr, c.bytesWrite, err)
	}
	return n, err
}

func (d *CustomDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	log.Printf("[SOCKS5-%s] Incoming request: %s -> %s", d.mode, network, addr)

	proxyAddr, err := d.pool.GetNext()
	if err != nil {
		log.Printf("[SOCKS5-%s] ERROR: No proxy available for %s: %v", d.mode, addr, err)
		return nil, err
	}

	log.Printf("[SOCKS5-%s] Using proxy %s for %s", d.mode, proxyAddr, addr)

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Printf("[SOCKS5-%s] ERROR: Failed to create dialer for proxy %s: %v", d.mode, proxyAddr, err)
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.Dial(network, addr)
	if err != nil {
		log.Printf("[SOCKS5-%s] ERROR: Failed to connect to %s via proxy %s: %v", d.mode, addr, proxyAddr, err)
		return nil, fmt.Errorf("failed to dial through proxy %s: %w", proxyAddr, err)
	}

	log.Printf("[SOCKS5-%s] SUCCESS: Connected to %s via proxy %s", d.mode, addr, proxyAddr)

	// Wrap the connection to log read/write errors and close events
	loggedConn := &LoggedConn{
		Conn:      conn,
		addr:      addr,
		proxyAddr: proxyAddr,
	}

	return loggedConn, nil
}

func startSOCKS5Server(pool *ProxyPool, port string, mode string) error {
	// Create a custom logger with mode-specific prefix
	socks5Logger := log.New(log.Writer(), fmt.Sprintf("[SOCKS5-%s-LIB] ", mode), log.LstdFlags)

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &CustomDialer{pool: pool, mode: mode}
			return dialer.Dial(ctx, network, addr)
		},
		Logger: socks5Logger,
	}

	if isProxyAuthEnabled() {
		conf.Credentials = socks5.StaticCredentials{
			config.Auth.Username: config.Auth.Password,
		}
		conf.AuthMethods = []socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: conf.Credentials}}
		log.Printf("[%s] SOCKS5 authentication enabled", mode)
	}

	server, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 server: %w", err)
	}

	log.Printf("[%s] SOCKS5 proxy server listening on %s", mode, port)
	return server.ListenAndServe("tcp", port)
}

// HTTP Proxy Server
func rotatePoolOnUpstreamFailure(pool *ProxyPool, mode string, failedProxy string, reason error) {
	if pool == nil || failedProxy == "" {
		return
	}

	newProxy, rotated, err := pool.ForceRotateIfCurrent(failedProxy)
	if err != nil {
		log.Printf("[AUTO-ROTATE-%s] on-failure rotate failed for %s: %v (trigger=%v)", mode, failedProxy, err, reason)
		return
	}
	if !rotated {
		return
	}
	if newProxy == failedProxy {
		log.Printf("[AUTO-ROTATE-%s] on-failure rotate skipped, only one proxy available (%s)", mode, failedProxy)
		return
	}

	log.Printf("[AUTO-ROTATE-%s] on-failure rotate switched from %s to %s (trigger=%v)", mode, failedProxy, newProxy, reason)
}

func selectProxyWithBreaker(pool *ProxyPool, fallbackPool *ProxyPool) (string, error) {
	if pool == nil {
		return "", fmt.Errorf("no primary pool")
	}
	tries := len(pool.GetAll())
	if tries <= 0 {
		tries = 1
	}
	for i := 0; i < tries; i++ {
		candidate, err := pool.GetNext()
		if err != nil {
			break
		}
		scheme, _, _, _, parseErr := parseMixedProxy(candidate)
		if parseErr != nil {
			scheme = "unknown"
		}
		if adapterBreaker.Allow(scheme, candidate) {
			return candidate, nil
		}
		_, _, _ = pool.ForceRotateIfCurrent(candidate)
	}
	if fallbackPool != nil {
		fallbackProxy, fallbackErr := fallbackPool.GetNext()
		if fallbackErr == nil {
			return fallbackProxy, nil
		}
	}
	return "", fmt.Errorf("no available proxies after breaker filtering")
}

func writePoolListResponse(w http.ResponseWriter, pool *ProxyPool, fallbackPool *ProxyPool, mode string) {
	payload := map[string]interface{}{
		"mode":     mode,
		"proxies":  pool.GetAll(),
		"count":    len(pool.GetAll()),
		"fallback": nil,
	}
	if current, ok := pool.GetCurrent(); ok {
		payload["current"] = current
	}
	if fallbackPool != nil {
		fallbackProxies := fallbackPool.GetAll()
		payload["fallback"] = map[string]interface{}{
			"count":   len(fallbackProxies),
			"proxies": fallbackProxies,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func resolveConnectTarget(r *http.Request) (string, error) {
	target := strings.TrimSpace(r.Host)
	if target == "" {
		target = strings.TrimSpace(r.URL.Host)
	}
	if target == "" {
		target = strings.TrimSpace(r.URL.Opaque)
	}
	if target == "" {
		return "", fmt.Errorf("empty target")
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	return target, nil
}

func handleHTTPProxy(w http.ResponseWriter, r *http.Request, pool *ProxyPool, fallbackPool *ProxyPool, mode string) {
	if r.URL.Path == "/list" {
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "HTTP-"+mode)
			return
		}
		writePoolListResponse(w, pool, fallbackPool, mode)
		return
	}

	log.Printf("[HTTP-%s] Incoming request: %s %s from %s", mode, r.Method, r.URL.String(), r.RemoteAddr)

	if !validateHTTPProxyAuth(r) {
		requireHTTPProxyAuth(w, mode)
		return
	}

	proxyAddr, err := selectProxyWithBreaker(pool, fallbackPool)
	if err != nil {
		log.Printf("[HTTP-%s] ERROR: No proxy available for %s %s: %v", mode, r.Method, r.URL.String(), err)
		if mode == "MAINSTREAM-MIXED" && config.MainstreamMixed.DegradeStrategy == "explicit_error" {
			http.Error(w, config.MainstreamMixed.ExplicitErrorMessage, http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "No available proxies", http.StatusServiceUnavailable)
		return
	}

	log.Printf("[HTTP-%s] Using proxy %s for %s %s", mode, proxyAddr, r.Method, r.URL.String())

	upstreamDialer, upstreamScheme, err := buildUpstreamDialer(proxyAddr)
	if err != nil {
		log.Printf("[HTTP-%s] ERROR: Unsupported upstream proxy %s: %v", mode, proxyAddr, err)
		rotatePoolOnUpstreamFailure(pool, mode, proxyAddr, err)
		http.Error(w, "Unsupported upstream proxy", http.StatusBadGateway)
		return
	}

	if r.Method == http.MethodConnect {
		targetHost, targetErr := resolveConnectTarget(r)
		if targetErr != nil {
			log.Printf("[HTTP-%s] ERROR: Invalid CONNECT target %q: %v", mode, r.URL.String(), targetErr)
			http.Error(w, "Invalid CONNECT target", http.StatusBadRequest)
			return
		}

		handleHTTPSProxy(w, r, targetHost, func(target string) (net.Conn, error) {
			return upstreamDialer.DialContext(r.Context(), "tcp", target)
		}, pool, proxyAddr, mode)
		return
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: upstreamDialer.DialContext,
	}
	defer transport.CloseIdleConnections()
	if upstreamScheme == "http" || upstreamScheme == "https" {
		transport.Proxy = nil
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		if strings.EqualFold(key, "Proxy-Authorization") {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	var resp *http.Response
	var lastErr error
	for attempt := 1; attempt <= requestForwardMaxRetries; attempt++ {
		resp, err = client.Do(proxyReq)
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		if attempt < requestForwardMaxRetries {
			time.Sleep(retryBackoff(attempt))
		}
	}
	if lastErr != nil {
		log.Printf("[HTTP-%s] ERROR: Request failed for %s: %v", mode, r.URL.String(), err)
		adapterMetrics.IncRetryExhausted()
		adapterBreaker.RecordFailure(upstreamScheme, proxyAddr)
		rotatePoolOnUpstreamFailure(pool, mode, proxyAddr, err)
		http.Error(w, fmt.Sprintf("Proxy request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	adapterBreaker.RecordSuccess(upstreamScheme, proxyAddr)

	log.Printf("[HTTP-%s] SUCCESS: Got response %d for %s", mode, resp.StatusCode, r.URL.String())

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[proxy_error] mode=%s proxyAddr=%s target=%s method=%s error=%v", mode, proxyAddr, r.URL.String(), r.Method, err)
	}
}

func handleHTTPSProxy(w http.ResponseWriter, r *http.Request, targetHost string, targetDial func(string) (net.Conn, error), pool *ProxyPool, proxyAddr string, mode string) {
	log.Printf("[HTTPS-%s] Connecting to %s via proxy %s", mode, targetHost, proxyAddr)
	const tunnelIdleTimeout = 90 * time.Second

	// Connect to target through upstream proxy
	targetConn, err := targetDial(targetHost)
	if err != nil {
		log.Printf("[HTTPS-%s] ERROR: Failed to connect to %s via proxy %s: %v", mode, targetHost, proxyAddr, err)
		rotatePoolOnUpstreamFailure(pool, mode, proxyAddr, err)
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[HTTPS-%s] ERROR: Hijacking not supported for %s", mode, targetHost)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[HTTPS-%s] ERROR: Failed to hijack connection for %s: %v", mode, targetHost, err)
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("[proxy_error] mode=%s proxyAddr=%s target=%s method=%s error=%v", mode, proxyAddr, targetHost, r.Method, err)
		return
	}
	log.Printf("[HTTPS-%s] SUCCESS: Tunnel established to %s via proxy %s", mode, targetHost, proxyAddr)
	if err := clientConn.SetDeadline(time.Now().Add(tunnelIdleTimeout)); err != nil {
		log.Printf("[HTTPS-%s] WARN: Failed to set initial client deadline for %s: %v", mode, targetHost, err)
	}
	if err := targetConn.SetDeadline(time.Now().Add(tunnelIdleTimeout)); err != nil {
		log.Printf("[HTTPS-%s] WARN: Failed to set initial target deadline for %s: %v", mode, targetHost, err)
	}

	type copyResult struct {
		direction string
		bytes     int64
		err       error
	}

	copyWithDeadline := func(dst net.Conn, src net.Conn) (int64, error) {
		buf := make([]byte, 32*1024)
		var total int64
		for {
			if err := src.SetReadDeadline(time.Now().Add(tunnelIdleTimeout)); err != nil {
				return total, fmt.Errorf("set read deadline: %w", err)
			}
			n, readErr := src.Read(buf)
			if n > 0 {
				if err := dst.SetWriteDeadline(time.Now().Add(tunnelIdleTimeout)); err != nil {
					return total, fmt.Errorf("set write deadline: %w", err)
				}
				written, writeErr := dst.Write(buf[:n])
				total += int64(written)
				if writeErr != nil {
					return total, writeErr
				}
				if written != n {
					return total, io.ErrShortWrite
				}
			}

			if readErr != nil {
				return total, readErr
			}
		}
	}

	closeWrite := func(conn net.Conn, side string) {
		type closeWriter interface{ CloseWrite() error }
		if cw, ok := conn.(closeWriter); ok {
			if err := cw.CloseWrite(); err != nil {
				log.Printf("[HTTPS-%s] WARN: CloseWrite failed on %s for %s: %v", mode, side, targetHost, err)
			}
			return
		}
		if err := conn.Close(); err != nil {
			log.Printf("[HTTPS-%s] WARN: Close failed on %s for %s: %v", mode, side, targetHost, err)
		}
	}

	resultCh := make(chan copyResult, 2)
	go func() {
		bytes, err := copyWithDeadline(targetConn, clientConn)
		resultCh <- copyResult{direction: "client->target", bytes: bytes, err: err}
	}()
	go func() {
		bytes, err := copyWithDeadline(clientConn, targetConn)
		resultCh <- copyResult{direction: "target->client", bytes: bytes, err: err}
	}()

	for i := 0; i < 2; i++ {
		result := <-resultCh
		reason := "completed"
		if result.err != nil {
			reason = result.err.Error()
			log.Printf("[proxy_error] mode=%s proxyAddr=%s target=%s method=%s error=%v direction=%s", mode, proxyAddr, targetHost, r.Method, result.err, result.direction)
		}
		log.Printf("[HTTPS-%s] tunnel copy finished %s for %s via %s bytes=%d reason=%s", mode, result.direction, targetHost, proxyAddr, result.bytes, reason)
		if i == 0 {
			if result.direction == "client->target" {
				closeWrite(targetConn, "target")
			} else {
				closeWrite(clientConn, "client")
			}
		}
	}
}

func dialTargetThroughHTTPProxy(ctx context.Context, proxyScheme string, proxyAddr string, proxyAuthHeader string, targetHost string) (net.Conn, error) {
	connectAddr := proxyAddr
	if !strings.Contains(connectAddr, ":") {
		if proxyScheme == "https" {
			connectAddr += ":443"
		} else {
			connectAddr += ":80"
		}
	}

	var conn net.Conn
	var err error
	dialer := &net.Dialer{}
	if proxyScheme == "https" {
		if deadline, ok := ctx.Deadline(); ok {
			dialer.Deadline = deadline
		} else {
			dialer.Timeout = 10 * time.Second
		}
		rawConn, dialErr := dialer.DialContext(ctx, "tcp", connectAddr)
		if dialErr != nil {
			return nil, dialErr
		}
		host, _, splitErr := net.SplitHostPort(connectAddr)
		if splitErr != nil {
			host = connectAddr
		}
		tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		conn = tlsConn
	} else {
		if deadline, ok := ctx.Deadline(); ok {
			dialer.Deadline = deadline
		} else {
			dialer.Timeout = 10 * time.Second
		}
		conn, err = dialer.DialContext(ctx, "tcp", connectAddr)
	}
	if err != nil {
		return nil, err
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetHost},
		Host:   targetHost,
		Header: make(http.Header),
	}
	if proxyAuthHeader != "" {
		connectReq.Header.Set("Proxy-Authorization", proxyAuthHeader)
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("http proxy CONNECT failed with status %s", resp.Status)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	return conn, nil
}

func startHTTPServer(pool *ProxyPool, fallbackPool *ProxyPool, port string, mode string) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleHTTPProxy(w, r, pool, fallbackPool, mode)
	})

	server := &http.Server{
		Addr:    port,
		Handler: handler,
	}

	log.Printf("[%s] HTTP proxy server listening on %s", mode, port)
	return server.ListenAndServe()
}

func startRotateControlServer(strictPool *ProxyPool, relaxedPool *ProxyPool, cfPool *ProxyPool, mixedPool *ProxyPool, mainstreamMixedPool *ProxyPool, cfMixedPool *ProxyPool, port string) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "ROTATE")
			return
		}

		switch r.URL.Path {
		case "/", "/rotate":
			strictProxy, strictErr := strictPool.ForceRotate()
			relaxedProxy, relaxedErr := relaxedPool.ForceRotate()
			mixedProxy, mixedErr := mixedPool.ForceRotate()
			mainstreamProxy, mainstreamErr := mainstreamMixedPool.ForceRotate()
			cfMixedProxy, cfMixedErr := cfMixedPool.ForceRotate()

			if strictErr != nil && relaxedErr != nil && mixedErr != nil && mainstreamErr != nil && cfMixedErr != nil {
				log.Printf("[ROTATE] ERROR: rotate failed (strict=%v, relaxed=%v, mixed=%v, mainstream=%v, cf_mixed=%v)", strictErr, relaxedErr, mixedErr, mainstreamErr, cfMixedErr)
				http.Error(w, "Rotate failed: no available proxies", http.StatusServiceUnavailable)
				return
			}

			log.Printf("[ROTATE] Manual rotate triggered from %s | strict=%s err=%v | relaxed=%s err=%v | mixed=%s err=%v | mainstream=%s err=%v | cf_mixed=%s err=%v",
				r.RemoteAddr, strictProxy, strictErr, relaxedProxy, relaxedErr, mixedProxy, mixedErr, mainstreamProxy, mainstreamErr, cfMixedProxy, cfMixedErr)

			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "rotate success\nstrict: %s\nrelaxed: %s\nmixed: %s\nmainstream: %s\ncf_mixed: %s\n", strictProxy, relaxedProxy, mixedProxy, mainstreamProxy, cfMixedProxy)
		case "/cf-proxies":
			proxies := cfPool.GetAll()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "cf_pass_proxy_count: %d\n", len(proxies))
			for _, proxyAddr := range proxies {
				fmt.Fprintln(w, proxyAddr)
			}
		case "/list":
			strictProxies := strictPool.GetAll()
			relaxedProxies := relaxedPool.GetAll()
			cfProxies := cfPool.GetAll()
			mixedProxies := mixedPool.GetAll()
			mainstreamProxies := mainstreamMixedPool.GetAll()
			cfMixedProxies := cfMixedPool.GetAll()
			strictCurrent, _ := strictPool.GetCurrent()
			relaxedCurrent, _ := relaxedPool.GetCurrent()
			mixedCurrent, _ := mixedPool.GetCurrent()
			mainstreamCurrent, _ := mainstreamMixedPool.GetCurrent()
			cfMixedCurrent, _ := cfMixedPool.GetCurrent()

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"strict_proxy_count":       len(strictProxies),
				"strict_current_proxy":     strictCurrent,
				"relaxed_proxy_count":      len(relaxedProxies),
				"relaxed_current_proxy":    relaxedCurrent,
				"cf_proxy_count":           len(cfProxies),
				"mixed_proxy_count":        len(mixedProxies),
				"mixed_current_proxy":      mixedCurrent,
				"mainstream_proxy_count":   len(mainstreamProxies),
				"mainstream_current_proxy": mainstreamCurrent,
				"cf_mixed_proxy_count":     len(cfMixedProxies),
				"cf_mixed_current_proxy":   cfMixedCurrent,
				"error_code_counts":        mixedHealthErrorCodeMetrics.Snapshot(),
			})
		default:
			http.NotFound(w, r)
		}
	})

	server := &http.Server{
		Addr:    port,
		Handler: handler,
	}

	log.Printf("[ROTATE] Manual rotate control server listening on %s", port)
	return server.ListenAndServe()
}

func buildPoolStatusPayload(strictPool *ProxyPool, relaxedPool *ProxyPool, cfPool *ProxyPool, mixedPool *ProxyPool, mainstreamMixedPool *ProxyPool, cfMixedPool *ProxyPool, port string) map[string]interface{} {
	strictProxies := strictPool.GetAll()
	relaxedProxies := relaxedPool.GetAll()
	cfProxies := cfPool.GetAll()
	mixedProxies := mixedPool.GetAll()
	mainstreamProxies := mainstreamMixedPool.GetAll()
	cfMixedProxies := cfMixedPool.GetAll()

	strictCurrent, _ := strictPool.GetCurrent()
	relaxedCurrent, _ := relaxedPool.GetCurrent()
	cfCurrent, _ := cfPool.GetCurrent()
	mixedCurrent, _ := mixedPool.GetCurrent()
	mainstreamCurrent, _ := mainstreamMixedPool.GetCurrent()
	cfMixedCurrent, _ := cfMixedPool.GetCurrent()

	allHealthyProxies := mergeUniqueMixedEntries(strictProxies, relaxedProxies)
	allHealthyProxies = mergeUniqueMixedEntries(allHealthyProxies, mixedProxies)
	allHealthyProxies = mergeUniqueMixedEntries(allHealthyProxies, mainstreamProxies)
	allHealthyProxies = mergeUniqueMixedEntries(allHealthyProxies, cfProxies)
	allHealthyProxies = mergeUniqueMixedEntries(allHealthyProxies, cfMixedProxies)
	protocolCounts := protocolHealthyCounts(allHealthyProxies)
	mainstreamProtocolCounts := protocolHealthyCounts(mainstreamProxies)
	mainstreamZeroCycles, _, sloViolations, highPriorityAlert := runtimeHealth.Snapshot()

	return map[string]interface{}{
		"strict_proxy_count":                 len(strictProxies),
		"strict_current_proxy":               strictCurrent,
		"strict_proxies":                     strictProxies,
		"relaxed_proxy_count":                len(relaxedProxies),
		"relaxed_current_proxy":              relaxedCurrent,
		"relaxed_proxies":                    relaxedProxies,
		"cf_proxy_count":                     len(cfProxies),
		"cf_current_proxy":                   cfCurrent,
		"cf_proxies":                         cfProxies,
		"http_socks_proxy_count":             len(mixedProxies),
		"http_socks_current_proxy":           mixedCurrent,
		"http_socks_proxies":                 mixedProxies,
		"mainstream_proxy_count":             len(mainstreamProxies),
		"mainstream_current_proxy":           mainstreamCurrent,
		"mainstream_proxies":                 mainstreamProxies,
		"cf_mixed_proxy_count":               len(cfMixedProxies),
		"cf_mixed_current_proxy":             cfMixedCurrent,
		"cf_mixed_proxies":                   cfMixedProxies,
		"all_healthy_proxy_count":            len(allHealthyProxies),
		"all_healthy_proxies":                allHealthyProxies,
		"protocol_healthy_counts":            protocolCounts,
		"mainstream_protocol_healthy_counts": mainstreamProtocolCounts,
		"mainstream_zero_cycles":             mainstreamZeroCycles,
		"protocol_slo_violations":            sloViolations,
		"high_priority_alert":                highPriorityAlert,
		"mainstream_listen_port":             config.Ports.HTTPMainstreamMix,
		"status_listen_addr":                 port,
		"mainstream_excluded_protocols":      []string{"http", "https", "socks5", "socks5h"},
		"error_code_counts":                  mixedHealthErrorCodeMetrics.Snapshot(),
	}
}

type ProxyRow struct {
	Address   string `json:"address"`
	Protocol  string `json:"protocol"`
	Pool      string `json:"pool"`
	LatencyMS int    `json:"latency_ms"`
	Current   bool   `json:"current"`
}

func splitProxyEntry(entry string) (protocol string, address string) {
	trimmed := strings.TrimSpace(entry)
	if trimmed == "" {
		return "unknown", ""
	}
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return "unknown", trimmed
		}
		host := u.Host
		if host == "" {
			host = strings.TrimPrefix(trimmed, u.Scheme+"://")
		}
		return strings.ToLower(u.Scheme), host
	}
	return "http", trimmed
}

func rowsFromPool(poolName string, pool *ProxyPool) []ProxyRow {
	entries := pool.GetAll()
	current, _ := pool.GetCurrent()
	out := make([]ProxyRow, 0, len(entries))
	for _, entry := range entries {
		protocol, address := splitProxyEntry(entry)
		out = append(out, ProxyRow{Address: address, Protocol: protocol, Pool: poolName, LatencyMS: 0, Current: current == entry})
	}
	return out
}

func triggerRotateControlAll() (string, error) {
	rotateAddr := config.Ports.RotateControl
	if !strings.HasPrefix(rotateAddr, ":") {
		if !strings.Contains(rotateAddr, ":") {
			rotateAddr = ":" + rotateAddr
		}
	}
	endpoint := "http://127.0.0.1" + rotateAddr + "/rotate"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if isProxyAuthEnabled() {
		req.SetBasicAuth(config.Auth.Username, config.Auth.Password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return string(body), fmt.Errorf("rotate control status=%d", resp.StatusCode)
	}
	return string(body), nil
}

func buildStageFunnelByProtocol() map[string]map[string]int64 {
	snapshot := mixedStageMetrics.Snapshot()
	inputRaw, _ := snapshot["input"].(map[string]int64)
	passRaw, _ := snapshot["pass"].(map[string]map[string]int64)
	funnel := make(map[string]map[string]int64, len(inputRaw))
	for protocol, input := range inputRaw {
		stage1 := int64(0)
		stage2 := int64(0)
		if stages, ok := passRaw[protocol]; ok {
			stage1 = stages["stage1"]
			stage2 = stages["stage2"]
		}
		funnel[protocol] = map[string]int64{"input": input, "stage1": stage1, "stage2": stage2}
	}
	return funnel
}

func mergedMetricsPayload() map[string]interface{} {
	payload := map[string]interface{}{
		"error_code_counts": mixedHealthErrorCodeMetrics.Snapshot(),
		"stage_metrics":     mixedStageMetrics.Snapshot(),
	}
	for k, v := range adapterMetrics.Snapshot() {
		payload[k] = v
	}
	return payload
}

func startPoolStatusServer(strictPool *ProxyPool, relaxedPool *ProxyPool, cfPool *ProxyPool, mixedPool *ProxyPool, mainstreamMixedPool *ProxyPool, cfMixedPool *ProxyPool, port string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-ADMIN")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(adminPanelHTML))
	})

	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-LIST")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(buildPoolStatusPayload(strictPool, relaxedPool, cfPool, mixedPool, mainstreamMixedPool, cfMixedPool, port))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-METRICS")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(mergedMetricsPayload())
	})

	mux.HandleFunc("/metrics/prometheus", func(w http.ResponseWriter, r *http.Request) {
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-METRICS")
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(mixedStageMetrics.RenderPrometheus()))
	})

	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-OVERVIEW")
			return
		}
		payload := buildPoolStatusPayload(strictPool, relaxedPool, cfPool, mixedPool, mainstreamMixedPool, cfMixedPool, port)
		lastUpdate, lastHealth, status := adminRuntime.Snapshot()
		allHealthyCount := payload["all_healthy_proxy_count"]
		out := map[string]interface{}{
			"strict":                      map[string]interface{}{"available": payload["strict_proxy_count"]},
			"relaxed":                     map[string]interface{}{"available": payload["relaxed_proxy_count"]},
			"mixed":                       map[string]interface{}{"available": payload["http_socks_proxy_count"]},
			"mainstream":                  map[string]interface{}{"available": payload["mainstream_proxy_count"]},
			"all_healthy":                 allHealthyCount,
			"protocol_healthy_counts":     payload["protocol_healthy_counts"],
			"protocol_slo_violations":     payload["protocol_slo_violations"],
			"high_priority_alert":         payload["high_priority_alert"],
			"last_update_status":          status,
			"mixed_stage_funnel_by_proto": buildStageFunnelByProtocol(),
		}
		if !lastUpdate.IsZero() {
			out["last_update_time"] = lastUpdate.Format(time.RFC3339)
		}
		if !lastHealth.IsZero() {
			out["last_health_check_time"] = lastHealth.Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/proxies", func(w http.ResponseWriter, r *http.Request) {
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-PROXIES")
			return
		}
		items := make([]ProxyRow, 0)
		items = append(items, rowsFromPool("strict", strictPool)...)
		items = append(items, rowsFromPool("relaxed", relaxedPool)...)
		items = append(items, rowsFromPool("cf", cfPool)...)
		items = append(items, rowsFromPool("mixed", mixedPool)...)
		items = append(items, rowsFromPool("mainstream", mainstreamMixedPool)...)
		items = append(items, rowsFromPool("cf_mixed", cfMixedPool)...)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-CONFIG")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"update_interval_minutes":   config.UpdateIntervalMinutes,
			"health_check_concurrency":  config.HealthCheckConcurrency,
			"proxy_switch_interval_min": config.ProxySwitchIntervalMin,
			"mainstream_mixed":          config.MainstreamMixed,
			"protocol_slo":              config.ProtocolSLO,
			"alerting":                  config.Alerting,
			"ports":                     config.Ports,
			"auth_enabled":              isProxyAuthEnabled(),
		})
	})

	mux.HandleFunc("/api/diagnostics/diff-probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-DIFF-PROBE")
			return
		}
		report, err := runDifferentialProbeReport()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(report)
	})

	mux.HandleFunc("/api/actions/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-REFRESH")
			return
		}
		go updateProxyPool(strictPool, relaxedPool, cfPool)
		go updateMixedProxyPool(mixedPool, mainstreamMixedPool, cfMixedPool, strictPool, relaxedPool)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "message": "refresh triggered"})
	})

	mux.HandleFunc("/api/actions/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateBasicAuth(r) {
			requireBasicAuth(w, "STATUS-ROTATE")
			return
		}
		var req struct {
			Pool string `json:"pool"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Pool == "" {
			req.Pool = "all"
		}
		result := map[string]string{}
		rotateOne := func(name string, pool *ProxyPool) {
			proxyAddr, err := pool.ForceRotate()
			if err != nil {
				result[name] = "error: " + err.Error()
				return
			}
			result[name] = proxyAddr
		}
		switch req.Pool {
		case "all":
			body, err := triggerRotateControlAll()
			if err != nil {
				result["all"] = "error: " + err.Error() + " body=" + body
			} else {
				result["all"] = body
			}
		case "strict":
			rotateOne("strict", strictPool)
		case "relaxed":
			rotateOne("relaxed", relaxedPool)
		case "mixed":
			rotateOne("mixed", mixedPool)
		case "mainstream":
			rotateOne("mainstream", mainstreamMixedPool)
		case "cf_mixed":
			rotateOne("cf_mixed", cfMixedPool)
		default:
			http.Error(w, "invalid pool", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "pool": req.Pool, "result": result})
	})

	server := &http.Server{Addr: port, Handler: mux}
	log.Printf("[STATUS] Admin panel + status API listening on %s", port)
	return server.ListenAndServe()
}

func startProxyConnectivityMonitor(ctx context.Context, pool *ProxyPool, mode string, interval time.Duration, checker func(string) bool) {
	if interval <= 0 {
		interval = connectivityCheckInterval
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("[AUTO-ROTATE-%s] connectivity monitor stopped: %v", mode, ctx.Err())
				return
			case <-ticker.C:
				proxyAddr, ok := pool.GetCurrent()
				if !ok {
					continue
				}

				if checker(proxyAddr) {
					continue
				}

				newProxy, err := pool.ForceRotate()
				if err != nil {
					log.Printf("[AUTO-ROTATE-%s] connectivity check failed for %s, but rotate failed: %v", mode, proxyAddr, err)
					continue
				}

				if newProxy == proxyAddr {
					log.Printf("[AUTO-ROTATE-%s] connectivity check failed for %s, only one proxy available", mode, proxyAddr)
					continue
				}

				log.Printf("[AUTO-ROTATE-%s] connectivity check failed for %s, rotated to %s", mode, proxyAddr, newProxy)
			}
		}
	}()
}

func startProxyIntervalRotate(ctx context.Context, pool *ProxyPool, mode string, interval time.Duration) {
	if interval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("[AUTO-ROTATE-%s] interval rotate stopped: %v", mode, ctx.Err())
				return
			case <-ticker.C:
				proxyAddr, ok := pool.GetCurrent()
				if !ok {
					continue
				}

				newProxy, err := pool.ForceRotate()
				if err != nil {
					log.Printf("[AUTO-ROTATE-%s] periodic rotate failed for %s: %v", mode, proxyAddr, err)
					continue
				}

				if newProxy == proxyAddr {
					log.Printf("[AUTO-ROTATE-%s] periodic rotate skipped, only one proxy available (%s)", mode, proxyAddr)
					continue
				}

				log.Printf("[AUTO-ROTATE-%s] periodic rotate switched from %s to %s", mode, proxyAddr, newProxy)
			}
		}
	}()
}

type goldenProxySet struct {
	Samples map[string][]string `yaml:"samples"`
}

type differentialProbeEntry struct {
	Protocol         string `json:"protocol"`
	Proxy            string `json:"proxy"`
	ComparePolicy    string `json:"compare_tls_policy"`
	DNSMode          string `json:"dns_mode"`
	ResolvedIP       string `json:"resolved_ip,omitempty"`
	ConnectedIP      string `json:"connected_ip,omitempty"`
	SNI              string `json:"sni,omitempty"`
	ALPN             string `json:"alpn,omitempty"`
	CertSHA256       string `json:"cert_sha256,omitempty"`
	ClientSuccess    bool   `json:"client_success"`
	ClientError      string `json:"client_error,omitempty"`
	ServerSuccess    bool   `json:"server_success"`
	ServerError      string `json:"server_error,omitempty"`
	StrictSuccess    bool   `json:"strict_success"`
	StrictError      string `json:"strict_error,omitempty"`
	RelaxedSuccess   bool   `json:"relaxed_success"`
	RelaxedError     string `json:"relaxed_error,omitempty"`
	HandshakeLatency string `json:"handshake_latency,omitempty"`
}

type differentialProbeReport struct {
	GeneratedAt time.Time                `json:"generated_at"`
	TargetURL   string                   `json:"target_url"`
	DNSMode     string                   `json:"dns_mode"`
	Entries     []differentialProbeEntry `json:"entries"`
	DiffOnly    []differentialProbeEntry `json:"client_ok_server_fail"`
}

func loadOrBuildGoldenProxySet() (map[string][]string, error) {
	path := strings.TrimSpace(config.DifferentialProbe.GoldenSampleFile)
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var gs goldenProxySet
			if yaml.Unmarshal(data, &gs) == nil && len(gs.Samples) > 0 {
				return gs.Samples, nil
			}
		}
	}
	perProtocol := config.DifferentialProbe.SamplesPerProtocol
	if perProtocol <= 0 {
		perProtocol = 5
	}
	if perProtocol > 10 {
		perProtocol = 10
	}
	picked := make(map[string][]string)
	err := fetchAndProcessMixedProxyBatches(2000, func(batch []string) {
		for _, entry := range batch {
			scheme, _, _, _, parseErr := parseMixedProxy(entry)
			if parseErr != nil {
				continue
			}
			scheme = strings.ToLower(strings.TrimSpace(scheme))
			if len(picked[scheme]) >= perProtocol {
				continue
			}
			picked[scheme] = append(picked[scheme], entry)
		}
	})
	if err != nil {
		return nil, err
	}
	if path != "" && len(picked) > 0 {
		out, _ := yaml.Marshal(goldenProxySet{Samples: picked})
		_ = os.WriteFile(path, out, 0o644)
	}
	return picked, nil
}

func resolveTargetIPForProbe(ctx context.Context, host string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(config.DifferentialProbe.DNS.Mode))
	switch mode {
	case "", "system":
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("system dns lookup failed: %w", err)
		}
		return ips[0].IP.String(), nil
	case "dot":
		dotServer := strings.TrimSpace(config.DifferentialProbe.DNS.DoTServer)
		if dotServer == "" {
			dotServer = "1.1.1.1:853"
		}
		dotHost := dotServer
		if h, _, err := net.SplitHostPort(dotServer); err == nil {
			dotHost = h
		}
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 6 * time.Second}
			return tls.DialWithDialer(d, "tcp", dotServer, &tls.Config{ServerName: dotHost})
		}}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("dot lookup failed: %w", err)
		}
		return ips[0].IP.String(), nil
	case "doh":
		ep := strings.TrimSpace(config.DifferentialProbe.DNS.DoHEndpoint)
		if ep == "" {
			ep = "https://dns.google/resolve"
		}
		u, _ := url.Parse(ep)
		q := u.Query()
		q.Set("name", host)
		q.Set("type", "A")
		u.RawQuery = q.Encode()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
		if err != nil {
			return "", fmt.Errorf("doh lookup failed: %w", err)
		}
		defer resp.Body.Close()
		var payload struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return "", err
		}
		for _, a := range payload.Answer {
			if ip := net.ParseIP(strings.TrimSpace(a.Data)); ip != nil {
				return ip.String(), nil
			}
		}
		return "", errors.New("no A record from doh")
	default:
		return "", fmt.Errorf("unsupported dns mode: %s", mode)
	}
}

func probeServerDetailed(proxyEntry string, strictMode bool, targetURL string) (differentialProbeEntry, error) {
	entry := differentialProbeEntry{Proxy: proxyEntry, ComparePolicy: config.DifferentialProbe.CompareTLSPolicy, DNSMode: config.DifferentialProbe.DNS.Mode}
	scheme, _, _, _, err := parseMixedProxy(proxyEntry)
	if err == nil {
		entry.Protocol = scheme
	}
	dialer, _, err := upstreamDialerBuilder(proxyEntry)
	if err != nil {
		return entry, err
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return entry, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.HealthCheck.TotalTimeoutSeconds)*time.Second)
	defer cancel()
	resolvedIP, err := resolveTargetIPForProbe(ctx, host)
	if err == nil {
		entry.ResolvedIP = resolvedIP
		u.Host = net.JoinHostPort(resolvedIP, port)
	}
	transport := &http.Transport{}
	transport.DialContext = dialer.DialContext
	var tlsHello time.Duration
	var certVerify time.Duration
	var connectedIP string
	var certSHA string
	var alpn string
	var verifyErr error
	transport.TLSClientConfig = &tls.Config{ServerName: host, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) > 0 {
			h := sha256.Sum256(cs.PeerCertificates[0].Raw)
			certSHA = fmt.Sprintf("%x", h[:])
		}
		if cs.NegotiatedProtocol != "" {
			alpn = cs.NegotiatedProtocol
		}
		if !strictMode {
			return nil
		}
		start := time.Now()
		defer func() { certVerify = time.Since(start) }()
		if len(cs.PeerCertificates) == 0 {
			verifyErr = errors.New("no peer cert")
			return verifyErr
		}
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, verifyErr = cs.PeerCertificates[0].Verify(opts)
		return verifyErr
	}}
	var tlsStart time.Time
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Host = host
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		ConnectDone: func(_, addr string, _ error) {
			if h, _, e := net.SplitHostPort(addr); e == nil {
				connectedIP = h
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				if h, _, e := net.SplitHostPort(info.Conn.RemoteAddr().String()); e == nil {
					connectedIP = h
				}
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStart.IsZero() {
				tlsHello = time.Since(tlsStart) - certVerify
				if tlsHello < 0 {
					tlsHello = time.Since(tlsStart)
				}
			}
		},
	}))
	resp, err := (&http.Client{Transport: transport, Timeout: time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second}).Do(req)
	if err != nil {
		if verifyErr != nil {
			err = verifyErr
		}
		entry.ServerError = err.Error()
		return entry, err
	}
	defer resp.Body.Close()
	entry.ServerSuccess = resp.StatusCode >= 200 && resp.StatusCode < 500
	entry.ConnectedIP = connectedIP
	entry.SNI = host
	entry.ALPN = alpn
	entry.CertSHA256 = certSHA
	entry.HandshakeLatency = (tlsHello + certVerify).String()
	return entry, nil
}

func runDifferentialProbeReport() (*differentialProbeReport, error) {
	samples, err := loadOrBuildGoldenProxySet()
	if err != nil {
		return nil, err
	}
	report := &differentialProbeReport{GeneratedAt: time.Now(), TargetURL: config.DifferentialProbe.TargetURL, DNSMode: config.DifferentialProbe.DNS.Mode}
	compareStrict := strings.EqualFold(strings.TrimSpace(config.DifferentialProbe.CompareTLSPolicy), "strict")
	protocols := make([]string, 0, len(samples))
	for k := range samples {
		protocols = append(protocols, k)
	}
	sort.Strings(protocols)
	for _, protocol := range protocols {
		for _, proxyEntry := range samples[protocol] {
			serverEntry, serverErr := probeServerDetailed(proxyEntry, compareStrict, config.DifferentialProbe.TargetURL)
			clientOK := checkMixedProxyHealth(proxyEntry, compareStrict)
			serverEntry.Protocol = protocol
			serverEntry.ClientSuccess = clientOK
			if !clientOK {
				serverEntry.ClientError = "client_probe_failed"
			}
			if serverErr != nil {
				serverEntry.ServerSuccess = false
			}
			strictStatus := checkMainstreamProxyHealthStage2(proxyEntry, true, config.HealthCheck).Status
			relaxedStatus := checkMainstreamProxyHealthStage2(proxyEntry, false, config.HealthCheck).Status
			serverEntry.StrictSuccess = strictStatus.Healthy
			serverEntry.RelaxedSuccess = relaxedStatus.Healthy
			if !strictStatus.Healthy {
				serverEntry.StrictError = strictStatus.Reason
			}
			if !relaxedStatus.Healthy {
				serverEntry.RelaxedError = relaxedStatus.Reason
			}
			report.Entries = append(report.Entries, serverEntry)
			if serverEntry.ClientSuccess && !serverEntry.ServerSuccess {
				report.DiffOnly = append(report.DiffOnly, serverEntry)
			}
		}
	}
	if file := strings.TrimSpace(config.DifferentialProbe.ReportOutputFile); file != "" {
		if out, err := json.MarshalIndent(report, "", "  "); err == nil {
			_ = os.WriteFile(file, out, 0o644)
		}
	}
	return report, nil
}

func main() {
	log.Println("Starting Dynamic Proxy Server...")

	rootCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Load configuration
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	config = *cfg

	proxySwitchInterval, rotateEveryRequest, err := parseProxySwitchInterval(config.ProxySwitchIntervalMin)
	if err != nil {
		log.Fatalf("Failed to parse proxy_switch_interval_min: %v", err)
	}

	// Log configuration
	log.Printf("Configuration loaded:")
	log.Printf("  - Proxy sources: %d", len(config.ProxyListURLs))
	for i, url := range config.ProxyListURLs {
		log.Printf("    [%d] %s", i+1, url)
	}
	log.Printf("  - Health check concurrency: %d", config.HealthCheckConcurrency)
	log.Printf("  - Update interval: %d minutes", config.UpdateIntervalMinutes)
	if rotateEveryRequest {
		log.Printf("  - Proxy switch interval: now (switch on every request)")
	} else {
		log.Printf("  - Proxy switch interval: %d minutes", int(proxySwitchInterval/time.Minute))
	}
	log.Printf("  - Health check timeout: %ds (TLS threshold: %ds)",
		config.HealthCheck.TotalTimeoutSeconds,
		config.HealthCheck.TLSHandshakeThresholdSeconds)
	log.Printf("  - SOCKS5 Strict port: %s", config.Ports.SOCKS5Strict)
	log.Printf("  - SOCKS5 Relaxed port: %s", config.Ports.SOCKS5Relaxed)
	log.Printf("  - HTTP Strict port: %s", config.Ports.HTTPStrict)
	log.Printf("  - HTTP Relaxed port: %s", config.Ports.HTTPRelaxed)
	log.Printf("  - HTTP Mixed port (HTTP/HTTPS/SOCKS): %s", config.Ports.HTTPMixed)
	log.Printf("  - HTTP Mixed port (VMESS/VLESS/HY2): %s", config.Ports.HTTPMainstreamMix)
	log.Printf("  - HTTP Mixed CF-pass port: %s", config.Ports.HTTPCFMixed)
	if isProxyAuthEnabled() {
		log.Printf("  - Proxy authentication: enabled (user: %s)", config.Auth.Username)
	} else {
		log.Printf("  - Proxy authentication: disabled")
	}

	if backend, ok := resolveMainstreamCoreBackend(config.Detector.Core); ok {
		info := backend.Info()
		log.Printf("  - Mainstream core backend: %s", info.Name)
		log.Printf("  - Mainstream core version: %s", info.Version)
		log.Printf("  - Mainstream core build: %s", info.Build)
		log.Printf("  - Mainstream protocol matrix: %s", protocolCapString(info.ProtocolCap))
	} else {
		log.Printf("  - Mainstream core backend: not configured (set detector.core to mihomo/meta/singbox)")
	}
	logCoreCapabilitySelfCheckSummary(config.Detector.Core)

	if config.DifferentialProbe.Enabled {
		if report, err := runDifferentialProbeReport(); err != nil {
			log.Printf("[DIFF-PROBE] failed: %v", err)
		} else {
			log.Printf("[DIFF-PROBE] completed target=%s entries=%d client_ok_server_fail=%d dns=%s", report.TargetURL, len(report.Entries), len(report.DiffOnly), report.DNSMode)
		}
	}

	// Create proxy pools
	strictPool := NewProxyPool(proxySwitchInterval, rotateEveryRequest)
	relaxedPool := NewProxyPool(proxySwitchInterval, rotateEveryRequest)
	cfPool := NewProxyPool(proxySwitchInterval, rotateEveryRequest)
	mixedHTTPPool := NewProxyPool(proxySwitchInterval, rotateEveryRequest)
	mainstreamMixedHTTPPool := NewProxyPool(proxySwitchInterval, rotateEveryRequest)
	cfMixedHTTPPool := NewProxyPool(proxySwitchInterval, rotateEveryRequest)

	// Start proxy updater with initial synchronous update
	startProxyUpdater(rootCtx, strictPool, relaxedPool, cfPool, mixedHTTPPool, mainstreamMixedHTTPPool, cfMixedHTTPPool, true)

	// Auto monitor current selected proxies and rotate when connectivity is lost
	startProxyConnectivityMonitor(rootCtx, strictPool, "STRICT", connectivityCheckInterval, func(proxyAddr string) bool {
		return checkProxyHealth(proxyAddr, true)
	})
	startProxyConnectivityMonitor(rootCtx, relaxedPool, "RELAXED", connectivityCheckInterval, func(proxyAddr string) bool {
		return checkProxyHealth(proxyAddr, false)
	})
	startProxyConnectivityMonitor(rootCtx, mixedHTTPPool, "MIXED", connectivityCheckInterval, func(proxyEntry string) bool {
		return checkMixedProxyHealth(proxyEntry, false)
	})
	startProxyConnectivityMonitor(rootCtx, cfMixedHTTPPool, "CF-MIXED", connectivityCheckInterval, func(proxyEntry string) bool {
		return checkMixedProxyHealth(proxyEntry, false)
	})
	startProxyConnectivityMonitor(rootCtx, mainstreamMixedHTTPPool, "MAINSTREAM-MIXED", connectivityCheckInterval, func(proxyEntry string) bool {
		return checkMixedProxyHealth(proxyEntry, false)
	})

	if !rotateEveryRequest {
		startProxyIntervalRotate(rootCtx, strictPool, "STRICT", proxySwitchInterval)
		startProxyIntervalRotate(rootCtx, relaxedPool, "RELAXED", proxySwitchInterval)
		startProxyIntervalRotate(rootCtx, mixedHTTPPool, "MIXED", proxySwitchInterval)
		startProxyIntervalRotate(rootCtx, mainstreamMixedHTTPPool, "MAINSTREAM-MIXED", proxySwitchInterval)
		startProxyIntervalRotate(rootCtx, cfMixedHTTPPool, "CF-MIXED", proxySwitchInterval)
	}

	// Check proxy pool status
	strictCount := len(strictPool.GetAll())
	relaxedCount := len(relaxedPool.GetAll())

	if strictCount == 0 {
		log.Println("[STRICT] Warning: No healthy proxies available")
		log.Println("[STRICT] Strict mode servers will return errors until proxies become available")
	} else {
		log.Printf("[STRICT] Successfully loaded %d healthy proxies", strictCount)
	}

	if relaxedCount == 0 {
		log.Println("[RELAXED] Warning: No healthy proxies available")
		log.Println("[RELAXED] Relaxed mode servers will return errors until proxies become available")
	} else {
		log.Printf("[RELAXED] Successfully loaded %d healthy proxies", relaxedCount)
	}

	// Start servers
	var wg sync.WaitGroup
	wg.Add(9)
	var mainstreamFallbackPool *ProxyPool
	if config.MainstreamMixed.DegradeStrategy == "fallback_http_socks" {
		mainstreamFallbackPool = mixedHTTPPool
	}

	// SOCKS5 Strict
	go func() {
		defer wg.Done()
		if err := startSOCKS5Server(strictPool, config.Ports.SOCKS5Strict, "STRICT"); err != nil {
			log.Fatalf("[STRICT] SOCKS5 server error: %v", err)
		}
	}()

	// SOCKS5 Relaxed
	go func() {
		defer wg.Done()
		if err := startSOCKS5Server(relaxedPool, config.Ports.SOCKS5Relaxed, "RELAXED"); err != nil {
			log.Fatalf("[RELAXED] SOCKS5 server error: %v", err)
		}
	}()

	// HTTP Strict
	go func() {
		defer wg.Done()
		if err := startHTTPServer(strictPool, nil, config.Ports.HTTPStrict, "STRICT"); err != nil {
			log.Fatalf("[STRICT] HTTP server error: %v", err)
		}
	}()

	// HTTP Relaxed
	go func() {
		defer wg.Done()
		if err := startHTTPServer(relaxedPool, nil, config.Ports.HTTPRelaxed, "RELAXED"); err != nil {
			log.Fatalf("[RELAXED] HTTP server error: %v", err)
		}
	}()

	// Rotate Control
	go func() {
		defer wg.Done()
		if err := startRotateControlServer(strictPool, relaxedPool, cfPool, mixedHTTPPool, mainstreamMixedHTTPPool, cfMixedHTTPPool, config.Ports.RotateControl); err != nil {
			log.Fatalf("[ROTATE] Control server error: %v", err)
		}
	}()

	// HTTP Mixed (HTTP/HTTPS/SOCKS5 upstream)
	go func() {
		defer wg.Done()
		if err := startHTTPServer(mixedHTTPPool, nil, config.Ports.HTTPMixed, "MIXED"); err != nil {
			log.Fatalf("[MIXED] HTTP server error: %v", err)
		}
	}()

	// HTTP Mixed CF-pass
	go func() {
		defer wg.Done()
		if err := startHTTPServer(cfMixedHTTPPool, nil, config.Ports.HTTPCFMixed, "CF-MIXED"); err != nil {
			log.Fatalf("[CF-MIXED] HTTP server error: %v", err)
		}
	}()

	// HTTP Mainstream Mixed (VMESS/VLESS/HY2 upstream)
	go func() {
		defer wg.Done()
		if err := startHTTPServer(mainstreamMixedHTTPPool, mainstreamFallbackPool, config.Ports.HTTPMainstreamMix, "MAINSTREAM-MIXED"); err != nil {
			log.Fatalf("[MAINSTREAM-MIXED] HTTP server error: %v", err)
		}
	}()

	// Pool status endpoint
	go func() {
		defer wg.Done()
		if err := startPoolStatusServer(strictPool, relaxedPool, cfPool, mixedHTTPPool, mainstreamMixedHTTPPool, cfMixedHTTPPool, ":17233"); err != nil {
			log.Fatalf("[STATUS] Server error: %v", err)
		}
	}()

	log.Println("All servers started successfully")
	log.Println("  [STRICT] SOCKS5: " + config.Ports.SOCKS5Strict + " | HTTP: " + config.Ports.HTTPStrict)
	log.Println("  [RELAXED] SOCKS5: " + config.Ports.SOCKS5Relaxed + " | HTTP: " + config.Ports.HTTPRelaxed)
	log.Println("  [MIXED] HTTP (HTTP/HTTPS/SOCKS upstream): " + config.Ports.HTTPMixed)
	log.Println("  [MAINSTREAM-MIXED] HTTP (all non-http/socks5 upstream): " + config.Ports.HTTPMainstreamMix)
	log.Printf("  [MAINSTREAM-MIXED] Degrade strategy: %s", config.MainstreamMixed.DegradeStrategy)
	log.Println("  [CF-MIXED] HTTP (CF-pass SOCKS5/HTTP upstream): " + config.Ports.HTTPCFMixed)
	log.Println("  [ROTATE] Control: " + config.Ports.RotateControl)
	log.Println("  [STATUS] Pool list: :17233/list")
	log.Printf("Proxy pools will update every %d minutes in background...", config.UpdateIntervalMinutes)
	log.Printf("Auto connectivity monitor enabled: checks every %s and rotates unhealthy current proxy", connectivityCheckInterval)
	wg.Wait()
}
