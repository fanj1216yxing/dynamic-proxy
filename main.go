package main

import (
	"bufio"
	"context"
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
		Enabled  bool                `yaml:"enabled"`
		StageOne HealthCheckSettings `yaml:"stage_one"`
		StageTwo HealthCheckSettings `yaml:"stage_two"`
	} `yaml:"health_check_two_stage"`
	HealthCheckProtocolOverrides map[string]TwoStageHealthCheckSettings `yaml:"health_check_protocol_overrides"`
	Ports                        struct {
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

var mixedHealthCheckURL = defaultMixedHealthCheckURL
var mixedProxyHealthChecker = checkMainstreamProxyHealth
var mixedCFBypassChecker = checkCloudflareBypassMixed
var upstreamDialerBuilder = buildUpstreamDialer
var mainstreamAdapterFactory = func() mainstreamDialAdapter { return &mainstreamTCPConnectAdapter{} }

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
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 45, TLSHandshakeThresholdSeconds: 15},
		},
		"ssr": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 10, TLSHandshakeThresholdSeconds: 6},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 45, TLSHandshakeThresholdSeconds: 15},
		},
		"trojan": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 10, TLSHandshakeThresholdSeconds: 6},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 45, TLSHandshakeThresholdSeconds: 15},
		},
		"vmess": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 15, TLSHandshakeThresholdSeconds: 8},
		},
		"vless": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 15, TLSHandshakeThresholdSeconds: 8},
		},
		"hy2": {
			StageOne: HealthCheckSettings{TotalTimeoutSeconds: 6, TLSHandshakeThresholdSeconds: 3},
			StageTwo: HealthCheckSettings{TotalTimeoutSeconds: 15, TLSHandshakeThresholdSeconds: 8},
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
	if cfg.Ports.HTTPCFMixed == "" {
		cfg.Ports.HTTPCFMixed = ":8084"
	}
	if cfg.Ports.RotateControl == "" {
		cfg.Ports.RotateControl = ":9090"
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

var mixedRuntimeDisabledSchemes = map[string]string{
	"ss":     "disabled_by_runtime: pending kernel adaptation",
	"ssr":    "disabled_by_runtime: pending kernel adaptation",
	"trojan": "disabled_by_runtime: pending kernel adaptation",
}

var protocolAvailabilityTracker = newProtocolAvailabilityStore()

type protocolAvailabilityStatus struct {
	Scheme           string `json:"scheme"`
	ParseSupport     bool   `json:"parse_support"`
	DetectSupport    bool   `json:"detect_support"`
	ForwardSupport   bool   `json:"forward_support"`
	Availability     string `json:"availability"`
	PrimaryFailure   string `json:"primary_failure_reason,omitempty"`
	RuntimeNote      string `json:"runtime_note,omitempty"`
	ObservedSuccess  int64  `json:"observed_success"`
	ObservedFailures int64  `json:"observed_failures"`
}

type protocolAvailabilityStore struct {
	mu        sync.RWMutex
	stats     map[string]map[string]int64
	successes map[string]int64
}

func newProtocolAvailabilityStore() *protocolAvailabilityStore {
	return &protocolAvailabilityStore{stats: make(map[string]map[string]int64), successes: make(map[string]int64)}
}

func (s *protocolAvailabilityStore) record(status proxyHealthStatus) {
	scheme := strings.ToLower(strings.TrimSpace(status.Scheme))
	if scheme == "" {
		scheme = "unknown"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if status.Healthy {
		s.successes[scheme]++
		return
	}
	reasonKey := string(status.Category)
	if reasonKey == "" {
		reasonKey = "unknown"
	}
	if s.stats[scheme] == nil {
		s.stats[scheme] = make(map[string]int64)
	}
	s.stats[scheme][reasonKey]++
}

func (s *protocolAvailabilityStore) snapshot() map[string]protocolAvailabilityStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]protocolAvailabilityStatus)
	for scheme := range mixedSupportedSchemes {
		status := currentProtocolAvailability(scheme)
		status.ObservedSuccess = s.successes[scheme]
		var topReason string
		var topCount int64
		for reason, c := range s.stats[scheme] {
			status.ObservedFailures += c
			if c > topCount {
				topReason = reason
				topCount = c
			}
		}
		if topReason != "" {
			status.PrimaryFailure = topReason
		}
		out[scheme] = status
	}
	return out
}

func isRuntimeSchemeEnabled(scheme string) bool {
	_, disabled := mixedRuntimeDisabledSchemes[strings.ToLower(strings.TrimSpace(scheme))]
	return !disabled
}

func schemeRequiresMainstreamCore(scheme string) bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http", "https", "socks5", "socks5h":
		return false
	default:
		return true
	}
}

func currentProtocolAvailability(scheme string) protocolAvailabilityStatus {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	parseSupport := mixedSupportedSchemes[scheme]
	detectSupport := parseSupport && isRuntimeSchemeEnabled(scheme)
	forwardSupport := detectSupport
	status := protocolAvailabilityStatus{
		Scheme:         scheme,
		ParseSupport:   parseSupport,
		DetectSupport:  detectSupport,
		ForwardSupport: forwardSupport,
		Availability:   "enabled",
	}
	if reason, ok := mixedRuntimeDisabledSchemes[scheme]; ok {
		status.Availability = "disabled_by_runtime"
		status.RuntimeNote = reason
		status.DetectSupport = false
		status.ForwardSupport = false
		return status
	}
	if schemeRequiresMainstreamCore(scheme) && strings.TrimSpace(config.Detector.Core) == "" {
		status.Availability = "core_unconfigured"
		status.RuntimeNote = "set detector.core to enable mainstream protocol detection/forwarding"
		status.DetectSupport = false
		status.ForwardSupport = false
	}
	return status
}

func logProtocolSupportMatrixAtStartup() {
	schemes := make([]string, 0, len(mixedSupportedSchemes))
	for scheme := range mixedSupportedSchemes {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	log.Printf("  - 协议支持矩阵（解析支持/检测支持/转发支持）:")
	for _, scheme := range schemes {
		status := currentProtocolAvailability(scheme)
		note := ""
		if status.RuntimeNote != "" {
			note = " (" + status.RuntimeNote + ")"
		}
		log.Printf("    %s: %t/%t/%t [%s]%s", scheme, status.ParseSupport, status.DetectSupport, status.ForwardSupport, status.Availability, note)
	}
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
		if !seen[entry] {
			seen[entry] = true
			result = append(result, entry)
		}
	}

	return result, len(result) > 0
}

func parseRegularProxyContent(content string) ([]string, string) {
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
		}
	}

	return proxies, "plain"
}

func parseRegularProxyContentMixed(content string) ([]string, string) {
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

func normalizeMixedProxyEntry(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
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
			return "", false
		}

		if strings.HasPrefix(lowerLine, "vmess://") {
			if normalized, ok := normalizeVMESSURI(line); ok {
				return normalized, true
			}
		}

		if strings.HasPrefix(lowerLine, "ssr://") {
			if normalized, ok := normalizeSSRURI(line); ok {
				return normalized, true
			}
			return "", false
		}

		if strings.HasPrefix(lowerLine, "trojan://") {
			u, err := url.Parse(line)
			if err != nil || u.Host == "" || u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
				return "", false
			}
		}

		if strings.HasPrefix(lowerLine, "wg://") || strings.HasPrefix(lowerLine, "wireguard://") {
			if normalized, ok := normalizeWireGuardURI(line); ok {
				return normalized, true
			}
		}

		u, err := url.Parse(line)
		if err != nil || u.Host == "" {
			return "", false
		}
		scheme := strings.ToLower(u.Scheme)
		if !mixedSupportedSchemes[scheme] {
			return "", false
		}
		if !validateMainstreamURI(scheme, u) {
			return "", false
		}
		authority := u.Host
		if u.User != nil {
			authority = u.User.String() + "@" + authority
		}
		normalized := fmt.Sprintf("%s://%s", scheme, authority)
		if filteredQuery := filterRawQueryWithWhitelist(u.RawQuery, scheme); filteredQuery != "" {
			normalized += "?" + filteredQuery
		}
		if u.Fragment != "" && scheme != "vless" {
			normalized += "#" + u.Fragment
		}
		return normalized, true
	}

	return "socks5://" + line, true
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
	"sni": true, "alpn": true, "insecure": true, "security": true,
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
	if err != nil || u.Host == "" {
		return node, false
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
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
	if node.Add == "" || node.Port == "" {
		return vmessNode{}, false
	}
	return node, true
}

func parseVLESSNode(raw string) (vlessNode, bool) {
	node := vlessNode{}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || strings.ToLower(u.Scheme) != "vless" {
		return node, false
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if host == "" || port == "" || u.User == nil {
		return node, false
	}
	uuid := strings.TrimSpace(u.User.Username())
	if uuid == "" {
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
		return node, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "hy2" && scheme != "hysteria2" {
		return node, false
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if host == "" || port == "" || u.User == nil {
		return node, false
	}
	password := strings.TrimSpace(u.User.Username())
	if password == "" {
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
		return true
	case "trojan", "hy2", "hysteria2":
		return u.User != nil && strings.TrimSpace(u.User.Username()) != ""
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

type socksUpstreamDialer struct {
	proxyAddr string
	auth      *proxy.Auth
}

func (d *socksUpstreamDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = result.conn.SetDeadline(deadline)
		}
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
	return dialTargetThroughHTTPProxy(ctx, d.proxyScheme, d.proxyAddr, d.proxyAuthHeader, addr)
}

var errMainstreamAdapterUnavailable = errors.New("mainstream upstream adapter unavailable")

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

type tcpConnectCoreBackend struct {
	info mainstreamCoreInfo
}

func (b *tcpConnectCoreBackend) DialContext(ctx context.Context, _ kernelNodeConfig, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (b *tcpConnectCoreBackend) Info() mainstreamCoreInfo {
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
		return &tcpConnectCoreBackend{info: mainstreamCoreInfo{Name: "mihomo", Version: "builtin", Build: "dynamic-proxy", ProtocolCap: matrix}}, true
	case "meta":
		return &tcpConnectCoreBackend{info: mainstreamCoreInfo{Name: "meta", Version: "builtin", Build: "dynamic-proxy", ProtocolCap: matrix}}, true
	case "singbox", "sing-box":
		return &tcpConnectCoreBackend{info: mainstreamCoreInfo{Name: "singbox", Version: "builtin", Build: "dynamic-proxy", ProtocolCap: matrix}}, true
	default:
		return &tcpConnectCoreBackend{info: mainstreamCoreInfo{Name: core, Version: "unknown", Build: "dynamic-proxy", ProtocolCap: matrix}}, true
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
	}

	return node, nil
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
	if d.adapter == nil {
		return nil, fmt.Errorf("%w: %s", errMainstreamAdapterUnavailable, d.proxyScheme)
	}
	return d.adapter.DialContext(ctx, d.proxyScheme, d.proxyEntry, d.proxyAddr, network, addr)
}

type mainstreamTCPConnectAdapter struct{}

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

		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "ss://") || strings.Contains(lowerLine, "ssr://") || strings.Contains(lowerLine, "trojan://") {
			log.Printf("parse_failed: skip malformed mainstream line without fallback: %s", line)
			continue
		}

		matches := simpleProxyRegex.FindStringSubmatch(line)
		if len(matches) < 3 {
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
		if reason, disabled := mixedRuntimeDisabledSchemes[s]; disabled {
			return "", "", nil, "", fmt.Errorf("%s: %s", reason, s)
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

	if reason, disabled := mixedRuntimeDisabledSchemes["socks5"]; disabled {
		return "", "", nil, "", fmt.Errorf("%s: %s", reason, "socks5")
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

	client := &http.Client{Transport: transport, Timeout: totalTimeout}
	start := time.Now()
	resp, err := client.Get(mixedHealthCheckURL)
	if err != nil {
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
	Healthy  bool
	Scheme   string
	Category healthFailureCategory
	Reason   string
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
}

func (s *protocolStats) addResult(status proxyHealthStatus) {
	s.Total++
	if status.Healthy {
		s.Success++
		return
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

type healthPhaseMetrics struct {
	DNS        time.Duration
	TCPConnect time.Duration
	TLSHello   time.Duration
	CertVerify time.Duration
	FirstByte  time.Duration
}

func formatHealthReason(code string, err error) string {
	if code == "" {
		code = "unknown"
	}
	if err == nil {
		return "code=" + code
	}
	detail := strings.ReplaceAll(err.Error(), ";", ",")
	return fmt.Sprintf("code=%s;detail=%s", code, detail)
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
	case errors.Is(err, errMainstreamAdapterUnavailable), strings.Contains(msg, "detector.core is empty"):
		return healthFailureCoreUnavailable, "core_unconfigured"
	case strings.Contains(msg, "disabled_by_runtime"):
		return healthFailureUnsupported, "disabled_by_runtime"
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
		if strings.Contains(err.Error(), "invalid") {
			return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, Reason: err.Error()}
		}
		category, code := classifyHealthFailure(err)
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, Reason: formatHealthReason(code, err)}
	}

	totalTimeout := time.Duration(settings.TotalTimeoutSeconds) * time.Second
	threshold := time.Duration(settings.TLSHandshakeThresholdSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", mixedHealthTargetAddr())
	if err != nil {
		category, code := classifyHealthFailure(err)
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, Reason: formatHealthReason(code, err)}
	}
	_ = conn.Close()

	if time.Since(start) > threshold {
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, Reason: "stage1 tunnel connect exceeded threshold"}
	}

	return proxyHealthStatus{Healthy: true, Scheme: scheme, Category: healthFailureNone}
}

func checkMainstreamProxyHealthStage2(proxyEntry string, strictMode bool, settings HealthCheckSettings) mixedStageCheckResult {
	dialer, scheme, err := upstreamDialerBuilder(proxyEntry)
	if scheme == "" {
		scheme = "unknown"
	}
	if err != nil {
		if strings.Contains(err.Error(), "invalid") {
			return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, Reason: err.Error()}}
		}
		category, code := classifyHealthFailure(err)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, Reason: formatHealthReason(code, err)}}
	}

	totalTimeout := time.Duration(settings.TotalTimeoutSeconds) * time.Second
	threshold := time.Duration(settings.TLSHandshakeThresholdSeconds) * time.Second

	targetURL, parseErr := url.Parse(mixedHealthCheckURL)
	if parseErr != nil {
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, Reason: formatHealthReason("invalid_healthcheck_url", parseErr)}}
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
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, Reason: formatHealthReason("invalid_request", reqErr)}}
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
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
			category, code := classifyHealthFailure(verifyErr)
			return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, Reason: formatHealthReason(code, verifyErr)}, Latency: latency}
		}
		if isTimeoutError(err) && !tlsHandshakeDone {
			return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, Reason: formatHealthReason("tls_handshake_timeout", err)}, Latency: latency}
		}
		category, code := classifyHealthFailure(err)
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: category, Reason: formatHealthReason(code, err)}, Latency: latency}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureUnreachable, Reason: fmt.Sprintf("unexpected status: %d", resp.StatusCode)}, Latency: latency}
	}

	if tlsHandshakeDone && phase.TLSHello+phase.CertVerify > threshold {
		return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, Reason: "stage2 tls handshake exceeded threshold"}, Latency: latency}
	}

	log.Printf("[MIXED-TLS-PHASE] scheme=%s dns=%s tcp_connect=%s tls_clienthello=%s cert_verify=%s first_byte=%s",
		scheme, phase.DNS, phase.TCPConnect, phase.TLSHello, phase.CertVerify, phase.FirstByte)

	return mixedStageCheckResult{Status: proxyHealthStatus{Healthy: true, Scheme: scheme, Category: healthFailureNone}, Latency: latency}
}

func healthCheckMixedProxies(proxies []string) MixedHealthCheckResult {
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
				protocolAvailabilityTracker.record(status)
				stats := localSummary[status.Scheme]
				stats.addResult(status)
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
		log.Printf("[MIXED-SUMMARY] scheme=%s tls_failures={eof:%d protocol_error:%d cert_verify_failed:%d sni_mismatch:%d}",
			scheme,
			stats.EOF,
			stats.ProtocolError,
			stats.CertVerifyFail,
			stats.SNIMismatch,
		)
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
		log.Printf("[MIXED-2STAGE-POLICY] scheme=%s stage1={tier:%s timeout:%ds tls_threshold:%ds} stage2={tier:%s timeout:%ds tls_threshold:%ds}",
			scheme,
			stageOneTier,
			stageOneSettings.TotalTimeoutSeconds,
			stageOneSettings.TLSHandshakeThresholdSeconds,
			stageTwoTier,
			stageTwoSettings.TotalTimeoutSeconds,
			stageTwoSettings.TLSHandshakeThresholdSeconds,
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
				status := checkMainstreamProxyHealthStage1(entry, settings)
				protocolAvailabilityTracker.record(status)
				mu.Lock()
				st := getStageStats(status.Scheme)
				st.Total++
				if status.Healthy {
					st.Stage1Pass++
					stage1Candidates = append(stage1Candidates, entry)
				} else {
					st.DropReason[string(status.Category)]++
				}
				mu.Unlock()
			}
		}()
	}
	for _, entry := range proxies {
		jobs <- entry
	}
	close(jobs)
	wg.Wait()

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
		}
		return MixedHealthCheckResult{}
	}

	mixedHealthy := make([]string, 0, len(stage1Candidates))
	cfPassHealthy := make([]string, 0)
	latencies := make([]time.Duration, 0, len(stage1Candidates))

	jobs2 := make(chan string, workerCount*4)
	wg = sync.WaitGroup{}
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
				result := checkMainstreamProxyHealthStage2(entry, false, settings)
				protocolAvailabilityTracker.record(result.Status)
				mu.Lock()
				st := getStageStats(result.Status.Scheme)
				if result.Status.Healthy {
					st.Stage2Pass++
					mixedHealthy = append(mixedHealthy, entry)
					latencies = append(latencies, result.Latency)
					if config.CFChallengeCheck.Enabled && mixedCFBypassChecker(entry) {
						cfPassHealthy = append(cfPassHealthy, entry)
					}
				} else {
					st.DropReason[string(result.Status.Category)]++
				}
				mu.Unlock()
			}
		}()
	}
	for _, entry := range stage1Candidates {
		jobs2 <- entry
	}
	close(jobs2)
	wg.Wait()

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

	if config.CFChallengeCheck.Enabled {
		if len(result.CFPass) > 0 {
			cfMixedPool.Update(result.CFPass)
			log.Printf("[HTTP-CF-MIXED] Pool updated with %d CF-pass mixed proxies", len(result.CFPass))
		} else {
			log.Println("[HTTP-CF-MIXED] Warning: No CF-pass mixed proxies found, keeping existing pool")
		}
	}

	adminRuntime.MarkUpdated("ok")
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

	proxyAddr, err := pool.GetNext()
	if err != nil && fallbackPool != nil {
		fallbackProxy, fallbackErr := fallbackPool.GetNext()
		if fallbackErr == nil {
			log.Printf("[HTTP-%s] Primary pool unavailable, fallback proxy selected from MIXED pool: %s", mode, fallbackProxy)
			proxyAddr = fallbackProxy
			err = nil
		}
	}
	if err != nil {
		log.Printf("[HTTP-%s] ERROR: No proxy available for %s %s: %v", mode, r.Method, r.URL.String(), err)
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

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[HTTP-%s] ERROR: Request failed for %s: %v", mode, r.URL.String(), err)
		rotatePoolOnUpstreamFailure(pool, mode, proxyAddr, err)
		http.Error(w, fmt.Sprintf("Proxy request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

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

	protocolAvailability := protocolAvailabilityTracker.snapshot()

	return map[string]interface{}{
		"strict_proxy_count":            len(strictProxies),
		"strict_current_proxy":          strictCurrent,
		"strict_proxies":                strictProxies,
		"relaxed_proxy_count":           len(relaxedProxies),
		"relaxed_current_proxy":         relaxedCurrent,
		"relaxed_proxies":               relaxedProxies,
		"cf_proxy_count":                len(cfProxies),
		"cf_current_proxy":              cfCurrent,
		"cf_proxies":                    cfProxies,
		"http_socks_proxy_count":        len(mixedProxies),
		"http_socks_current_proxy":      mixedCurrent,
		"http_socks_proxies":            mixedProxies,
		"mainstream_proxy_count":        len(mainstreamProxies),
		"mainstream_current_proxy":      mainstreamCurrent,
		"mainstream_proxies":            mainstreamProxies,
		"cf_mixed_proxy_count":          len(cfMixedProxies),
		"cf_mixed_current_proxy":        cfMixedCurrent,
		"cf_mixed_proxies":              cfMixedProxies,
		"all_healthy_proxy_count":       len(allHealthyProxies),
		"all_healthy_proxies":           allHealthyProxies,
		"mainstream_listen_port":        config.Ports.HTTPMainstreamMix,
		"status_listen_addr":            port,
		"mainstream_excluded_protocols": []string{"http", "https", "socks5", "socks5h"},
		"protocol_availability":         protocolAvailability,
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
			"strict":             map[string]interface{}{"available": payload["strict_proxy_count"]},
			"relaxed":            map[string]interface{}{"available": payload["relaxed_proxy_count"]},
			"mixed":              map[string]interface{}{"available": payload["http_socks_proxy_count"]},
			"all_healthy":        allHealthyCount,
			"last_update_status": status,
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
			"ports":                     config.Ports,
			"auth_enabled":              isProxyAuthEnabled(),
		})
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
	logProtocolSupportMatrixAtStartup()

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
		if err := startHTTPServer(mainstreamMixedHTTPPool, nil, config.Ports.HTTPMainstreamMix, "MAINSTREAM-MIXED"); err != nil {
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
	log.Println("  [CF-MIXED] HTTP (CF-pass SOCKS5/HTTP upstream): " + config.Ports.HTTPCFMixed)
	log.Println("  [ROTATE] Control: " + config.Ports.RotateControl)
	log.Println("  [STATUS] Pool list: :17233/list")
	log.Printf("Proxy pools will update every %d minutes in background...", config.UpdateIntervalMinutes)
	log.Printf("Auto connectivity monitor enabled: checks every %s and rotates unhealthy current proxy", connectivityCheckInterval)
	wg.Wait()
}
