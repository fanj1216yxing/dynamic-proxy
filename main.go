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
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
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
}

type HealthCheckSettings struct {
	TotalTimeoutSeconds          int `yaml:"total_timeout_seconds"`
	TLSHandshakeThresholdSeconds int `yaml:"tls_handshake_threshold_seconds"`
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
		Type     string `yaml:"type"`
		Server   string `yaml:"server"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		UUID     string `yaml:"uuid"`
		Cipher   string `yaml:"cipher"`
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
		switch proxyType {
		case "ss":
			if p.Cipher == "" || p.Password == "" {
				continue
			}
			entry = fmt.Sprintf("ss://%s:%s@%s", url.QueryEscape(p.Cipher), url.QueryEscape(p.Password), host)
		case "vless":
			if p.UUID == "" {
				continue
			}
			entry = fmt.Sprintf("vless://%s@%s", url.QueryEscape(p.UUID), host)
		case "hy2", "hysteria2":
			if p.Password == "" {
				continue
			}
			entry = fmt.Sprintf("%s://%s@%s", proxyType, url.QueryEscape(p.Password), host)
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

	if strings.Contains(line, "://") {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "ss://") {
			if normalized, ok := normalizeSSURI(line); ok {
				return normalized, true
			}
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
		if scheme == "https" {
			return normalized, true
		}
		if u.RawQuery != "" {
			normalized += "?" + u.RawQuery
		}
		if u.Fragment != "" && scheme != "vless" {
			normalized += "#" + u.Fragment
		}
		return normalized, true
	}

	return "socks5://" + line, true
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

func normalizeSSRURI(raw string) (string, bool) {
	encoded := strings.TrimSpace(strings.TrimPrefix(raw, "ssr://"))
	if idx := strings.Index(encoded, "#"); idx >= 0 {
		encoded = encoded[:idx]
	}
	if encoded == "" {
		return "", false
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		payload, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", false
		}
	}

	parts := strings.SplitN(string(payload), "/?", 2)
	segments := strings.Split(parts[0], ":")
	if len(segments) < 6 {
		return "", false
	}
	host, port, passwordEnc := segments[0], segments[1], segments[5]
	if host == "" || port == "" || passwordEnc == "" {
		return "", false
	}

	passwordRaw, err := base64.RawURLEncoding.DecodeString(passwordEnc)
	if err != nil {
		passwordRaw, err = base64.RawStdEncoding.DecodeString(passwordEnc)
		if err != nil {
			return "", false
		}
	}

	return fmt.Sprintf("ssr://%s@%s", url.QueryEscape(string(passwordRaw)), net.JoinHostPort(host, port)), true
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
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if u.Host != "" && (u.User != nil || strings.Contains(u.Host, ":")) {
		authority := u.Host
		if u.User != nil {
			authority = u.User.String() + "@" + authority
		}
		return "ss://" + authority, true
	}

	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(raw, "ss://"))
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "ss://"))
		if err != nil {
			return "", false
		}
	}

	decodedURL, err := url.Parse("ss://" + string(decoded))
	if err != nil || decodedURL.Host == "" {
		return "", false
	}
	authority := decodedURL.Host
	if decodedURL.User != nil {
		authority = decodedURL.User.String() + "@" + authority
	}
	return "ss://" + authority, true
}

func resolveMixedDialTarget(scheme string, addr string) (dialScheme string, dialAddr string, useAuth bool) {
	return scheme, addr, true
}

type UpstreamDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type socksUpstreamDialer struct {
	dialer proxy.Dialer
}

func (d *socksUpstreamDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.Dial(network, addr)
}

type httpConnectUpstreamDialer struct {
	proxyScheme     string
	proxyAddr       string
	proxyAuthHeader string
}

func (d *httpConnectUpstreamDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network %s for HTTP upstream", network)
	}
	return dialTargetThroughHTTPProxy(d.proxyScheme, d.proxyAddr, d.proxyAuthHeader, addr)
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
		dialer, dialErr := proxy.SOCKS5("tcp", dialAddr, auth, proxy.Direct)
		if dialErr != nil {
			return nil, scheme, fmt.Errorf("failed to create SOCKS dialer: %w", dialErr)
		}
		return &socksUpstreamDialer{dialer: dialer}, scheme, nil
	case "http", "https":
		return &httpConnectUpstreamDialer{proxyScheme: dialScheme, proxyAddr: dialAddr, proxyAuthHeader: httpAuthHeader}, scheme, nil
	case "vmess", "vless", "hy2", "hysteria", "hysteria2", "trojan", "ss", "ssr", "tuic", "wg", "wireguard":
		return nil, scheme, fmt.Errorf("unsupported upstream proxy scheme: %s", scheme)
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

		matches := simpleProxyRegex.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}

		scheme := "socks5"
		lowerLine := strings.ToLower(line)
		switch {
		case strings.Contains(lowerLine, "https://"):
			scheme = "https"
		case strings.Contains(lowerLine, "http://"):
			scheme = "http"
		case strings.Contains(lowerLine, "socks5h://"):
			scheme = "socks5h"
		case strings.Contains(lowerLine, "socks5://"):
			scheme = "socks5"
		case strings.Contains(lowerLine, "ss://"):
			scheme = "ss"
		case strings.Contains(lowerLine, "ssr://"):
			scheme = "ssr"
		case strings.Contains(lowerLine, "trojan://"):
			scheme = "trojan"
		case strings.Contains(lowerLine, "vmess://"):
			scheme = "vmess"
		case strings.Contains(lowerLine, "vless://"):
			scheme = "vless"
		case strings.Contains(lowerLine, "tuic://"):
			scheme = "tuic"
		case strings.Contains(lowerLine, "hysteria://"):
			scheme = "hysteria"
		case strings.Contains(lowerLine, "hy2://"):
			scheme = "hy2"
		case strings.Contains(lowerLine, "hysteria2://"):
			scheme = "hysteria2"
		case strings.Contains(lowerLine, "wg://"):
			scheme = "wg"
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
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(entry)), "vmess://") {
			node, ok := parseVMESSNode(entry)
			if !ok {
				return "", "", nil, "", fmt.Errorf("invalid vmess entry: %s", entry)
			}
			return "vmess", net.JoinHostPort(node.Add, node.Port), nil, "", nil
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

	dialer, _, err := buildUpstreamDialer(proxyEntry)
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
	dialer, _, err := buildUpstreamDialer(proxyEntry)
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
	healthFailureNone        healthFailureCategory = "none"
	healthFailureParse       healthFailureCategory = "parse_failed"
	healthFailureHandshake   healthFailureCategory = "handshake_failed"
	healthFailureAuth        healthFailureCategory = "auth_failed"
	healthFailureTimeout     healthFailureCategory = "timeout"
	healthFailureUnreachable healthFailureCategory = "unreachable"
)

type proxyHealthStatus struct {
	Healthy  bool
	Scheme   string
	Category healthFailureCategory
	Reason   string
}

type protocolStats struct {
	Total         int64
	Success       int64
	ParseFailed   int64
	HandshakeFail int64
	AuthFail      int64
	Timeout       int64
	Unreachable   int64
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
	case healthFailureHandshake:
		s.HandshakeFail++
	case healthFailureAuth:
		s.AuthFail++
	case healthFailureTimeout:
		s.Timeout++
	case healthFailureUnreachable:
		s.Unreachable++
	}
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

func classifyHealthFailure(err error) healthFailureCategory {
	if err == nil {
		return healthFailureNone
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return healthFailureTimeout
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return healthFailureTimeout
	case strings.Contains(msg, "auth"), strings.Contains(msg, "unauthorized"), strings.Contains(msg, "forbidden"):
		return healthFailureAuth
	case strings.Contains(msg, "handshake"), strings.Contains(msg, "tls"), strings.Contains(msg, "certificate"):
		return healthFailureHandshake
	default:
		return healthFailureUnreachable
	}
}

func checkMainstreamProxyHealth(proxyEntry string, strictMode bool) proxyHealthStatus {
	dialer, scheme, err := buildUpstreamDialer(proxyEntry)
	if scheme == "" {
		scheme = "unknown"
	}
	if err != nil {
		if strings.Contains(err.Error(), "unsupported upstream proxy scheme") || strings.Contains(err.Error(), "invalid") {
			return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureParse, Reason: err.Error()}
		}
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: classifyHealthFailure(err), Reason: err.Error()}
	}

	totalTimeout := time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second
	threshold := time.Duration(config.HealthCheck.TLSHandshakeThresholdSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", "www.google.com:443")
	if err != nil {
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: classifyHealthFailure(err), Reason: err.Error()}
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "www.google.com", InsecureSkipVerify: !strictMode})
	if err := tlsConn.Handshake(); err != nil {
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: classifyHealthFailure(err), Reason: err.Error()}
	}
	_ = tlsConn.Close()

	if time.Since(start) > threshold {
		return proxyHealthStatus{Healthy: false, Scheme: scheme, Category: healthFailureTimeout, Reason: "tls handshake exceeded threshold"}
	}

	return proxyHealthStatus{Healthy: true, Scheme: scheme, Category: healthFailureNone}
}

func healthCheckMixedProxies(proxies []string) MixedHealthCheckResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	mixedHealthy := make([]string, 0)
	cfPassHealthy := make([]string, 0)

	total := len(proxies)
	var checked int64
	var healthyCount int64
	var cfPassCount int64
	protocolSummary := make(map[string]*protocolStats)

	workerCount := config.HealthCheckConcurrency
	if workerCount <= 0 {
		workerCount = 1
	}
	jobs := make(chan string)
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
			for entry := range jobs {
				status := checkMainstreamProxyHealth(entry, false)

				mu.Lock()
				stats, ok := protocolSummary[status.Scheme]
				if !ok {
					stats = &protocolStats{}
					protocolSummary[status.Scheme] = stats
				}
				stats.addResult(status)
				mu.Unlock()

				if status.Healthy {
					mu.Lock()
					mixedHealthy = append(mixedHealthy, entry)
					mu.Unlock()
					atomic.AddInt64(&healthyCount, 1)
					if config.CFChallengeCheck.Enabled && checkCloudflareBypassMixed(entry) {
						mu.Lock()
						cfPassHealthy = append(cfPassHealthy, entry)
						mu.Unlock()
						atomic.AddInt64(&cfPassCount, 1)
					}
				}
				atomic.AddInt64(&checked, 1)
			}
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
		log.Printf("[MIXED-SUMMARY] scheme=%s total=%d success=%d success_rate=%.1f%% failures={parse:%d handshake:%d auth:%d timeout:%d unreachable:%d}",
			scheme,
			stats.Total,
			stats.Success,
			successRate,
			stats.ParseFailed,
			stats.HandshakeFail,
			stats.AuthFail,
			stats.Timeout,
			stats.Unreachable,
		)
	}
	mu.Unlock()

	sort.Strings(cfPassHealthy)

	return MixedHealthCheckResult{Healthy: mixedHealthy, CFPass: cfPassHealthy}
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

func dialTargetThroughHTTPProxy(proxyScheme string, proxyAddr string, proxyAuthHeader string, targetHost string) (net.Conn, error) {
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
	if proxyScheme == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", connectAddr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", connectAddr, 10*time.Second)
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
