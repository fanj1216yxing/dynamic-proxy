package dockerfix

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	dynamicProxyServiceName      = "dynamic-proxy"
	singboxServiceName           = "singbox"
	defaultComposeNetworkName    = "proxy-network"
	defaultSingboxSidecarAddr    = "http://singbox:9090"
	defaultSidecarConfigRelPath  = "sing-box/sidecar.docker.json"
	defaultSingboxImage          = "ghcr.io/sagernet/sing-box:v1.12.22"
	defaultSidecarContainerName  = "singbox-sidecar"
	defaultSidecarConfigDestPath = "/etc/sing-box/config.json"
	defaultSidecarListenPort     = 9090
)

type Result struct {
	Core                 string
	Changed              bool
	ComposeChanged       bool
	SidecarConfigChanged bool
	Messages             []string
}

type appConfig struct {
	Detector struct {
		Core string `yaml:"core"`
	} `yaml:"detector"`
}

type composeFixResult struct {
	Changed            bool
	CreatedSingbox     bool
	ComposeYAMLWritten bool
}

func Run(projectRoot, configPath, composePath string, logger *log.Logger) (Result, error) {
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	projectRoot = strings.TrimSpace(projectRoot)
	if projectRoot == "" {
		projectRoot = "."
	}
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = filepath.Join(projectRoot, "config.yaml")
	}
	composePath = strings.TrimSpace(composePath)
	if composePath == "" {
		composePath = filepath.Join(projectRoot, "docker-compose.yml")
	}

	core, err := readDetectorCore(configPath)
	if err != nil {
		return Result{}, err
	}

	result := Result{Core: core}
	if !isSingboxCore(core) {
		msg := fmt.Sprintf("[docker-autofix] skip: detector.core=%s (no singbox autofix needed)", core)
		logger.Println(msg)
		result.Messages = append(result.Messages, msg)
		return result, nil
	}

	composeFix, err := ensureComposeForSingbox(composePath, logger)
	if err != nil {
		return result, err
	}
	result.ComposeChanged = composeFix.ComposeYAMLWritten
	result.Changed = result.Changed || composeFix.Changed

	sidecarChanged, err := ensureSidecarConfig(projectRoot, composeFix.CreatedSingbox, logger)
	if err != nil {
		return result, err
	}
	result.SidecarConfigChanged = sidecarChanged
	result.Changed = result.Changed || sidecarChanged

	summary := fmt.Sprintf("[docker-autofix] completed: detector.core=%s compose_changed=%t sidecar_config_changed=%t", core, result.ComposeChanged, result.SidecarConfigChanged)
	logger.Println(summary)
	result.Messages = append(result.Messages, summary)
	return result, nil
}

func readDetectorCore(configPath string) (string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read config failed: %w", err)
	}
	var cfg appConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return "", fmt.Errorf("parse config failed: %w", err)
	}
	core := strings.ToLower(strings.TrimSpace(cfg.Detector.Core))
	if core == "" {
		return "", fmt.Errorf("detector.core is empty in %s", configPath)
	}
	return core, nil
}

func isSingboxCore(core string) bool {
	core = strings.ToLower(strings.TrimSpace(core))
	return core == "singbox" || core == "sing-box"
}

func ensureComposeForSingbox(composePath string, logger *log.Logger) (composeFixResult, error) {
	raw, err := os.ReadFile(composePath)
	if err != nil {
		return composeFixResult{}, fmt.Errorf("read compose failed: %w", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return composeFixResult{}, fmt.Errorf("parse compose failed: %w", err)
	}

	services, err := ensureMapField(doc, "services")
	if err != nil {
		return composeFixResult{}, fmt.Errorf("compose services invalid: %w", err)
	}
	dpService, ok := toStringMap(services[dynamicProxyServiceName])
	if !ok {
		return composeFixResult{}, fmt.Errorf("compose missing %q service", dynamicProxyServiceName)
	}

	changed := false

	envChanged, err := ensureEnvironmentValue(dpService, "DP_SINGBOX_SIDECAR_ADDR", fmt.Sprintf("${DP_SINGBOX_SIDECAR_ADDR:-%s}", defaultSingboxSidecarAddr))
	if err != nil {
		return composeFixResult{}, fmt.Errorf("ensure environment failed: %w", err)
	}
	changed = changed || envChanged

	depChanged, err := ensureDependsOnService(dpService, singboxServiceName)
	if err != nil {
		return composeFixResult{}, fmt.Errorf("ensure depends_on failed: %w", err)
	}
	changed = changed || depChanged

	dpNetworkChanged, err := ensureServiceNetwork(dpService, defaultComposeNetworkName)
	if err != nil {
		return composeFixResult{}, fmt.Errorf("ensure dynamic-proxy network failed: %w", err)
	}
	changed = changed || dpNetworkChanged

	services[dynamicProxyServiceName] = dpService

	createdSingbox := false
	singboxServiceRaw, hasSingboxService := services[singboxServiceName]
	if !hasSingboxService {
		services[singboxServiceName] = defaultSingboxService()
		createdSingbox = true
		changed = true
		logger.Printf("[docker-autofix] added missing %q service", singboxServiceName)
	} else {
		singboxService, ok := toStringMap(singboxServiceRaw)
		if !ok {
			return composeFixResult{}, fmt.Errorf("compose service %q has unsupported structure", singboxServiceName)
		}
		svcNetworkChanged, err := ensureServiceNetwork(singboxService, defaultComposeNetworkName)
		if err != nil {
			return composeFixResult{}, fmt.Errorf("ensure singbox network failed: %w", err)
		}
		changed = changed || svcNetworkChanged
		services[singboxServiceName] = singboxService
	}
	doc["services"] = services

	networks, err := ensureMapField(doc, "networks")
	if err != nil {
		return composeFixResult{}, fmt.Errorf("compose networks invalid: %w", err)
	}
	if _, exists := networks[defaultComposeNetworkName]; !exists {
		networks[defaultComposeNetworkName] = map[string]any{"driver": "bridge"}
		changed = true
	}
	doc["networks"] = networks

	written := false
	if changed {
		encoded, err := yaml.Marshal(doc)
		if err != nil {
			return composeFixResult{}, fmt.Errorf("encode compose failed: %w", err)
		}
		if err := os.WriteFile(composePath, encoded, 0o644); err != nil {
			return composeFixResult{}, fmt.Errorf("write compose failed: %w", err)
		}
		written = true
		logger.Printf("[docker-autofix] compose updated: %s", composePath)
	}

	return composeFixResult{
		Changed:            changed,
		CreatedSingbox:     createdSingbox,
		ComposeYAMLWritten: written,
	}, nil
}

func ensureSidecarConfig(projectRoot string, forceRepair bool, logger *log.Logger) (bool, error) {
	sidecarPath := filepath.Join(projectRoot, defaultSidecarConfigRelPath)
	if err := os.MkdirAll(filepath.Dir(sidecarPath), 0o755); err != nil {
		return false, fmt.Errorf("create sidecar config dir failed: %w", err)
	}

	defaultConfig, err := buildDefaultSidecarConfigJSON()
	if err != nil {
		return false, fmt.Errorf("build default sidecar config failed: %w", err)
	}

	if _, statErr := os.Stat(sidecarPath); errors.Is(statErr, os.ErrNotExist) {
		if err := os.WriteFile(sidecarPath, defaultConfig, 0o644); err != nil {
			return false, fmt.Errorf("write sidecar config failed: %w", err)
		}
		logger.Printf("[docker-autofix] created sidecar config: %s", sidecarPath)
		return true, nil
	} else if statErr != nil {
		return false, fmt.Errorf("stat sidecar config failed: %w", statErr)
	}

	content, err := os.ReadFile(sidecarPath)
	if err != nil {
		return false, fmt.Errorf("read sidecar config failed: %w", err)
	}

	port, validJSON := detectMixedInboundPort(content)
	if !validJSON {
		backupPath := sidecarPath + ".bak." + time.Now().Format("20060102-150405")
		if err := os.Rename(sidecarPath, backupPath); err != nil {
			return false, fmt.Errorf("backup corrupted sidecar config failed: %w", err)
		}
		if err := os.WriteFile(sidecarPath, defaultConfig, 0o644); err != nil {
			return false, fmt.Errorf("repair sidecar config failed: %w", err)
		}
		logger.Printf("[docker-autofix] repaired corrupted sidecar config and created backup: %s", backupPath)
		return true, nil
	}

	if forceRepair && port != defaultSidecarListenPort {
		backupPath := sidecarPath + ".bak." + time.Now().Format("20060102-150405")
		if err := os.Rename(sidecarPath, backupPath); err != nil {
			return false, fmt.Errorf("backup sidecar config before port repair failed: %w", err)
		}
		if err := os.WriteFile(sidecarPath, defaultConfig, 0o644); err != nil {
			return false, fmt.Errorf("rewrite sidecar config with default port failed: %w", err)
		}
		logger.Printf("[docker-autofix] rewrote sidecar config to default listen_port=%d (backup: %s)", defaultSidecarListenPort, backupPath)
		return true, nil
	}

	if port != defaultSidecarListenPort {
		logger.Printf("[docker-autofix] existing sidecar config uses listen_port=%d, keep user-defined config", port)
	}
	return false, nil
}

func buildDefaultSidecarConfigJSON() ([]byte, error) {
	payload := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"inbounds": []map[string]any{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "0.0.0.0",
				"listen_port": defaultSidecarListenPort,
			},
		},
		"outbounds": []map[string]any{
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
		"route": map[string]any{
			"final": "direct",
		},
	}
	return json.MarshalIndent(payload, "", "  ")
}

func detectMixedInboundPort(content []byte) (int, bool) {
	var payload struct {
		Inbounds []struct {
			Type       string `json:"type"`
			ListenPort int    `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return 0, false
	}
	for _, inbound := range payload.Inbounds {
		if strings.EqualFold(strings.TrimSpace(inbound.Type), "mixed") && inbound.ListenPort > 0 {
			return inbound.ListenPort, true
		}
	}
	return 0, true
}

func defaultSingboxService() map[string]any {
	return map[string]any{
		"image":          defaultSingboxImage,
		"container_name": defaultSidecarContainerName,
		"restart":        "unless-stopped",
		"command":        []any{"run", "-c", defaultSidecarConfigDestPath},
		"volumes":        []any{fmt.Sprintf("./%s:%s:ro", defaultSidecarConfigRelPath, defaultSidecarConfigDestPath)},
		"networks":       []any{defaultComposeNetworkName},
	}
}

func ensureMapField(parent map[string]any, field string) (map[string]any, error) {
	raw, exists := parent[field]
	if !exists || raw == nil {
		created := make(map[string]any)
		parent[field] = created
		return created, nil
	}
	m, ok := toStringMap(raw)
	if !ok {
		return nil, fmt.Errorf("field %s is not a map", field)
	}
	return m, nil
}

func ensureEnvironmentValue(service map[string]any, key, value string) (bool, error) {
	raw, exists := service["environment"]
	if !exists || raw == nil {
		service["environment"] = []any{fmt.Sprintf("%s=%s", key, value)}
		return true, nil
	}

	switch env := raw.(type) {
	case []any:
		for _, item := range env {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if hasEnvKey(s, key) {
				return false, nil
			}
		}
		service["environment"] = append(env, fmt.Sprintf("%s=%s", key, value))
		return true, nil
	case map[string]any:
		if _, ok := env[key]; ok {
			return false, nil
		}
		env[key] = value
		service["environment"] = env
		return true, nil
	default:
		return false, fmt.Errorf("unsupported environment format %T", raw)
	}
}

func hasEnvKey(entry, key string) bool {
	entry = strings.TrimSpace(entry)
	if entry == key {
		return true
	}
	prefix := key + "="
	return strings.HasPrefix(entry, prefix)
}

func ensureDependsOnService(service map[string]any, dependency string) (bool, error) {
	raw, exists := service["depends_on"]
	if !exists || raw == nil {
		service["depends_on"] = []any{dependency}
		return true, nil
	}

	switch depends := raw.(type) {
	case []any:
		for _, item := range depends {
			if strings.EqualFold(strings.TrimSpace(fmt.Sprint(item)), dependency) {
				return false, nil
			}
		}
		service["depends_on"] = append(depends, dependency)
		return true, nil
	case map[string]any:
		if _, ok := depends[dependency]; ok {
			return false, nil
		}
		depends[dependency] = map[string]any{"condition": "service_started"}
		service["depends_on"] = depends
		return true, nil
	default:
		return false, fmt.Errorf("unsupported depends_on format %T", raw)
	}
}

func ensureServiceNetwork(service map[string]any, networkName string) (bool, error) {
	raw, exists := service["networks"]
	if !exists || raw == nil {
		service["networks"] = []any{networkName}
		return true, nil
	}

	switch networks := raw.(type) {
	case []any:
		for _, item := range networks {
			if strings.EqualFold(strings.TrimSpace(fmt.Sprint(item)), networkName) {
				return false, nil
			}
		}
		service["networks"] = append(networks, networkName)
		return true, nil
	case map[string]any:
		if _, ok := networks[networkName]; ok {
			return false, nil
		}
		networks[networkName] = map[string]any{}
		service["networks"] = networks
		return true, nil
	default:
		return false, fmt.Errorf("unsupported networks format %T", raw)
	}
}

func toStringMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if ok {
		return m, true
	}
	return nil, false
}
