package dockerfix

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRunSkipsWhenCoreIsNotSingbox(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "config.yaml"), "detector:\n  core: meta\n")
	composePath := filepath.Join(root, "docker-compose.yml")
	originalCompose := "version: '3.8'\nservices:\n  dynamic-proxy:\n    image: demo\n"
	mustWriteFile(t, composePath, originalCompose)

	result, err := Run(root, "", "", log.New(os.Stdout, "", 0))
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result.Changed {
		t.Fatalf("expected no change for non-singbox core")
	}

	currentCompose := mustReadFile(t, composePath)
	if currentCompose != originalCompose {
		t.Fatalf("compose should remain unchanged")
	}
}

func TestRunAddsSingboxSidecarAndEnvIdempotently(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "config.yaml"), "detector:\n  core: singbox\n")
	composePath := filepath.Join(root, "docker-compose.yml")
	mustWriteFile(t, composePath, "version: '3.8'\nservices:\n  dynamic-proxy:\n    image: demo\n")

	first, err := Run(root, "", "", log.New(os.Stdout, "", 0))
	if err != nil {
		t.Fatalf("Run first failed: %v", err)
	}
	if !first.Changed {
		t.Fatalf("expected first run to change files")
	}

	doc := readComposeYAML(t, composePath)
	services := doc["services"].(map[string]any)
	dp := services["dynamic-proxy"].(map[string]any)
	if !containsEnvKey(dp["environment"], "DP_SINGBOX_SIDECAR_ADDR") {
		t.Fatalf("expected DP_SINGBOX_SIDECAR_ADDR to be injected")
	}
	if _, ok := services["singbox"]; !ok {
		t.Fatalf("expected singbox service to be added")
	}

	sidecar := mustReadFile(t, filepath.Join(root, defaultSidecarConfigRelPath))
	if !json.Valid([]byte(sidecar)) {
		t.Fatalf("expected sidecar config to be valid json")
	}
	if !strings.Contains(sidecar, "\"listen_port\": 9090") {
		t.Fatalf("expected default sidecar listen port 9090")
	}

	second, err := Run(root, "", "", log.New(os.Stdout, "", 0))
	if err != nil {
		t.Fatalf("Run second failed: %v", err)
	}
	if second.Changed {
		t.Fatalf("expected second run to be idempotent")
	}
}

func TestRunKeepsExistingCustomEnvAndSingboxService(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "config.yaml"), "detector:\n  core: singbox\n")
	composePath := filepath.Join(root, "docker-compose.yml")
	mustWriteFile(t, composePath, `
version: '3.8'
services:
  dynamic-proxy:
    image: demo
    environment:
      - DP_SINGBOX_SIDECAR_ADDR=http://custom-sidecar:12345
    depends_on:
      - singbox
  singbox:
    image: custom/singbox:latest
`)
	mustWriteFile(t, filepath.Join(root, defaultSidecarConfigRelPath), `{"inbounds":[{"type":"mixed","listen_port":12345}]}`)

	result, err := Run(root, "", "", log.New(os.Stdout, "", 0))
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result.SidecarConfigChanged {
		t.Fatalf("expected existing valid sidecar config to be preserved")
	}

	doc := readComposeYAML(t, composePath)
	services := doc["services"].(map[string]any)
	dp := services["dynamic-proxy"].(map[string]any)
	if !containsEnvEntry(dp["environment"], "DP_SINGBOX_SIDECAR_ADDR=http://custom-sidecar:12345") {
		t.Fatalf("expected custom sidecar env to be preserved")
	}
	singbox := services["singbox"].(map[string]any)
	if singbox["image"] != "custom/singbox:latest" {
		t.Fatalf("expected custom singbox image to be preserved")
	}
}

func TestRunRepairsCorruptedSidecarConfig(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "config.yaml"), "detector:\n  core: singbox\n")
	composePath := filepath.Join(root, "docker-compose.yml")
	mustWriteFile(t, composePath, "version: '3.8'\nservices:\n  dynamic-proxy:\n    image: demo\n")

	sidecarPath := filepath.Join(root, defaultSidecarConfigRelPath)
	mustWriteFile(t, sidecarPath, "{not-json")

	result, err := Run(root, "", "", log.New(os.Stdout, "", 0))
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !result.SidecarConfigChanged {
		t.Fatalf("expected corrupted sidecar config to be repaired")
	}
	if !json.Valid([]byte(mustReadFile(t, sidecarPath))) {
		t.Fatalf("expected repaired sidecar config to be valid json")
	}
	backups, err := filepath.Glob(sidecarPath + ".bak.*")
	if err != nil {
		t.Fatalf("glob backup files failed: %v", err)
	}
	if len(backups) == 0 {
		t.Fatalf("expected backup file for corrupted sidecar config")
	}
}

func readComposeYAML(t *testing.T, composePath string) map[string]any {
	t.Helper()
	raw := mustReadFile(t, composePath)
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parse compose yaml failed: %v", err)
	}
	return doc
}

func containsEnvKey(raw any, key string) bool {
	switch env := raw.(type) {
	case []any:
		for _, item := range env {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if strings.TrimSpace(s) == key || strings.HasPrefix(strings.TrimSpace(s), key+"=") {
				return true
			}
		}
	case map[string]any:
		_, ok := env[key]
		return ok
	}
	return false
}

func containsEnvEntry(raw any, entry string) bool {
	switch env := raw.(type) {
	case []any:
		for _, item := range env {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if strings.TrimSpace(s) == entry {
				return true
			}
		}
	}
	return false
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file failed for %s: %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file failed for %s: %v", path, err)
	}
	return string(raw)
}
