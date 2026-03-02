package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"dynamic-proxy/internal/dockerfix"
)

func main() {
	var (
		projectRoot string
		configPath  string
		composePath string
	)

	flag.StringVar(&projectRoot, "project-root", ".", "project root directory")
	flag.StringVar(&configPath, "config", "", "config.yaml path (default: <project-root>/config.yaml)")
	flag.StringVar(&composePath, "compose", "", "docker-compose.yml path (default: <project-root>/docker-compose.yml)")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		logger.Fatalf("[docker-autofix] resolve project root failed: %v", err)
	}

	result, err := dockerfix.Run(absRoot, configPath, composePath, logger)
	if err != nil {
		logger.Fatalf("[docker-autofix] failed: %v", err)
	}

	logger.Printf("[docker-autofix] done: core=%s changed=%t", result.Core, result.Changed)
}
