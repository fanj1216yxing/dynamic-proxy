#!/usr/bin/env sh
set -eu

echo "[docker-up] applying docker singbox autofix from config.yaml ..."
go run ./cmd/docker-autofix --project-root .

echo "[docker-up] starting services with docker compose ..."
docker compose up -d

