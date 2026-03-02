$ErrorActionPreference = 'Stop'

Write-Host "[docker-up] applying docker singbox autofix from config.yaml ..."
& 'C:\Program Files\Go\bin\go.exe' run .\cmd\docker-autofix --project-root .

Write-Host "[docker-up] starting services with docker compose ..."
docker compose up -d

