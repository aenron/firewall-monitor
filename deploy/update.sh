#!/usr/bin/env bash
# Run after git pull. Images must both exist before running containers change.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tag="${1:-latest}"
if [[ ! "$tag" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$ ]]; then
  echo 'Invalid image tag' >&2
  exit 2
fi
export IMAGE_TAG="$tag"
docker compose -f compose.yaml pull
docker compose -f compose.yaml up -d --no-build
# The restricted Fail2ban executor remains a native host service.
systemctl restart firewall-monitor-agent
docker compose -f compose.yaml ps
systemctl is-active firewall-monitor-agent
