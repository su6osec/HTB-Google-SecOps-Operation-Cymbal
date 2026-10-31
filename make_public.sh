#!/usr/bin/env bash
# ==============================================================================
# Script: make_public.sh
# Purpose: Transition su6osec/HTB-Google-SecOps-Operation-Cymbal from private to public
# Target Time: Nov 01 2026, 09:30 PM IST (21:30 IST / 16:00 UTC)
# ==============================================================================

set -euo pipefail

REPO_OWNER="su6osec"
REPO_NAME="HTB-Google-SecOps-Operation-Cymbal"

# Retrieve token
TOKEN=""
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    TOKEN="${GITHUB_TOKEN}"
else
    TOKEN="$(zsh -c 'source ~/.zshrc 2>/dev/null; ght' 2>/dev/null || true)"
fi

if [[ -z "${TOKEN}" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Error: Could not retrieve GitHub token." >&2
    exit 1
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Updating visibility of ${REPO_OWNER}/${REPO_NAME} to PUBLIC..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}" \
  -d '{"private": false}')

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
BODY=$(echo "${RESPONSE}" | sed '$d')

if [[ "${HTTP_CODE}" == "200" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: Repository ${REPO_OWNER}/${REPO_NAME} is now PUBLIC!"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Link: https://github.com/${REPO_OWNER}/${REPO_NAME}"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED with HTTP ${HTTP_CODE}:" >&2
    echo "${BODY}" >&2
    exit 1
fi
