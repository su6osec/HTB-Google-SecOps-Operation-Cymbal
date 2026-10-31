#!/usr/bin/env bash
# ==============================================================================
# Script: make_public.sh
# Purpose: Transition the repository su6osec/HTB-Google-SecOps-Operation-Cymbal
#          from private to public on or after Nov 01 2026, 09:30 PM IST.
# ==============================================================================

set -euo pipefail

REPO_OWNER="su6osec"
REPO_NAME="HTB-Google-SecOps-Operation-Cymbal"

# Retrieve GitHub Token
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    TOKEN="${GITHUB_TOKEN}"
elif command -v ght &>/dev/null; then
    TOKEN="$(zsh -i -c 'ght' 2>/dev/null || ght)"
else
    echo "[-] Error: GITHUB_TOKEN environment variable not set and ght command not found." >&2
    exit 1
fi

echo "[*] Updating repository visibility to public for ${REPO_OWNER}/${REPO_NAME}..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}" \
  -d '{"private": false}')

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
BODY=$(echo "${RESPONSE}" | sed '$d')

if [[ "${HTTP_CODE}" == "200" ]]; then
    echo "[+] Success! Repository ${REPO_OWNER}/${REPO_NAME} is now PUBLIC."
    echo "[+] URL: https://github.com/${REPO_OWNER}/${REPO_NAME}"
else
    echo "[-] Failed with HTTP ${HTTP_CODE}:" >&2
    echo "${BODY}" >&2
    exit 1
fi
