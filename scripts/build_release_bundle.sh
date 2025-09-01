#!/usr/bin/env bash
set -euo pipefail
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="dist/assessment-${TS}.zip"
mkdir -p dist artifacts
echo "[*] Collecting artifacts"
cp -r integrations/runtime artifacts/ || true
mkdir -p artifacts/signet && curl -sS http://localhost:8000/sth -o artifacts/signet/sth.json || true
echo "[*] Building bundle ${OUT}"
zip -r "${OUT}" docs schema artifacts || true
sha256sum "${OUT}" > "dist/assessment-${TS}.sha256"
echo "${OUT}"
