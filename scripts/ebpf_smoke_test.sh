#!/usr/bin/env bash
set -euo pipefail
DUR="${1:-10}"
OUT="integrations/runtime/runtime.jsonl"

echo "[*] Building BPF + loader"
pushd introspection-engine/ebpf-core >/dev/null
make
popd >/dev/null
go build -o introspection-engine/ebpf-core/go-loader/bin/carnot-ebpf-loader ./introspection-engine/ebpf-core/go-loader

echo "[*] Running loader for ${DUR}s (sudo likely required)"
sudo ./introspection-engine/ebpf-core/go-loader/bin/carnot-ebpf-loader -obj introspection-engine/ebpf-core/openssl_handshake.bpf.o -out "${OUT}" &
PID=$!
sleep 1

echo "[*] Generating HTTPS traffic with curl"
for i in $(seq 1 50); do
  curl -sS https://example.org >/dev/null || true
done

sleep "${DUR}" || true
echo "[*] Stopping loader"
sudo kill ${PID} || true
sleep 1

echo "[*] Converting to CCM"
python3 integrations/runtime/ebpf_to_ccm.py "${OUT}" "integrations/runtime/runtime.ccm.json" || true
ls -l integrations/runtime/

# Basic sanity: ensure at least one observation with group_selected if present
if [ -f integrations/runtime/runtime.jsonl ]; then
  if grep -q '"group_selected"' integrations/runtime/runtime.jsonl; then
    echo "[OK] group_selected observed"
  else
    echo "[WARN] group_selected not observed; check CO-RE read support for this libssl/build"
  fi
fi
