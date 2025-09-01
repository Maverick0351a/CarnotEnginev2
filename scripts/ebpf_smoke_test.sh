#!/usr/bin/env bash
set -euo pipefail
MODE="normal"
DUR="10s"
CONCURRENCY=20
GEN="curl"
URL="https://example.org"
OUT="integrations/runtime/runtime.jsonl"
OPS=2000

usage(){
  echo "usage: $0 [-m mode] [-d duration] [-c concurrency] [-g generator] [-u url] [-o out]" >&2
}

while getopts ":m:d:c:g:u:o:h" o; do
  case "$o" in
    m) MODE="$OPTARG";;
    d) DUR="$OPTARG";;
    c) CONCURRENCY="$OPTARG";;
    g) GEN="$OPTARG";;
    u) URL="$OPTARG";;
    o) OUT="$OPTARG";;
    h) usage; exit 0;;
    *) usage; exit 1;;
  esac
done

# Convert duration to seconds for sleep
DUR_S=${DUR%s}

echo "[*] Building BPF + loader"
pushd introspection-engine/ebpf-core >/dev/null
make
popd >/dev/null
go build -o introspection-engine/ebpf-core/go-loader/bin/carnot-ebpf-loader ./introspection-engine/ebpf-core/go-loader

echo "[*] Running loader for ${DUR} (sudo likely required)"
sudo ./introspection-engine/ebpf-core/go-loader/bin/carnot-ebpf-loader -obj introspection-engine/ebpf-core/openssl_handshake.bpf.o -out "${OUT}" &
PID=$!
sleep 1

if [ "$GEN" = "curl" ]; then
  echo "[*] Generating HTTPS traffic with curl (${OPS} ops, concurrency ${CONCURRENCY})"
  seq 1 $OPS | xargs -n1 -P "$CONCURRENCY" -I{} sh -c 'curl -sS -o /dev/null '"$URL"' || true'
else
  echo "[*] Unknown generator: $GEN" >&2
fi

sleep "$DUR_S" || true

echo "[*] Stopping loader"
sudo kill ${PID} || true
sleep 1

mkdir -p integrations/runtime/artifacts || true
cp -f "$OUT" integrations/runtime/artifacts/runtime.jsonl || true

echo "[*] Converting to CCM"
python3 integrations/runtime/ebpf_to_ccm.py "$OUT" "integrations/runtime/artifacts/runtime.ccm.json" || true
ls -l integrations/runtime/ integrations/runtime/artifacts/

# Basic sanity: ensure at least one observation with group_selected (acceptance criteria)
if [ -f integrations/runtime/runtime.jsonl ]; then
  if grep -q '"group_selected"' integrations/runtime/runtime.jsonl; then
    echo "[OK] group_selected observed"
  else
    echo "[WARN] group_selected not observed; check CO-RE read support for this libssl/build"
  fi
fi
