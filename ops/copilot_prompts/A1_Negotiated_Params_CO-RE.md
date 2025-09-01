# Task A1 — Negotiated Parameters via BPF CO‑RE

## Goal
Populate `tls.group_selected` and `tls.cipher_selected` by reading from `SSL*` at `SSL_do_handshake` exit.

## Do
1) In `introspection-engine/ebpf-core/openssl_handshake.bpf.c`:
   - At `SSL_do_handshake_exit`, add CO‑RE reads into internal SSL fields to extract selected group/cipher NIDs.
   - Write them into a new event struct fields (e.g., `nid_group`, `nid_cipher`). Keep ringbuf payload ≤ 4KB.
2) In loader (`main.go`):
   - Map NIDs to human‑readable names; fill `NegotiatedSource = "bpf_core"`.
   - Add unit tests that feed synthetic events to mapping.
3) Update `ops/` smoke prompt to check presence of `group_selected` for at least 1 obs.

## Acceptance Criteria
- `group_selected` appears in `integrations/runtime/runtime.jsonl` for successful handshakes.
- No loader panic; ringbuf drops ≤ 2% in smoke test.
