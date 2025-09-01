# Task A3 — Key Rotation, JWKS, Persistent TL

## Goal
Promote signing to production-grade basics: rotation, JWKS endpoint, persistent transparency log file.

## Do
1) `signet/keyprovider.py`: add rotation schedule + persisted key-id history (memory ok).
2) `api/main.py`:
   - Serve `/jwks.json` from KeyProvider.
   - Ensure `/sth` reflects the latest root with signature and key id.
3) `signet/transparency_log.py`: keep sqlite DB path configurable via env `SIGNET_TL_PATH`.

## Acceptance Criteria
- Hitting `/ingest` increases `treeSize` on `/sth`.
- Rotating key changes `kid` in `/jwks.json` and in new receipts.
