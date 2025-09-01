# Task A5 — HEL allowlist & SPKI pinning

## Goal
Enforce egress allowlist and optional SPKI pins from `ops/hel_allowlist.txt` and `ops/spki_pins.txt`.

## Do
1) Loader: before any HTTP egress to API, verify destination host is in HEL list; if pins exist, enforce.
2) Add `scripts/hel_lint.sh` checks for syntax.
3) Provide negative test: blocked host.

## Acceptance Criteria
- Calls to non-allowlisted host are blocked with clear logs.
- Linter passes with provided files.
