# Task A00 — Onboarding, Environment, Repo Init

## Goal
Prepare local dev; create a new GitHub repo with CI enabled and branch protection; verify toolchains.

## Do
1) Install prereqs:
   - Ubuntu/Debian: `sudo apt-get update && sudo apt-get install -y clang make bpftool libbpf-dev golang-go python3-pip python3-venv sqlite3`
   - Python: `python3 -m venv .venv && source .venv/bin/activate && pip install -r api/requirements.txt jsonschema`
2) Create GitHub repo `carnotengine` (or chosen name). Push initial commit.
3) Enable GitHub Actions. Protect `main` (require PR + status checks).
4) Run: `bash scripts/hel_lint.sh` and `python3 integrations/runtime/ebpf_to_ccm.py /dev/null /tmp/x.json || true` (should print usage).

## Acceptance Criteria
- `git remote -v` shows origin.
- `.github/workflows/tests.yml` runs on PR.
- `WORKLOG.md` updated with onboarding entry.
