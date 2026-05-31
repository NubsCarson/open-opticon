# Contributing

Thanks for your interest. open-opticon is a small, dependency-light PoC; the bar
is "clean, tested, honestly scoped."

## Build & test (host)

Everything host-runnable is gated by one command — no Docker, no Arm hardware:

```sh
make test          # C unit tests + Go unit tests + e2e pipeline + tamper self-test
```

Requirements: `gcc`, `go` (>=1.23), `openssl`, `python3`. CI runs exactly this
on every push (`.github/workflows/ci.yml`).

The OP-TEE TA/PTA/host code under `src/optee/` builds on an Arm rig against the
optee-ra tree — see [`docs/RUNBOOK.md`](docs/RUNBOOK.md). Please don't claim a
change is "tested" if you've only built the host side; say which.

## Style

- **Go:** `gofmt` clean and `go vet ./...` clean (stdlib only — no new deps).
- **C:** integer-only, allocation-free in the shared `src/common/` code (it
  compiles into the TA); match the surrounding style; no warnings under
  `-Wall -Wextra -Wpedantic`.
- **Shell:** `shellcheck`-clean; `set -euo pipefail` where it fits
  (`test/run_e2e.sh` deliberately omits `-e` because it tallies its own pass/fail).
- Keep the wire formats (`he_payload.h`) and the byte-identical
  signer/verifier contract intact — add a test if you touch them.

## Scope & honesty

This project lives or dies on **not overclaiming**. If you add a capability,
update [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) to match, and keep the
"proven here vs on the rig" distinction accurate in the README.

## PRs

Small, focused PRs with a clear description. Note whether you ran `make test`
and/or the on-rig flow. By contributing you agree your work is licensed under
the repository's MIT license.
