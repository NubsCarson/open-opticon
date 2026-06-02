#!/usr/bin/env bash
#
# verify_all.sh — one command that runs every laptop-runnable, no-r0vm check in
# the repo and prints a PASS/SKIP line per check. This is the skeptic's entry
# point: clone, run `make verify-all`, and confirm the claims yourself. Each check
# maps to a claim in docs/VERIFY.md.
#
# It runs NO prover (r0vm) and needs NO hardware or testnet funds. Checks that need
# an optional tool (Foundry, Rust, Node, network) SKIP cleanly rather than fail, so
# a green run means "everything runnable here passed" and skips are stated openly.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
passed=0; skipped=0; failed=0
PASS() { printf '  \033[1;32mPASS\033[0m  %s\n' "$1"; passed=$((passed+1)); }
SKIP() { printf '  \033[1;33mSKIP\033[0m  %s (%s)\n' "$1" "$2"; skipped=$((skipped+1)); }
FAIL() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; failed=$((failed+1)); }

# run <claim> <command...> — PASS if it exits 0, FAIL otherwise.
run() { local claim="$1"; shift; if "$@" >/tmp/va.log 2>&1; then PASS "$claim"; else FAIL "$claim"; tail -3 /tmp/va.log | sed 's/^/      /'; fi; }

echo "== open-opticon: verify everything (laptop, no r0vm, no funds) =="
echo

echo "Tier 1 — software integrity, binding, and verification (host):"
run "host test suite (C+Go units, all e2e, tamper, -race)" make test
run "C detector == Rust zk-port (bit-identical verdicts)" bash test/run_port_diff.sh
run "byte-reproducible host build (two independent trees)" bash tools/repro.sh

echo
echo "Cross-root + Track-6 + accountability:"
run "cross-root demo (TEE + ZK + audio binding agree)" make demo
if command -v node >/dev/null 2>&1; then
  ( bash tools/build_wasm.sh && node test/wasm_verify_test.js ) >/tmp/va.log 2>&1 \
    && PASS "in-browser WASM verifier matches the CLI" || { FAIL "WASM verifier smoke"; tail -3 /tmp/va.log | sed 's/^/      /'; }
else SKIP "in-browser WASM verifier matches the CLI" "node not installed"; fi
if command -v swtpm >/dev/null 2>&1 && command -v tpm2_sign >/dev/null 2>&1; then
  run "heterogeneous TPM root (in-TPM key, verifier accepts)" make tpm-e2e
else SKIP "heterogeneous TPM root" "swtpm/tpm2-tools not installed"; fi

echo
echo "On-chain (permissionless verification of the zk receipt + dual-root quorum):"
if command -v forge >/dev/null 2>&1 && [ -d onchain/lib/forge-std ]; then
  run "zk receipt + dual-root quorum verify on a local EVM" bash -c 'cd onchain && forge test'
else SKIP "on-chain verify on a local EVM" "forge/deps not installed (live on Sepolia regardless)"; fi
if [ "${VERIFY_SEPOLIA:-0}" = "1" ]; then
  run "live Sepolia quorum returns the agreed verdict" bash onchain/call-sepolia.sh
else SKIP "live Sepolia eth_call" "set VERIFY_SEPOLIA=1 to hit the network"; fi

echo
echo "== verify-all: $passed passed, $skipped skipped, $failed failed =="
[ "$failed" -eq 0 ] || exit 1
