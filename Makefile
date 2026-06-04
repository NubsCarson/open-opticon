# Honest Ear — top-level developer convenience targets (host side).
#
#   make verify-all - run every laptop check (no r0vm) with PASS/SKIP — see docs/VERIFY.md
#   make test       - all host tests (C units, Go units, e2e + vision + chain, tamper)
#   make sim        - build the host simulators + CLIs
#   make e2e        - audio end-to-end pipeline;  make vision-e2e - vision pipeline
#   make chain-e2e  - streaming hash-chain: append-only stream + gap detection
#   make cose-e2e   - COSE_Sign1 (RFC 9052) envelope: emit (C) -> verify (Go)
#   make witness-e2e - operating log witnesses: cosign quorum + fork refusal
#   make multimodal-e2e - audio + vision verdicts co-attested to one nonce
#   make consent-e2e - Track-6 threshold reveal + consent-gated window disclosure
#   make endorse-e2e - signed endorsements: endorser authenticity + log inclusion
#   make eat-e2e    - PSA attestation-token (EAT) offline verify vs a committed fixture
#   make tpm-e2e    - heterogeneous root: a TPM-resident key signs (needs swtpm+tpm2-tools)
#   make quorum-hetero-e2e - sim + TPM roots agree via he-verify --quorum (needs swtpm)
#   make voxterm-e2e - portable restraint receipts (VoxTerm bridge): see docs/INTEGRATIONS.md
#   make voxterm-demo - narrated walkthrough of the restraint-receipt bridge
#   make port-diff  - C detector == Rust zk port, differential test (needs cargo)
#   make demo       - whole thesis on one clip: TEE + ZK + on-chain 2-of-2 agree
#   make wasm-verify - committed docs/verify.wasm + wasm_exec.js match their pinned SHA-256
#   make gui/sites/fuzz/repro/cross - GUI, static site, fuzzing, reproducible-build,
#                     Raspberry Pi cross-compile
#   make clean      - remove build artifacts
#
# The OP-TEE TA/PTA/host code is built on the target rig — see docs/RUNBOOK.md.
# The zk/ (RISC Zero, cargo) and onchain/ (Foundry, forge) legs build via their
# own subdir tooling, not this Makefile — see zk/README.md and onchain/README.md.

VERIFIER = src/verifier

.PHONY: help test units sim verifier-test fixtures e2e vision-e2e chain-e2e cose-e2e witness-e2e voxterm-e2e multimodal-e2e consent-e2e endorse-e2e eat-e2e tpm-e2e quorum-hetero-e2e voxterm-demo verify-all port-diff demo tamper-test gui sites wasm wasm-verify fuzz repro cross clean

test: units verifier-test e2e vision-e2e chain-e2e cose-e2e witness-e2e voxterm-e2e multimodal-e2e consent-e2e endorse-e2e eat-e2e tamper-test
	@echo ""
	@echo "==================================================="
	@echo " ALL HOST TESTS PASSED"
	@echo "==================================================="

sim:
	$(MAKE) -C sim all

# C unit tests (audio detector + payload + vision detector).
units: sim
	$(MAKE) -C sim test

# Go verifier unit tests (stdlib runtime; offline; -race guards the concurrent
# attest/anti-replay paths in he-challenge). Depends on sim + fixtures so the
# exec-based tests (TestSimEmitsLowS audio/vision, TestProcessE2E) actually RUN
# here instead of skipping — verifier-test runs before e2e/vision-e2e, which
# would otherwise be the first thing to generate these fixtures.
verifier-test: sim fixtures
	cd $(VERIFIER) && CGO_ENABLED=1 GOPROXY=off go test -race ./...

# Generated test fixtures (audio tones + vision frames; stdlib-python only) that
# the exec-based verifier tests read. Best-effort: without python3 the tests fall
# back to their built-in skip rather than failing the build.
fixtures:
	@if command -v python3 >/dev/null 2>&1; then \
		python3 test/gen_frames.py test/fixtures >/dev/null; \
		python3 test/gen_vision_frames.py test/fixtures >/dev/null; \
	else \
		echo "  (python3 not found — skipping fixture generation; exec-based tests will skip)"; \
	fi

# Full detect -> sign -> verify pipeline incl. negative attacks.
e2e:
	bash test/run_e2e.sh

# Same machinery, a camera: vision detect -> bind -> verify with the same he-verify.
vision-e2e:
	bash test/run_vision_e2e.sh

# Streaming hash-chain: an append-only stream verifies; a suppressed window
# breaks the chain (prev_digest gap detection), no hardware.
chain-e2e:
	bash test/run_chain_e2e.sh

# COSE_Sign1 (RFC 9052) envelope: emit (C) -> verify (Go), same key/payload,
# standards-aligned signed structure; binding holds; raw envelope unaffected.
cose-e2e:
	bash test/run_cose_e2e.sh

# Operating witnesses: he-logd serves checkpoints; he-witness daemons consistency-
# check + cosign; a 2-of-3 quorum verifies; a forked/rewound log is refused.
witness-e2e:
	bash test/run_witness_e2e.sh

# Portable "restraint receipts" (the VoxTerm bridge): a transcription session ->
# signed, hash-chained receipts (audio in, only text out) -> verify + transparency
# log + gap detection. See docs/INTEGRATIONS.md.
voxterm-e2e:
	bash test/run_voxterm_e2e.sh

# Multi-modal co-attestation: an audio AND a vision verdict, each a fresh signature
# bound to the SAME nonce, accepted by `he-verify --co-attest 2`. Cross-modal
# sibling of the quorum (same challenge, not same event).
multimodal-e2e:
	bash test/run_multimodal_e2e.sh

# Track-6 consent mechanisms: k-of-n threshold reveal + consent-gated single-window
# disclosure (he-consent, wrapping threshold.go).
consent-e2e:
	bash test/run_consent_e2e.sh

# Signed endorsements: an endorser vouches for a device key (signed body), the body
# is logged, and a verifier confirms both endorser authenticity + log inclusion.
endorse-e2e:
	bash test/run_endorse_e2e.sh

# PSA attestation-token (EAT) offline verify: he-attest-verify against a committed
# faithful token fixture; happy path + wrong-nonce/key/ref + tamper negatives.
eat-e2e:
	bash test/run_eat_e2e.sh

# Skeptic's entry point: run every laptop-runnable, no-r0vm check and print
# PASS/SKIP per check (host suite, port-diff, repro, demo, wasm, TPM, on-chain).
# Maps to the claim->command->tier table in docs/VERIFY.md. Not in `test` (heavy
# meta-target; CI runs these individually).
verify-all:
	bash tools/verify_all.sh

# Print the target list from this file's header.
help:
	@grep -E '^#   make ' $(MAKEFILE_LIST) | sed 's/^#   //'

# Heterogeneous-root demo: a TPM-resident P-256 key (private half never leaves the
# TPM) signs an artifact the unmodified verifier accepts — shows the verifier is
# root-agnostic. Needs swtpm + tpm2-tools; SELF-SKIPS cleanly if absent. NOT in the
# default `test` aggregate (it has its own CI job) so offline boxes stay green.
tpm-e2e:
	bash test/run_tpm_e2e.sh

# Heterogeneous-root QUORUM: a sim P-256 root AND a TPM-resident P-256 root both
# sign the same bound output; `he-verify --quorum 2` accepts the two independent
# roots. Needs swtpm + tpm2-tools; SELF-SKIPS if absent. Own CI job (like tpm-e2e),
# not in the default aggregate.
quorum-hetero-e2e:
	bash test/run_quorum_hetero_e2e.sh

# Narrated walkthrough of the restraint-receipt bridge (a readable demo of
# voxterm-e2e: emit -> verify -> gap + tamper + retained negatives -> the
# 5-question receipt view). Self-contained; does not touch the VoxTerm repo.
voxterm-demo:
	bash tools/voxterm_demo.sh

# C detector == Rust zk port: differential test over the shared fixtures (needs cargo).
port-diff:
	bash test/run_port_diff.sh

# The whole thesis on one clip: TEE attestation + ZK proof + on-chain 2-of-2 all
# agree on the same observation, bound to the same audio (forge leg if available).
demo:
	bash test/run_demo.sh

# Tamper watcher breach action (key-shred + flag-latch), no hardware.
tamper-test:
	$(MAKE) -C src/tamper test

# Browser click-to-listen web UI (http://localhost:8095).
gui:
	tools/run_gui.sh

# Launch all local web surfaces (landing site + GUI + challenge/phone page).
sites:
	bash tools/sites.sh

# Compile the stdlib-only verifier to WebAssembly for the in-browser verifier
# (docs/verify.html) — same code path as he-verify, no server, no install.
wasm:
	bash tools/build_wasm.sh

# Download-integrity gate: the committed in-browser artifacts (docs/verify.wasm +
# wasm_exec.js) must match the published digest in docs/verify.wasm.sha256, so a
# `sha256sum -c` after downloading them confirms they weren't tampered with. This
# checks the COMMITTED pair (not a rebuild) — it catches a verify.wasm refresh
# that forgot to update the digest. Reproducibility of the build is a separate
# guarantee (`make repro` + the wasm smoke test rebuild it from source).
wasm-verify:
	cd docs && sha256sum -c verify.wasm.sha256

# Fuzz the CBOR decoder (Ctrl-C to stop; the seed corpus runs under `make test`).
fuzz:
	cd $(VERIFIER) && GOPROXY=off go test -run x -fuzz FuzzDecodePayload .

# Prove the host build is path/time-independent (byte-identical rebuilds).
repro:
	bash tools/repro.sh

# Cross-compile the Go verifier tools for Raspberry Pi (arm64 + armv7) and amd64.
cross:
	bash tools/cross.sh

clean:
	$(MAKE) -C sim clean
	$(MAKE) -C src/tamper clean
	rm -rf test/fixtures/*.pcm dist
	cd $(VERIFIER) && go clean ./... 2>/dev/null || true
