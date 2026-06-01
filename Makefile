# Honest Ear — top-level developer convenience targets (host side).
#
#   make test       - all host tests (C units, Go units, e2e + vision + chain, tamper)
#   make sim        - build the host simulators + CLIs
#   make e2e        - audio end-to-end pipeline;  make vision-e2e - vision pipeline
#   make chain-e2e  - streaming hash-chain: append-only stream + gap detection
#   make cose-e2e   - COSE_Sign1 (RFC 9052) envelope: emit (C) -> verify (Go)
#   make witness-e2e - operating log witnesses: cosign quorum + fork refusal
#   make voxterm-e2e - portable restraint receipts (VoxTerm bridge): see docs/INTEGRATIONS.md
#   make port-diff  - C detector == Rust zk port, differential test (needs cargo)
#   make demo       - whole thesis on one clip: TEE + ZK + on-chain 2-of-2 agree
#   make gui/sites/fuzz/repro/cross - GUI, static site, fuzzing, reproducible-build,
#                     Raspberry Pi cross-compile
#   make clean      - remove build artifacts
#
# The OP-TEE TA/PTA/host code is built on the target rig — see docs/RUNBOOK.md.
# The zk/ (RISC Zero, cargo) and onchain/ (Foundry, forge) legs build via their
# own subdir tooling, not this Makefile — see zk/README.md and onchain/README.md.

VERIFIER = src/verifier

.PHONY: test units sim verifier-test e2e vision-e2e chain-e2e cose-e2e witness-e2e voxterm-e2e port-diff demo tamper-test gui sites wasm fuzz repro cross clean

test: units verifier-test e2e vision-e2e chain-e2e cose-e2e witness-e2e voxterm-e2e tamper-test
	@echo ""
	@echo "==================================================="
	@echo " ALL HOST TESTS PASSED"
	@echo "==================================================="

sim:
	$(MAKE) -C sim all

# C unit tests (audio detector + payload + vision detector).
units: sim
	$(MAKE) -C sim test

# Go verifier unit tests (stdlib only, offline).
verifier-test:
	cd $(VERIFIER) && GOPROXY=off go test ./...

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
