# Honest Ear — top-level developer convenience targets (host side).
#
#   make test       - all host tests (C units, Go units, e2e + vision-e2e, tamper)
#   make sim        - build the host simulators + CLIs
#   make e2e        - audio end-to-end pipeline;  make vision-e2e - vision pipeline
#   make gui/sites/fuzz/repro/cross - GUI, static site, fuzzing, reproducible-build,
#                     Raspberry Pi cross-compile
#   make clean      - remove build artifacts
#
# The OP-TEE TA/PTA/host code is built on the target rig — see docs/RUNBOOK.md.
# The zk/ (RISC Zero, cargo) and onchain/ (Foundry, forge) legs build via their
# own subdir tooling, not this Makefile — see zk/README.md and onchain/README.md.

VERIFIER = src/verifier

.PHONY: test units sim verifier-test e2e vision-e2e tamper-test gui sites fuzz repro cross clean

test: units verifier-test e2e vision-e2e tamper-test
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

# Tamper watcher breach action (key-shred + flag-latch), no hardware.
tamper-test:
	$(MAKE) -C src/tamper test

# Browser click-to-listen web UI (http://localhost:8095).
gui:
	tools/run_gui.sh

# Launch all local web surfaces (landing site + GUI + challenge/phone page).
sites:
	bash tools/sites.sh

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
