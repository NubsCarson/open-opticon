# Honest Ear — top-level developer convenience targets (host side).
#
#   make test   - build + run all host-runnable tests (C units, Go units, e2e)
#   make sim    - build the host simulator + CLIs
#   make e2e    - run the end-to-end pipeline test
#   make clean  - remove build artifacts
#
# The OP-TEE TA/PTA/host code is built on the target rig — see docs/RUNBOOK.md.

VERIFIER = src/verifier

.PHONY: test units sim verifier-test e2e tamper-test gui fuzz repro cross clean

test: units verifier-test e2e tamper-test
	@echo ""
	@echo "==================================================="
	@echo " ALL HOST TESTS PASSED"
	@echo "==================================================="

sim:
	$(MAKE) -C sim all

# C unit tests (detector + payload).
units: sim
	$(MAKE) -C sim test

# Go verifier unit tests (stdlib only, offline).
verifier-test:
	cd $(VERIFIER) && GOPROXY=off go test ./...

# Full detect -> sign -> verify pipeline incl. negative attacks.
e2e:
	bash test/run_e2e.sh

# Tamper watcher breach action (key-shred + flag-latch), no hardware.
tamper-test:
	$(MAKE) -C src/tamper test

# Browser click-to-listen web UI (http://localhost:8095).
gui:
	tools/run_gui.sh

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
	rm -rf test/fixtures/*.pcm
	cd $(VERIFIER) && go clean ./... 2>/dev/null || true
