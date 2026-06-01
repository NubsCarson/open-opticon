# open-opticon

[![host tests](https://github.com/NubsCarson/open-opticon/actions/workflows/ci.yml/badge.svg)](https://github.com/NubsCarson/open-opticon/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **the panopticon, inside-out** — open source, see-through, and it proves its own restraint.
>
> *(internal codename: **Honest Ear**)*

**A microphone that cryptographically proves it's only listening for the one
thing it claims to — not recording you — and goes cryptographically dead the
instant someone opens it.**

> **Site:** <https://nubscarson.github.io/open-opticon/> (or open
> [`docs/index.html`](docs/index.html) locally / `python3 -m http.server -d docs 8099`). &nbsp;·&nbsp;
> **Walkthrough video:** [`docs/assets/walkthrough.mp4`](docs/assets/walkthrough.mp4)
> — real captured output: the host pipeline, an OP-TEE attestation on QEMU, the
> in-enclave bound output, and the tamper fail-closed path.

> ⚠️ **Status: proof-of-concept / d/acc art project.** The host pipeline is fully
> tested (`make test`). The OP-TEE path has been **run end-to-end on QEMU to a
> green, `affirming` Veraison attestation** — real TA + `PTA_SIGN_DATA` → signed
> PSA token → verified ([proof](docs/SAMPLE_ATTESTATION.md); reproduce via
> [`docs/RUNBOOK.md`](docs/RUNBOOK.md); not part of CI). It proves software
> integrity + output provenance, **not** nation-state confidentiality — read
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before you trust it with anything real.

**What is this for?** Verifiable, privacy-preserving sensing — prove a fact about
the physical world (an alarm sounded, a room is occupied) *without* the raw
audio ever leaving the device. See [`docs/USE_CASES.md`](docs/USE_CASES.md).

Honest Ear is a *verifiable, non-panopticon* acoustic sensor built on
[`optee-ra`](https://github.com/iisec-suzaki/optee-ra) (OP-TEE remote
attestation on Arm TrustZone, verified by Veraison). Audio capture and a tiny
event detector run **inside the secure world**; the raw audio is zeroized
immediately; the only thing that ever leaves the enclave is a **minimal,
non-reconstructable predicate** (e.g. "alarm tone detected", "voice present"),
cryptographically **bound to the same hardware key whose firmware identity is
proven by remote attestation**.

So instead of *"trust us, we delete your audio"*, anyone can **verify**: this is
the published, source-auditable firmware — and that firmware has no code path
that emits speech. The device proves its own restraint.

> This inverts content-provenance systems like C2PA, which sign raw content they
> *receive*. Honest Ear attests the honest *transformation inside the enclave*
> and emits only the bound, minimal result.

## Why it's different

| | C2PA / signed cameras | Phone app | **Honest Ear** |
|---|---|---|---|
| Proves *which code* ran | no | Play Integrity (closed, Google-rooted) | **yes — attested firmware hash** |
| Raw media leaves the trusted boundary | yes (signs after capture) | yes | **no — zeroized in-enclave** |
| Output bound to attested key | no | no | **yes — `PTA_SIGN_DATA` over canonical payload** |
| Anti-replay / live challenge | n/a | n/a | **yes — fresh nonce + monotonic counter** |
| Anti-suppression (dropped window) | n/a | n/a | **yes — append-only `prev_digest` hash-chain** |
| Open / permissionless verification | partial | no | **yes — Veraison + open verifier** |

## Repository layout

```
src/common/      Shared, pure-C, integer-only sources compiled into BOTH the TA
                 and the host tests (so tests exercise production code):
                   he_detector.[ch]  - VAD + Goertzel alarm-tone detector
                   he_vision.[ch]    - vision occupancy detector (empty/occupied)
                   he_payload.[ch]   - deterministic-CBOR bound-output payload
                   he_serialize.h    - shared big-endian config-blob serializer
                   he_testkey.h      - published QEMU test key (NOT secret)
src/optee/       OP-TEE integration (builds on the rig):
                   pta/  PTA_SIGN_DATA command + INTEGRATION.md
                   ta/   ATTEST_AUDIO + TRIP_TAMPER TA commands + INTEGRATION.md
                   host/ he_host CA + INTEGRATION.md
src/verifier/    Go (stdlib only) verifier:
                   bound.go        - 4-gate bundle verify (sig/pin/freshness/replay)
                   quorum.go       - k-of-n multi-prover quorum (reuses bound.go)
                   transparency.go - RFC 6962 endorsement log (inclusion/consistency)
                   cmd/he-verify   - verify a bundle (raw or --cose), or a --quorum of provers
                   cmd/he-dump     - decode a bundle to readable fields (no verify) — audit aid
                   cmd/he-attest-verify - verify a PSA attestation token (EAT) offline
                   cmd/he-log      - operate/prove/verify the transparency log
                   cmd/he-logd     - HTTP log server (checkpoints + consistency proofs)
                   cmd/he-witness  - witness daemon: consistency-check + cosign, refuse forks
                   cmd/he-challenge - live nonce server + mobile verifier page (/v)
                   cmd/he-gui      - browser click-to-listen web UI
                   cmd/he-verify-wasm - the verifier compiled to WASM for docs/verify.html
                   + unit tests, exhaustive log tests, and FuzzDecodePayload
zk/              RISC Zero zkVM proof of the detector (Rust): a faithful no_std
                 port of he_detector.c proven over private audio, committing only
                 the verdict — a non-TEE prover leg for the quorum (see zk/README.md)
onchain/         Foundry project: HonestEarVerifier.sol verifies the zk Groth16
                 receipt for the pinned guest imageId on an EVM, so the verdict is
                 permissionlessly checkable with no operator/enclave trusted; a real
                 proof fixture verifies on a local EVM via `forge test` (see
                 onchain/README.md)
src/tamper/      Linux GPIO tamper-loop watcher (key-destroy on enclosure breach)
sim/             Host simulators mirroring the TEE crypto path: he-attest-sim
                 (audio) and the vision signer (he_vision_sign.c), both emitting
                 via the one shared signing+envelope path (he_bundle.[ch]); plus
                 the detector CLI (he_detect_cli.c)
test/            Fixture generators (audio + vision), C unit tests
                 (detector/payload/vision), and the end-to-end tests
                 (detect -> sign -> verify, audio + vision)
tools/           stage_optee.sh   - copy overlay sources into an optee-ra checkout
                 run_qemu.sh      - QEMU bring-up driver (needs Docker + disk)
                 run_gui.sh       - browser click-to-listen web UI
                 repro.sh         - prove the host build is byte-reproducible
                 cross.sh         - cross-compile the verifier for Raspberry Pi
                 render_video.py  - render the walkthrough from captured output
docs/            ARCHITECTURE, THREAT_MODEL, RUNBOOK, HARDWARE, ROADMAP,
                 REPRODUCIBLE, USE_CASES, WHY_TEE
```

## Docs

[Use cases](docs/USE_CASES.md) · [Why a TEE? (vs ZK/FHE)](docs/WHY_TEE.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Threat model & scope](docs/THREAT_MODEL.md) ·
[Runbook](docs/RUNBOOK.md) · [Hardware & device](docs/HARDWARE.md) ·
[Reproducible builds](docs/REPRODUCIBLE.md) · [Roadmap](docs/ROADMAP.md) ·
[Sample attestation (QEMU)](docs/SAMPLE_ATTESTATION.md) ·
[ZK proof of the detector](zk/README.md) · [On-chain verification](onchain/README.md)

## What is proven *here* vs *on the rig*

This is a clean overlay on `optee-ra`; it does not modify the upstream tree
(integration is via documented patches + `tools/stage_optee.sh`).

**Verified on any Linux box with `gcc`, `go`, `openssl`, `python3` (`make test`):**
- the detector classifies silence / alarm-tone / voice / sub-floor noise correctly;
- the **same machinery generalizes beyond audio**: a vision occupancy detector
  (`he_vision`) emits only `empty` / `occupied` + a region count, never the
  frame, and the *identical* `he-verify` binds and verifies it (`make vision-e2e`);
- the canonical payload encodes to a byte-exact deterministic-CBOR golden vector;
- the **full crypto + binding + verification pipeline** end-to-end — using the
  *exact same* P-256 test key and SHA-256→ECDSA algorithm the QEMU TA uses — so
  the bytes the Go verifier accepts here are the bytes the device would emit;
- the verifier **rejects** tampered payloads, stale nonces, replayed counters,
  substituted keys, endorsement-pin mismatches, and non-canonical CBOR;
- a device's stream is an **append-only hash-chain** (`prev_digest` = SHA-256 of
  the previous payload): the counter defeats *replay*, the chain additionally
  defeats *suppression* — a dropped window is a detectable gap, not a silent one
  (`make chain-e2e` verifies a genuine stream and rejects a spliced one);
- the CBOR payload decoder is **fuzzed** (`FuzzDecodePayload`; the seed corpus
  runs under `make test`, deeper exploration via `make fuzz`);
- the browser GUI displays **only the verifier's bound/verified predicate**,
  never the untrusted simulator's raw output (and the live tamper/replay buttons
  show the verifier rejecting forgeries);
- the tamper watcher's breach action securely erases the device **key file** and
  writes the tamper-**flag file** (the on-device TA-side `TRIP_TAMPER` latch and
  the GPIO path are reviewed-but-run-on-rig).

**Two independent verification legs (own toolchains, laptop-runnable):**
- a **zero-knowledge proof of the detector** — a RISC Zero zkVM runs the
  published detector over audio as *private* witness data and proves the verdict,
  committing only the predicate. A real STARK proof is verified end-to-end
  (`zk/`, `cargo run`; ~6 min/clip — batch/audit, not live).
- **on-chain verification of that proof** — a Foundry test verifies the real
  Groth16 receipt for the pinned guest `imageId` on a local EVM, with no enclave
  or operator trusted (`onchain/`, `forge test`; no funds/network). The same
  project also proves, on-chain: a **heterogeneous 2-of-2 check** (a ZK proof
  *and* the device's secp256r1 signature must both verify and agree — one
  realisable leg of the broader 2-of-3 vision) and an **append-only log anchor**
  (RFC 9162 consistency verified on-chain, so a fork/rewrite reverts). The two
  roots are cryptographically bound to the same observation — the same verifier
  nonce and the same audio (sha256(nonce) and sha256(audio)). The full stack is
  **deployed live on Ethereum Sepolia** (addresses + Etherscan links in
  [`onchain/README.md`](onchain/README.md)) — a real `eth_call` to the deployed
  quorum returns the agreed verdict — and also runs locally on anvil.

**Reviewed and runbook-driven — builds/runs on an Arm rig (see [`docs/RUNBOOK.md`](docs/RUNBOOK.md)):**
- the OP-TEE TA/PTA/host code and the live QEMU / RPi 3B+ / i.MX 8M Plus
  attestation. (Not runnable in a typical dev box: the OP-TEE + Veraison build
  needs Docker and ~40 GB; the TA needs the Arm dev kit.)

The honest one-liner: **the application logic and the cryptographic binding are
fully tested here; the TEE wiring is delivered as correct, reviewed code plus a
runbook**, because the bound-output payload and detector are the same sources,
and `PTA_SIGN_DATA` is a thin wrapper over `optee-ra`'s already-tested
`sign_ecdsa_sha256`.

## Quickstart (host)

```sh
make test        # C unit tests, Go unit tests (+ fuzz seeds), e2e pipeline, tamper self-test
make demo        # the whole thesis on one clip: TEE + ZK + on-chain 2-of-2 all agree
```

`make demo` runs the restraint story three independent ways on one alarm clip —
TEE attestation, an independent ZK proof, and the on-chain 2-of-2 quorum — and
shows they all agree on the verdict and are bound to the same audio (`sha256`),
which never leaves the enclave.

**Browser GUI (click-to-listen, for non-devs):**

```sh
tools/run_gui.sh              # then open http://localhost:8095 and tap the mic
```

Tap the mic → it listens live and shows a plain "✓ Verified — voice present / alarm
detected / quiet" card; audio is discarded, only the verified predicate is shown.

Run a single attestation by hand:

```sh
make sim
python3 test/gen_frames.py test/fixtures             # generate the PCM fixtures (gitignored)
sim/bin/he-detect test/fixtures/alarm.pcm            # crypto-free detector smoke test
N=$(openssl rand -hex 32)
sim/bin/he-attest-sim test/fixtures/alarm.pcm "$N" 1 > bundle.json
(cd src/verifier && go run ./cmd/he-verify --nonce "$N" ../../bundle.json)
```

## Raspberry Pi

This is meant to run on a Pi. The detector and host code are integer-only C that
compiles natively on Raspberry Pi OS (`make sim`, `make -C src/tamper`), and
OP-TEE remote attestation runs on the **Raspberry Pi 3B+** (a Tier-1 target in
[`docs/RUNBOOK.md`](docs/RUNBOOK.md)). The Go verifier is pure stdlib with CGO
off, so it cross-compiles to the Pi from any machine with no toolchain:

```sh
make cross        # -> dist/linux-arm64/  (Pi 3B+/4/5, 64-bit OS)
                  #    dist/linux-armv7/  (32-bit Raspberry Pi OS)
                  #    dist/linux-amd64/
scp dist/linux-arm64/he-verify  pi@raspberrypi:~   # then run it on the Pi
```

On the Pi itself, `make test` runs the whole host pipeline exactly as on a laptop.

## Trust hardening

```sh
make repro        # prove the host build is byte-identical across two trees
                  # (path/time-independent; anyone can recompute the bytes)
```

- **Transparency log** — append-only Merkle log of device endorsements with
  inclusion + consistency proofs and a signed checkpoint, so trust in a key
  can't be equivocated (`he-log`; CT/RFC-6962 model).
- **Multi-prover quorum** — require *k* of *n* independent roots (e.g. the
  OP-TEE device + a second-vendor TEE + a TPM quote) to agree, so one broken
  enclave can't forge a verdict (`he-verify --quorum`).
- **Reproducible builds** — `make repro` for the host today; the TA-measurement
  recipe is in [`docs/REPRODUCIBLE.md`](docs/REPRODUCIBLE.md).

## License

This overlay's original code is **MIT** (see [LICENSE](LICENSE)). It builds on
OP-TEE remote attestation ([optee-ra](https://github.com/iisec-suzaki/optee-ra)),
which is **BSD-2-Clause** — honor it when you integrate. No third-party runtime
dependencies (Go stdlib only; C uses OpenSSL on the host simulator and the
OP-TEE APIs on device).
