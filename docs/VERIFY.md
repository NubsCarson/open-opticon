# Verify it yourself

Every claim open-opticon makes maps to a command or file you can run/read — no
trust required. `make verify-all` runs all the laptop-runnable, no-r0vm checks at
once and prints PASS/SKIP per check; the table below is the line-by-line map.

**Tiers:** **L** = proven on this laptop (no hardware, no r0vm) · **R** = needs the
Arm rig (QEMU/OP-TEE build) · **H** = needs hardware identity (i.MX CAAM / ST
secure element) · **F** = frontier / not built. Full scope: [THREAT_MODEL.md](THREAT_MODEL.md).

| Claim | How you check it | Tier |
|---|---|---|
| The output is a small event predicate, signed by the attested key — not a recording | `make test` (verifier units + `e2e`); read `src/common/he_payload.h`, `src/verifier/bound.go` | L |
| A bundle that is forged / replayed / stale-nonce / key-swapped / non-canonical is rejected | `make e2e` negatives; `src/verifier/bound_test.go`; `make fuzz` (CBOR decoder) | L |
| The browser verifier matches the CLI (same code, no server) | `bash tools/build_wasm.sh && node test/wasm_verify_test.js`; open [`verify.html`](verify.html) | L |
| Streaming hash-chain detects a suppressed window | `make chain-e2e` | L |
| COSE_Sign1 (RFC 9052) envelope verifies end to end | `make cose-e2e` | L |
| A PSA attestation token (EAT) verifies offline: sig + profile + freshness + reference measurement | `make eat-e2e` | L |
| The published C detector and the Rust zk port give bit-identical verdicts | `make port-diff` | L |
| The host build is byte-reproducible across independent trees | `make repro` (CI also attaches SLSA provenance to the manifest) | L |
| TEE + ZK + device signature agree, bound to the same audio + nonce | `make demo`; on a local EVM `cd onchain && forge test` | L |
| The same dual-root quorum returns the agreed verdict on a public chain | `VERIFY_SEPOLIA=1 bash onchain/call-sepolia.sh` (live Sepolia, view-only) | L |
| The transparency log is append-only; a fork/rewind is refused by witnesses | `make witness-e2e` | L |
| A genuinely independent (TPM) key signs and the verifier accepts it (root-agnostic) | `make tpm-e2e` (software TPM) | L |
| Two independent silicon roots (sim P-256 + TPM) agree in a k-of-n quorum | `make quorum-hetero-e2e` (software TPM) | L |
| Audio + vision verdicts can be co-attested to one challenge nonce | `make multimodal-e2e` | L |
| A full record reveals only with k-of-n agreement; one window discloses without the rest | `make consent-e2e` | L |
| A transcription session can prove input-processed-then-discarded, retained:0 | `make voxterm-demo`; [`INTEGRATIONS.md`](INTEGRATIONS.md) | L |
| Raw audio is zeroized in-enclave; only the predicate leaves | read `src/optee/ta/he_audio_ta.c`; in-enclave run is the rig step | R |
| Genuine published firmware produced the output (measured-boot attestation) | OP-TEE + Veraison on QEMU; [`SAMPLE_ATTESTATION.md`](SAMPLE_ATTESTATION.md), [`RUNBOOK.md`](RUNBOOK.md) | R |
| The signing key is non-extractable / tied to a specific device | i.MX CAAM or an ST secure element; [`PI_ST_ELEMENT.md`](PI_ST_ELEMENT.md) | H |
| An opened device is cryptographically dead (hardware tamper) | secure-element key zeroization; software latch proven on QEMU only | H |
| An audited learned detector; domain-separated on-chain replay; PIR/FHE | not built | F |

If a row's command fails on your machine, that's a bug — please report it (see
[`../SECURITY.md`](../SECURITY.md)). A **SKIP** in `make verify-all` only means an
optional tool (Foundry, Node, swtpm) or the network wasn't available; it never
hides a failure.
