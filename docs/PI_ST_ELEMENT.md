# Design — opticon on Raspberry Pi with an ST secure element

Audience: the Track 3 hardware side. This is the "economical path" the program
points at (ST secure elements as the per-device root). It is a **design feeding a
hardware pick — nothing here is built or proven.**

## Status legend (read first)

- **PROVEN (QEMU, Tier 1):** the attest → bind → verify loop runs on QEMU (Arm
  TrustZone) + the host verifier, using a **shared embedded test key**. Proves
  "genuine published code ran and emitted only this minimal verdict for this fresh
  nonce" — not device identity. See [HARDWARE.md](HARDWARE.md), [THREAT_MODEL.md](THREAT_MODEL.md).
- **SPECED (needs hardware):** i.MX CAAM black key, RPMB rollback-proof counter,
  AHAB secure boot, real enclosure/tamper — design/plan only.
- **FRONTIER (this doc):** Pi + STSAFE-A110 as the signing root. A new option that
  does not exist in the repo today.

The program's own floor applies and this design does not change it: **no
attestable microphone exists today**, and there is an enclave/handoff vendor-trust
floor (§8).

## 1. Where this sits vs. the two boards in the repo

| | Pi 3B+ (today) | i.MX 8M Plus (the "real target") | **Pi + STSAFE-A110 (this doc)** |
|---|---|---|---|
| Signing key | shared embedded test key | CAAM black key, private half never leaves chip | ST SE-held P-256 key, never leaves the STSAFE |
| Device identity | no (shared key) | yes (CAAM) | yes (per-SE key), rooted in a ~$1–2 external chip |
| Anti-replay counter | best-effort, REE storage | RPMB | STSAFE has HW counters, but binding is non-trivial (§6) |
| Secure boot | limited | AHAB | none on a stock Pi — the dominant gap (§8) |

The ST path gives the one thing the Pi alone structurally cannot: **per-device,
non-extractable key** material, for ~$1–2 of silicon, without an i.MX board. It
buys device-identity / anti-clone. It does **not** buy a secure execution
environment for the detector — that is the catch (§3, §8).

## 2. What the device signs (unchanged by the key root)

The signed object is the canonical bound-output payload and does not change with
the key root: the TA runs the detector in-enclave, SHA-256s the raw PCM, zeroizes
the PCM, builds a deterministic-CBOR predicate (version, nonce, event, voice flag,
presence, frames, window_ms, monotonic counter, config_hash, input_hash,
prev_digest), and signs **SHA-256(payload)** as ECDSA-P256 r‖s
(`src/optee/ta/he_audio_ta.c`; schema mirrored in `src/verifier/bound.go`). The
signing call is a thin wrapper over `sign_ecdsa_sha256()`
(`src/optee/pta/pta_sign_data.c`).

**Key point:** the verifier only cares that a P-256 signature over
SHA-256(payload) validates under a pinned/enrolled public key — it is
root-agnostic. Swapping the key root from "embedded key / CAAM" to "STSAFE-A110"
is, verifier-side, only a change in *which* P-256 key is enrolled. The wire format
and gates are untouched. That is why the swap is feasible.

## 3. Where the key lives, and the device-side change

Today the signing call accepts an optional packed key `PubX(32)||PubY(32)||blob(N)`
where only the `blob` (the CAAM black-key wrapper) is used; absent → embedded key.
With STSAFE-A110 the model is different, and **this is the core architectural
change**:

- CAAM is a *black blob*: the SoC unwraps `blob` and signs **inside the SoC**.
- STSAFE is an *external signing oracle*: the private key lives in the STSAFE and
  **never leaves it**. The Pi sends `SHA-256(payload)` to the STSAFE over I2C and
  reads back the ECDSA-P256 r‖s. There is no `blob`; the "key" is an SE slot index
  plus the SE's published public key.

What changes vs. today:

1. **The signing primitive is replaced, not the payload.** `sign_ecdsa_sha256()`
   is swapped for "hash here, ship the 32-byte digest to the STSAFE, read back 64
   bytes r‖s" (an STSAFE `Generate Signature` over a pre-hashed digest via ST's
   middleware).
2. **The `blob` parameter is dropped on this path.** The STSAFE never exposes its
   private half, so there is nothing to pass; the slot is configured once at
   provisioning.
3. **The verifier-facing public key is the STSAFE's per-device key**, read once at
   provisioning and enrolled (§4).

**The detector placement catch (mandatory for Noah to weigh).** A stock Pi 3B+
runs OP-TEE/TrustZone, so the detector can still run in the secure world and audio
is still zeroized there. But the STSAFE talks I2C, and on a Pi the I2C controller
and driver live in the **normal world**. So either (a) the secure-world TA owns the
I2C peripheral and drives the STSAFE directly, or (b) the TA hands the digest to
the normal world to relay. **Option (b) breaks the binding** — a normal-world relay
is exactly the forging oracle the threat model warns about: the normal world could
submit any digest and the SE would faithfully sign attacker-chosen bytes.
**Option (a) is mandatory** and is unproven, board-specific driver work. Treat
"secure-world I2C ownership of the STSAFE" as a first-class requirement, not a
detail.

## 4. Enrolling the ST root in the verifier

**What the verifier supports today:** it pins raw P-256 X/Y coordinates
(constant-time compared) and, for quorum, a flat list of enrolled `Prover{Name,
PubX, PubY}` roots. Endorsement is by appending the raw `PubX‖PubY` to a Merkle
transparency log and proving inclusion. There is **no x509 / CA-chain parsing
anywhere in the verifier**.

**What "ST published CA" means:** STSAFE-A110 ships personalized — each device
carries an ECDSA P-256 key whose public half is certified by ST's CA chain (a
per-device leaf under an ST intermediate, under ST's root CA). Validating that
chain to ST's published root is a **manufacturer root** — the thing opticon does
**not** have today (it self-provisions endorsements).

Two enrollment options; recommend A first:

- **Option A — flat enrollment (works with code as written; recommended for the
  PoC).** Read the STSAFE device public key once at provisioning and enroll its raw
  `PubX/PubY` exactly like the i.MX CAAM key: pin it and append to the transparency
  log — runnable on a laptop today. This gives anti-clone relative to *our*
  enrolment record. It is identical in trust model to the existing self-provisioned
  endorsement — it does **not** yet use ST's CA.
- **Option B — ST CA as a manufacturer root (SPECED, not built).** To get a
  manufacturer-rooted "this is a genuine ST secure element" check, the verifier
  needs new code it does not have: parse the STSAFE leaf certificate, validate the
  chain to ST's root CA, and bind the leaf key to the pinned endorsement. This is
  the first manufacturer-root anchor in the project and net-new x509 work — do not
  present it as existing. It slots into the k-of-n quorum as one independent root.

Either way the per-SE key becomes one enrolled P-256 root; nothing in `quorum.go`
or `bound.go` changes for Option A.

## 5. What stays the same

- Verifier gates 0–4 (pin, signature, freshness, anti-replay, optional stream
  chain) — root-agnostic, unchanged.
- Payload schema + deterministic CBOR — the device encoder/decoder contract is
  untouched.
- Quorum logic (k-of-n, one vote per root, event-class agreement) — an STSAFE leg
  is just another enrolled root, possibly heterogeneous alongside an i.MX/OP-TEE
  leg.
- In-enclave detect + immediate zeroize — preserved *only if* the detector still
  runs in the secure world (§3).
- Tamper fail-closed latch — see §6.

## 6. What changes, and the unsolved sub-problems

1. **Signing primitive → external SE call** (§3). New, unproven driver code.
2. **Secure-world I2C ownership of the STSAFE** (§3) — mandatory, unproven, the
   main new firmware effort.
3. **Monotonic counter.** Today the counter is in OP-TEE Trusted Storage,
   rollback-proof only with RPMB; a stock Pi has no RPMB and no AHAB, so it is
   best-effort. STSAFE-A110 *has* hardware counters — but using one as the
   anti-replay counter means the **counter increment and the signature must be
   atomic/bound at the SE**, or the normal world can desynchronize them. That
   binding is not designed in the repo and is non-trivial. For a first PoC, keep
   the in-TEE counter (defeats in-session replay) and label cross-session/rollback
   as an open gap.
4. **Tamper → key destruction.** Today the latch is a fail-closed software flag,
   and on a Pi there is no key file to erase, so a tampered-but-intact device could
   keep signing unless the latch gates *every* signing path. The STSAFE materially
   improves this: an external SE can be wired so a tamper line zeroizes/locks the
   SE's private key in hardware, even powered-off (the role HARDWARE.md assigns to
   an ATECC608 — STSAFE-A110 is the same shape of part). This is genuinely better
   than the Pi-alone story, **but design only**, and it still requires that the TA
   tamper latch gate the STSAFE-signing command.

## 7. Concrete bring-up sequence

1. Pi 3B+ + STSAFE-A110 eval on I2C. ~$60 (Pi) + ~$1–2 (SE).
2. Build OP-TEE for the Pi, stage the Honest Ear TA.
3. Provision: read the STSAFE per-device public key (and, for Option B, its leaf
   cert chain).
4. Enroll: pin `PubX/PubY` + append to the transparency log — laptop-only,
   runnable today.
5. Replace the in-TEE `sign_ecdsa_sha256` call with a secure-world STSAFE
   `Generate Signature` over the digest (§3) — **new, unproven**.
6. Verify with the existing `he-verify` / `he-challenge` path. Because the verifier
   is root-agnostic, a correct STSAFE signature should pass gates 0–4 with no
   verifier change (Option A).

## 8. Honest gaps and the vendor-trust floor (do not gloss)

- **No secure boot on a stock Pi — the biggest hole.** The SE proves *who signed*,
  but with no AHAB there is no measured-boot guarantee that the *genuine TA* called
  the SE. An attacker who replaces the firmware can still drive the SE; it signs
  whatever digest it is handed. **The SE gives key non-extractability, not code
  integrity.** On i.MX, AHAB + reproducible TA measurement closes this; on a bare
  Pi+SE it stays open. This is the central caveat of the economical path.
- **Enclave handoff / vendor-trust floor (the program's own caveat).** With the
  STSAFE you trust ST: the chip really keeps the key non-extractable, ST's CA was
  not mis-issued, the I2C handoff is not intercepted. This is a *different* vendor
  floor than CAAM (NXP), not the absence of one. "Check don't trust" is satisfied
  at the verifier (anyone validates the P-256 signature, and with Option B the ST
  chain); the SE-internal correctness is trusted, not layperson-verified.
- **No attestable microphone exists** (program premise). The STSAFE does nothing
  for the analog path: a second mic in the room, or audio reaching normal-world
  userspace before the TA, bypasses all of this. The SE secures the *key*, never
  the *capture*.
- **Side-channels / minimization unchanged** — the SE neither helps nor hurts; the
  "almost nothing to leak" argument stands.
- **Option B (ST CA validation) is unbuilt** — net-new x509 verifier code.
- **STSAFE counter binding unsolved** — do not assume drop-in rollback protection.

## Bottom line

Pi + STSAFE-A110 is a credible **economical middle tier**: for ~$1–2 it adds the
one thing the Pi-alone path structurally lacks — a per-device, non-extractable key
— and a path to hardware, powered-off key destruction on tamper. It is
root-agnostic-compatible with the existing verifier, so Option-A enrollment needs
**zero verifier changes**. But it does **not** give code-integrity (no secure boot
on a stock Pi), it does **not** solve secure audio capture, and the secure-world
I2C handoff to the SE is mandatory-but-unbuilt firmware work that, if skipped,
reintroduces the normal-world forging oracle. Everything here is SPECED/FRONTIER;
the only thing PROVEN remains the QEMU Tier-1 loop with the shared embedded test
key.
