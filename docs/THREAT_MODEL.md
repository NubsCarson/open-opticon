# Threat model & honest scope

Overclaiming is the main risk. This document states exactly what Honest Ear
proves, what it does not, and how the hard questions are answered.

## What remote attestation buys (and what it does not)

**Buys:** proof of *code identity and integrity* (the running firmware matches a
published, source-auditable measurement) and *freshness* (each result is bound
to a verifier-chosen nonce). On i.MX, also *device identity* via a
non-extractable key.

**Does NOT buy:** confidentiality of in-enclave data against a physical /
side-channel adversary. Attestation does not make a TEE side-channel-proof.

> **Headline scope:** *Honest Ear proves software integrity + output provenance,
> not nation-state confidentiality.*

## Adversaries and outcomes

| Adversary | Capability | Outcome |
|---|---|---|
| Malicious app / normal-world OS | Full control of normal world | **Defended.** Cannot forge the bound output (no key); cannot alter the predicate (signature breaks); cannot replay (nonce + counter). Cannot see raw audio (zeroized in-enclave; on a production sensor, audio never enters normal world). |
| Static-QR / sticker swap | Replaces a printed code | **Defended.** Trust is a *live* fresh-nonce signature, not a copyable QR. A photo/replay has no fresh signature. |
| Device substitution ("skimmer") | Swaps in attacker's own genuine TEE | **Defended on i.MX** by the endorsement pin (verifier checks the key against the enrolled device key). On QEMU/RPi the key is shared, so this proves "genuine published code", not device identity — stated openly. |
| Firmware modification | Patches the detector to exfiltrate | **Defended.** Measurement changes → Veraison reference-value mismatch → attestation FAIL. |
| Replay of an old valid bundle | Re-presents a captured PASS | **Defended** within a session by the monotonic counter; across sessions by the per-challenge fresh nonce. |
| Selective suppression of a window | Silently drops one window from the stream (e.g. swallows the alarm window, forwards the rest) | **Detected** by the append-only hash-chain: each payload carries `prev_digest` = SHA-256 of the previous one, so a verifier tracking the stream sees a broken link where a window was dropped (`make chain-e2e`). Scope: this catches a *gap* in an observed stream; it does not by itself force a device to emit (a verifier seeing *no* stream learns nothing) — liveness/heartbeat policy is the complement. |
| Enclosure tamper | Opens/drills the case | **Detected (best-effort, software-only).** Tamper loop → key erased + TA flag latched → attestation FAIL. Production: hardware zeroization in a secure element / CAAM. |
| Side-channel on the TEE | Cache/power/EM/fault to extract secrets | **Out of scope / mitigated by minimization** (below). |
| Analog domain | A second mic in the room, TEMPEST, accelerometer audio recovery | **Out of scope by physics** — bypasses the TEE entirely. |

## Side-channels: the honest answer

Arm TrustZone has documented cache (e.g. TruSpy / Prime+Probe), fault-injection
(CLKSCREW, VoltJockey), and power/EM channels. Two things make this *tolerable
for this device* rather than fatal:

1. **There's almost nothing to leak.** Raw audio lives in the enclave for
   milliseconds and is then zeroized; the only output is a count/event, not
   speech. Published TrustZone side-channels target long-lived *crypto keys*;
   there is no off-the-shelf attack that reconstructs streaming audio out of a
   TEE in this configuration.
2. **The detector is constant-shape.** It does not branch or index on secret
   audio sample values in a way that encodes content; it accumulates fixed
   per-frame arithmetic. (A hardening pass should audit for any
   data-dependent timing and is tracked in ROADMAP.)

Mitigations we ship / recommend: pin a current OP-TEE release, keep the
confidentiality claim modest, treat the TEE as **one leg of defense-in-depth**
(reproducible firmware hash is the real anchor), and migrate sensitive paths
toward PIR/FHE as performance allows.

## Known limitations

- **Device identity only on i.MX.** QEMU/RPi use a shared embedded test key.
- **Self-provisioned endorsement.** Anti-swap holds relative to *our* enrolment
  record, not a public manufacturer root (no StrongBox/TPM-EKCert equivalent
  yet). The k-of-n quorum verifier is built and tested (`he-verify --quorum`), and a
  real non-TEE ZK prover leg (`zk/`) already exists as one independent (non-enclave)
  root, though it is batch/audit-only and not yet auto-wired into the live quorum;
  enrolling genuinely heterogeneous silicon (a second-vendor TEE, a TPM quote) remains
  roadmap.
- **Counter rollback.** Trusted-Storage anti-rollback depends on RPMB; on QEMU
  it is best-effort. A hardware monotonic counter is the production answer.
- **The detector is a heuristic stub.** A probe-band Goertzel + energy-floor VAD,
  not a hardened/learned model; "what is an event" is a policy claim that is
  *auditable* from source and bound via `config_hash` (not formally audited). The
  coarse classifier can mislabel a non-target pure tone as "voice".
- **The enclosure is theatre-grade.** A determined attacker can bridge the loop
  before cutting, glitch power to skip the handler, or probe the bus. Real
  protection needs a fine anti-tamper mesh + potting + environmental sensors +
  backup battery (the PCI-PTS / HSM model).
- **The on-chain verification leg has no domain separation (yet).** The `onchain/`
  dual-root check binds the zk receipt and the device P-256 signature to the same
  nonce + audio, but not to a chain id or contract address, so a valid bundle is
  replayable into another deployment/instance of the same contract. The fix is to
  bind `chainid` + the contract address into the signed payload AND the zk journal
  (a TA + zk-guest wire change + re-prove); the live Sepolia contracts are an
  immutable PoC snapshot. Off-chain, the verifier's issued-nonce freshness gate
  still binds a session interactively. See [`../onchain/README.md`](../onchain/README.md).
- **The non-panopticon guarantee is only as strong as the public audit of the
  firmware source.** Attestation makes the promise *checkable*; humans still
  have to read the code.

## Trust roots, ranked

1. **Public, reproducible firmware source + its attested measurement** — the
   real anchor. Anyone can read it and confirm there is no audio-emitting path.
2. **Hardware key non-extractability** (i.MX CAAM) — device identity / anti-clone.
3. **Open, permissionless verification** (Veraison + the open verifier) — no
   company API gates a PASS/FAIL.
4. **TEE isolation** — a convenience layer, explicitly *not* the sole root.
