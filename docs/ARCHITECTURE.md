# Architecture

## The two proofs, one key

Honest Ear produces **two** signatures from the **same** attested key per
challenge:

1. **Firmware identity** — the existing `optee-ra` PSA/CBOR-COSE attestation
   evidence (RFC 9783), verified by **Veraison** against published reference
   values. Proves *which measured firmware is running* and binds the verifier's
   fresh nonce.
2. **Bound output** — a signature over a canonical payload containing the
   detector's minimal predicate + the same nonce + a monotonic counter + the
   detector-policy hash. Proves *this exact minimal output came from that
   attested firmware for that fresh challenge*.

Because both are signed by the same key — the non-extractable CAAM black key on
i.MX 8M Plus, the embedded test key on QEMU — a verifier that accepts both knows:
*genuine, unmodified Honest Ear firmware produced this output, now, and nothing
else left the device.*

## Data flow

```
            NORMAL WORLD (untrusted)              │   SECURE WORLD (TrustZone)
                                                  │
  mic/file ──PCM──▶ he_host (CA) ──TEEC invoke──▶ │  ATTEST_AUDIO (he_audio_ta.c)
                                                  │    1. he_detector_run(pcm)   [integer DSP]
                                                  │    2. TEE_MemFill(pcm, 0)    [zeroize audio]
                                                  │    3. he_payload_encode(nonce,
                                                  │         predicate, counter, cfg_hash)
                                                  │    4. PTA SIGN_DATA ─────────┐
                                                  │                              ▼
                                                  │                     remote_attestation.pta
                                                  │                     sign_ecdsa_sha256(payload)
                                                  │                     └─ CAAM black key (i.MX)
                                                  │                        / embedded key (QEMU)
                  bundle ◀──{payload, sig}────────│    5. return payload‖sig
                    │
                    ▼
          he-verify / he-challenge (Go)
            gate 1: ECDSA verify sig over SHA-256(payload) w/ attested pubkey
            gate 2: payload.nonce == issued fresh nonce        (freshness)
            gate 3: payload.counter > last seen                (anti-replay)
           (gate 0: pubkey == enrolled endorsement, optional)  (device identity)

      … in parallel, the existing optee-ra client + Veraison verify firmware
        identity for the SAME nonce.
```

## Why each design choice

**Detector in the secure world, output is a predicate, not a transcript.**
A transcript *is* the surveillance payload; "consent" is unverifiable. An
event/occupancy predicate delivers the safety utility while being structurally
incapable of being a wiretap — and the published firmware hash proves no
speech-emitting code path exists. The detector
(`src/common/he_detector.c`) is integer-only (Q15 Goertzel + energy/ZCR VAD),
no float, no allocation, no libc beyond `<string.h>`, so it is small and safe
inside a TA and is the *same source* the host tests run.

**Binding via a new `PTA_SIGN_DATA`, NOT nonce-stuffing.** Stuffing
`hash(nonce‖output)` into the attestation nonce would (a) break Veraison's
freshness check and (b) prove nothing about output origin (the untrusted host
could fabricate any output and hash it). Instead the nonce stays the raw
verifier challenge (Veraison freshness untouched), and the enclave signs its
*own computed* output with the attested key. `PTA_SIGN_DATA` is a thin wrapper
over `optee-ra`'s existing, tested `sign_ecdsa_sha256` (SHA-256 → ECDSA-P256 →
64-byte r‖s), and lives outside the CAAM `#ifdef` so it works on QEMU too.

**Canonical deterministic-CBOR payload.** The signed bytes must be identical on
the signer and verifier with no ambiguity and no third-party library inside the
TA. `he_payload.c` emits a single RFC 8949 deterministic CBOR map (definite
length, ascending integer keys, smallest-int encodings); the Go verifier has a
matching minimal reader. Fields: version, nonce, event, voice_active, presence,
frames, window_ms, counter, config_hash. See `he_payload.h` for the exact
schema (a stable wire contract).

**Policy hash in the payload.** `config_hash = SHA-256(detector config blob)`
binds *which detection policy* (sample rate, frame size, tone target,
thresholds) produced the result, so "what counts as an event" is itself
attested and auditable, not a hidden knob.

**Monotonic counter in Trusted Storage.** Defeats re-presentation of an old,
otherwise-valid bundle. Rollback-resistant where the platform provides
anti-rollback (RPMB on i.MX); best-effort on QEMU (still defeats in-session
replay). See THREAT_MODEL.

**Tamper response destroys the key.** `src/tamper/he_tamper.c` watches a GPIO
loop around the clear enclosure; on breach it erases the device key material
and latches a TA-side flag (`TRIP_TAMPER`) so the enclave refuses to attest even
with correct firmware — "an opened device is cryptographically dead."

**The envelope is sensor-agnostic, and the math has a second prover.** A vision
occupancy detector (`he_vision`) emits only empty/occupied + a region count
through the *same* `he_payload` envelope and is verified by the *same*
`he-verify` (`make vision-e2e`) — the attestation/binding/verification machinery
is not audio-specific. Independently, a non-TEE ZK prover leg (`zk/`) proves the
detector's verdict with no enclave trusted for the math, and its Groth16 receipt
is verifiable on an EVM (`onchain/`); both can feed the existing k-of-n quorum.

## Hardware tiers

| Tier | Target | Signing key | What it proves |
|---|---|---|---|
| 1 (baseline) | QEMU + RPi 3B+ | embedded test key (shared) | genuine *published code* in OP-TEE, fresh, output bound |
| 2 (hardware identity) | i.MX 8M Plus | **non-extractable CAAM black key** | + device identity / anti-clone (key can't leave the chip) |
| 3 (enclosure) | clear case + GPIO loop | (above) destroyed on breach | physical tamper-evidence + response |

Tier 1 is the reliable baseline; Tier 2 is the credibility upgrade (a cloned SD card
cannot reproduce the i.MX key); Tier 3 is the physical tamper-evidence layer.
