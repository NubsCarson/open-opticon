# Roadmap

From this PoC to a defensible product, in order of trust-impact.

## Cryptographic / protocol
- **Promote the bound-output envelope to COSE_Sign1.** The signing primitive is
  identical (`sign_ecdsa_sha256`); wrap the canonical payload in a standard
  COSE_Sign1 with a protected `alg` header so any RATS/EAT tooling consumes it.
- **Fold the bound output into the EAT itself** as a custom claim, so there is a
  single attestation token rather than two signatures. (Two signatures is fine
  for the PoC and keeps Veraison freshness untouched.)
- **Second independent prover (2-of-3).** Add a non-TEE attestation leg (e.g. a
  measured-boot TPM quote, or a second-vendor TEE) so a single broken enclave
  does not forge a PASS — directly answers the single-root critique.

## Hardware identity & tamper
- **i.MX 8M Plus CAAM** non-extractable black key as the default signing key;
  per-device endorsement enrolled to a **public manufacturer root** (the
  StrongBox/EKCert analogue we currently self-provision).
- **Hardware tamper response**: route the tamper line into a secure element
  (ATECC608) or CAAM so the *private key* is zeroized in hardware, with a backup
  battery so detection works while powered off. Fine anti-tamper mesh + potting
  behind the transparent window (PCI-PTS / IBM-4758 model).
- **Hardware monotonic counter** (RPMB-backed) for rollback-proof anti-replay.

## Secure capture path
- Move PCM capture to a **secure-world I2S/PDM** source so raw audio never
  enters the normal world at all (today the host feeds a file/buffer for the
  PoC). This closes the analog-hole-equivalent gap fully.

## Detector quality
- Replace the threshold detector with a small, **audited** keyword/acoustic-event
  model; publish the model + policy and bind its hash (already wired via
  `config_hash`). Add a constant-time / no-secret-dependent-branch audit pass.

## Confidentiality migration
- Where richer outputs are needed, migrate sensitive computation toward
  **PIR/FHE** so confidentiality no longer rests on TEE side-channel resistance.

## Ecosystem / collaborations
- **VoxTerm** ([dmarzzz/VoxTerm](https://github.com/dmarzzz/VoxTerm)) is a local-first
  voice-transcription app whose privacy pitch is "nothing sent to a server, no
  audio stored." Today that's a *trust* claim. open-opticon is the layer that
  could make it a *provable* one: attest the transcription pipeline's firmware
  and emit only signed, bound outputs, so VoxTerm could prove — not just assert —
  that it didn't exfiltrate or retain audio. Natural collaboration; keep the
  projects separate, bridge at the attestation boundary (don't merge codebases).

## Ops
- Reproducible-build attestation of the published firmware (so the measurement
  is independently re-derivable from source).
- Transparency log of reference values + endorsements.
