# Security Policy

## Status & scope

**open-opticon is a proof-of-concept / research artifact.** It has **not** been
independently audited. Do not deploy it to protect anything real without your
own review.

What it is designed to prove, and what it is not, is documented in detail in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). In short:

- ✅ **Integrity + provenance:** the running firmware matches a published,
  source-auditable measurement, and each output is fresh (nonce-bound) and
  signed by the attested key.
- ❌ **Not confidentiality against a physical / side-channel adversary.** A TEE
  is one leg of defense-in-depth, not a guarantee against cache/power/EM/fault
  attacks. The design *minimizes* what the enclave can leak (raw audio is
  zeroized; only a non-reconstructable predicate leaves), but makes no
  nation-state confidentiality claim.

Known limitations are listed in the threat model (device identity only on
i.MX hardware, self-provisioned endorsement, theatre-grade enclosure, etc.).

## The embedded key is not a secret

`src/common/he_testkey.h` contains a P-256 key that is **published and
non-secret** — it is the QEMU test key from upstream
[optee-ra](https://github.com/iisec-suzaki/optee-ra) (`sign.c` /
`relying_party/data/ec256.json`). It exists only so the host simulator can
produce signatures the verifier accepts on the no-hardware path. On real i.MX
8M Plus hardware the signing key is a non-extractable CAAM black key. **Never
treat the test key as a production secret.**

## Reporting a vulnerability

If you find a security issue in this code, please report it privately rather
than opening a public issue:

- Open a **GitHub Security Advisory** ("Report a vulnerability" on the
  Security tab), or
- email the maintainer at the address on the GitHub profile
  (<https://github.com/NubsCarson>).

Please include a description, affected files/lines, and a reproduction if
possible. As an unfunded PoC there is no formal SLA, but reports are welcome
and will be addressed on a best-effort basis.
