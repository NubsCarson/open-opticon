/*
 * Honest Ear — QEMU TEST KEY (NOT SECRET).
 *
 * These are the P-256 coordinates and private scalar embedded in the optee-ra
 * PTA's sign.c for the QEMU / no-CAAM build path. They are published in that
 * repository and in relying_party/data/ec256.json. They exist ONLY so the host
 * simulator can produce signatures that the verifier accepts exactly as it
 * would accept the QEMU TA's signatures.
 *
 * On real i.MX 8M Plus hardware the signing key is a non-extractable CAAM black
 * key and NONE of these constants are used. This file must never be used to
 * stand in for a production key.
 */
#ifndef HE_TESTKEY_H
#define HE_TESTKEY_H

/* SEC1 affine coordinates (32 bytes each), hex. */
#define HE_TESTKEY_PUB_X_HEX \
    "30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e"
#define HE_TESTKEY_PUB_Y_HEX \
    "e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723"
/* Private scalar d (32 bytes), hex. QEMU test only. */
#define HE_TESTKEY_PRIV_D_HEX \
    "f3bd0c07a81fb932781ed52752f60cc89a6be5e51934fe01938ddb55d8f77801"

#endif /* HE_TESTKEY_H */
