/*
 * Honest Ear — COSE_Sign1 encoder (RFC 9052). See he_cose.h.
 * Minimal, dependency-free, integer-only; TA- and host-safe.
 */
#include "he_cose.h"

#include <string.h>

/* The protected header, pre-encoded as a CBOR bstr wrapping {1: -7} (alg ES256):
 *   bstr(3) = 0x43, then map(1){ 1 : -7 } = 0xa1 0x01 0x26.
 * This exact 4-byte sequence appears verbatim both in the message and in the
 * Sig_structure, so the verifier reconstructs the signed bytes byte-for-byte. */
static const uint8_t HE_COSE_PROTECTED[] = {0x43, 0xa1, 0x01, 0x26};

/* "Signature1" as a CBOR text string: text(10) = 0x6a, then the 10 ASCII bytes. */
static const uint8_t HE_COSE_CONTEXT[] = {
    0x6a, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1'};

static int put_byte(uint8_t *out, size_t cap, size_t *pos, uint8_t b)
{
    if (*pos >= cap)
        return HE_COSE_E_OVERFLOW;
    out[(*pos)++] = b;
    return HE_COSE_OK;
}

static int put_bytes(uint8_t *out, size_t cap, size_t *pos, const uint8_t *b,
                     size_t n)
{
    int rc;
    for (size_t i = 0; i < n; i++)
        if ((rc = put_byte(out, cap, pos, b[i])))
            return rc;
    return HE_COSE_OK;
}

/* Emit a CBOR byte-string head (major type 2) for `len`, smallest legal form. */
static int put_bstr_head(uint8_t *out, size_t cap, size_t *pos, size_t len)
{
    int rc;
    if (len < 24u) {
        return put_byte(out, cap, pos, (uint8_t)(0x40u | (uint8_t)len));
    } else if (len <= 0xffu) {
        if ((rc = put_byte(out, cap, pos, 0x58u)))
            return rc;
        return put_byte(out, cap, pos, (uint8_t)len);
    } else if (len <= 0xffffu) {
        if ((rc = put_byte(out, cap, pos, 0x59u)))
            return rc;
        if ((rc = put_byte(out, cap, pos, (uint8_t)(len >> 8))))
            return rc;
        return put_byte(out, cap, pos, (uint8_t)len);
    }
    return HE_COSE_E_OVERFLOW; /* our payloads are far smaller than 64 KiB */
}

static int put_bstr(uint8_t *out, size_t cap, size_t *pos, const uint8_t *b,
                    size_t len)
{
    int rc = put_bstr_head(out, cap, pos, len);
    if (rc)
        return rc;
    return put_bytes(out, cap, pos, b, len);
}

int he_cose_sig_structure(const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t pos = 0;
    int rc;

    if (!payload || !out || !out_len)
        return HE_COSE_E_PARAM;

    /* Sig_structure = [ "Signature1", protected, external_aad, payload ] */
    if ((rc = put_byte(out, out_cap, &pos, 0x84u))) /* array(4) */
        return rc;
    if ((rc = put_bytes(out, out_cap, &pos, HE_COSE_CONTEXT, sizeof(HE_COSE_CONTEXT))))
        return rc;
    if ((rc = put_bytes(out, out_cap, &pos, HE_COSE_PROTECTED, sizeof(HE_COSE_PROTECTED))))
        return rc;
    if ((rc = put_byte(out, out_cap, &pos, 0x40u))) /* external_aad = empty bstr */
        return rc;
    if ((rc = put_bstr(out, out_cap, &pos, payload, payload_len)))
        return rc;

    *out_len = pos;
    return HE_COSE_OK;
}

int he_cose_sign1(const uint8_t *payload, size_t payload_len,
                  const uint8_t sig[64], uint8_t *out, size_t out_cap,
                  size_t *out_len)
{
    size_t pos = 0;
    int rc;

    if (!payload || !sig || !out || !out_len)
        return HE_COSE_E_PARAM;

    /* COSE_Sign1 = 18([ protected, unprotected, payload, signature ]) */
    if ((rc = put_byte(out, out_cap, &pos, 0xd2u))) /* tag(18) */
        return rc;
    if ((rc = put_byte(out, out_cap, &pos, 0x84u))) /* array(4) */
        return rc;
    if ((rc = put_bytes(out, out_cap, &pos, HE_COSE_PROTECTED, sizeof(HE_COSE_PROTECTED))))
        return rc;
    if ((rc = put_byte(out, out_cap, &pos, 0xa0u))) /* unprotected = {} */
        return rc;
    if ((rc = put_bstr(out, out_cap, &pos, payload, payload_len)))
        return rc;
    if ((rc = put_bstr(out, out_cap, &pos, sig, 64)))
        return rc;

    *out_len = pos;
    return HE_COSE_OK;
}
