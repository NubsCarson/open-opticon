/*
 * Honest Ear — canonical bound-output payload encoder.
 * Minimal, dependency-free, deterministic CBOR (RFC 8949 core deterministic
 * encoding). Integer-only; safe to compile into an OP-TEE TA and into host
 * tooling unchanged.
 */
#include "he_payload.h"

#include <string.h>

/* Append one raw byte with bounds check. */
static int put_byte(uint8_t *out, size_t cap, size_t *pos, uint8_t b)
{
    if (*pos >= cap)
        return HE_PAYLOAD_E_OVERFLOW;
    out[(*pos)++] = b;
    return HE_PAYLOAD_OK;
}

/*
 * Encode a CBOR head: major type (high 3 bits) + argument, using the
 * smallest legal encoding (deterministic). major is 0..7, val is the argument.
 */
static int put_head(uint8_t *out, size_t cap, size_t *pos, uint8_t major,
                    uint64_t val)
{
    uint8_t mt = (uint8_t)(major << 5);
    int rc;

    if (val < 24u) {
        return put_byte(out, cap, pos, (uint8_t)(mt | (uint8_t)val));
    } else if (val <= 0xffu) {
        if ((rc = put_byte(out, cap, pos, (uint8_t)(mt | 24u))))
            return rc;
        return put_byte(out, cap, pos, (uint8_t)val);
    } else if (val <= 0xffffu) {
        if ((rc = put_byte(out, cap, pos, (uint8_t)(mt | 25u))))
            return rc;
        if ((rc = put_byte(out, cap, pos, (uint8_t)(val >> 8))))
            return rc;
        return put_byte(out, cap, pos, (uint8_t)val);
    } else if (val <= 0xffffffffu) {
        if ((rc = put_byte(out, cap, pos, (uint8_t)(mt | 26u))))
            return rc;
        for (int s = 24; s >= 0; s -= 8)
            if ((rc = put_byte(out, cap, pos, (uint8_t)(val >> s))))
                return rc;
        return HE_PAYLOAD_OK;
    } else {
        if ((rc = put_byte(out, cap, pos, (uint8_t)(mt | 27u))))
            return rc;
        for (int s = 56; s >= 0; s -= 8)
            if ((rc = put_byte(out, cap, pos, (uint8_t)(val >> s))))
                return rc;
        return HE_PAYLOAD_OK;
    }
}

/* CBOR major types we use. */
#define CBOR_MT_UINT  0
#define CBOR_MT_BSTR  2

static int put_uint(uint8_t *out, size_t cap, size_t *pos, uint64_t v)
{
    return put_head(out, cap, pos, CBOR_MT_UINT, v);
}

static int put_bstr(uint8_t *out, size_t cap, size_t *pos, const uint8_t *b,
                    size_t len)
{
    int rc = put_head(out, cap, pos, CBOR_MT_BSTR, (uint64_t)len);
    if (rc)
        return rc;
    for (size_t i = 0; i < len; i++)
        if ((rc = put_byte(out, cap, pos, b[i])))
            return rc;
    return HE_PAYLOAD_OK;
}

static int put_bool(uint8_t *out, size_t cap, size_t *pos, uint32_t truthy)
{
    /* major type 7: 0xf4 = false, 0xf5 = true */
    return put_byte(out, cap, pos, truthy ? 0xf5u : 0xf4u);
}

int he_payload_encode(const he_predicate_t *p, uint8_t *out, size_t out_cap,
                      size_t *out_len)
{
    size_t pos = 0;
    int rc;

    if (!p || !out || !out_len)
        return HE_PAYLOAD_E_PARAM;
    if (p->nonce_len > HE_NONCE_MAX)
        return HE_PAYLOAD_E_PARAM;

    /* map(9) — keys are emitted in ascending order: deterministic. */
    if ((rc = put_head(out, out_cap, &pos, 5 /* map */, 9)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_VERSION)) ||
        (rc = put_uint(out, out_cap, &pos, p->version)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_NONCE)) ||
        (rc = put_bstr(out, out_cap, &pos, p->nonce, p->nonce_len)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_EVENT)) ||
        (rc = put_uint(out, out_cap, &pos, p->event_id)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_VOICE)) ||
        (rc = put_bool(out, out_cap, &pos, p->voice_active)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_PRESENCE)) ||
        (rc = put_uint(out, out_cap, &pos, p->presence)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_FRAMES)) ||
        (rc = put_uint(out, out_cap, &pos, p->frames)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_WINDOW_MS)) ||
        (rc = put_uint(out, out_cap, &pos, p->window_ms)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_COUNTER)) ||
        (rc = put_uint(out, out_cap, &pos, p->counter)))
        return rc;

    if ((rc = put_uint(out, out_cap, &pos, HE_K_CONFIG_HASH)) ||
        (rc = put_bstr(out, out_cap, &pos, p->config_hash, HE_CONFIG_HASH_LEN)))
        return rc;

    *out_len = pos;
    return HE_PAYLOAD_OK;
}
