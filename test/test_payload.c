/*
 * Unit test: deterministic CBOR encoding of the bound-output payload.
 * Checks a hand-derived golden vector byte-for-byte, plus determinism and
 * overflow handling. Returns non-zero on failure.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "he_payload.h"

static int fails = 0;

static void check(int cond, const char *msg)
{
    if (!cond) {
        printf("  FAIL: %s\n", msg);
        fails++;
    } else {
        printf("  ok:   %s\n", msg);
    }
}

int main(void)
{
    printf("test_payload:\n");

    he_predicate_t p;
    memset(&p, 0, sizeof(p));
    p.version = 1;
    p.nonce[0] = 0xAA;
    p.nonce[1] = 0xBB;
    p.nonce_len = 2;
    p.event_id = 2;       /* alarm_tone */
    p.voice_active = 0;   /* -> CBOR false */
    p.presence = 1;
    p.frames = 10;
    p.window_ms = 160;
    p.counter = 7;
    memset(p.config_hash, 0x11, 32);

    /* Golden, hand-derived deterministic CBOR (see he_payload.h). */
    static const uint8_t golden[] = {
        0xA9,                   /* map(9) */
        0x00, 0x01,             /* 0: version=1 */
        0x01, 0x42, 0xAA, 0xBB, /* 1: nonce=h'AABB' */
        0x02, 0x02,             /* 2: event=2 */
        0x03, 0xF4,             /* 3: voice=false */
        0x04, 0x01,             /* 4: presence=1 */
        0x05, 0x0A,             /* 5: frames=10 */
        0x06, 0x18, 0xA0,       /* 6: window_ms=160 */
        0x07, 0x07,             /* 7: counter=7 */
        0x08, 0x58, 0x20,       /* 8: config_hash bstr(32) */
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    };

    uint8_t out[HE_PAYLOAD_MAX_LEN];
    size_t out_len = 0;
    int rc = he_payload_encode(&p, out, sizeof(out), &out_len);
    check(rc == HE_PAYLOAD_OK, "encode returns OK");
    check(out_len == sizeof(golden), "encoded length matches golden");
    check(out_len == sizeof(golden) && memcmp(out, golden, out_len) == 0,
          "encoded bytes match golden vector");

    /* Determinism: encoding twice yields identical bytes. */
    uint8_t out2[HE_PAYLOAD_MAX_LEN];
    size_t out_len2 = 0;
    he_payload_encode(&p, out2, sizeof(out2), &out_len2);
    check(out_len == out_len2 && memcmp(out, out2, out_len) == 0,
          "encoding is deterministic");

    /* Overflow: tiny buffer must be rejected, not overrun. */
    uint8_t tiny[4];
    size_t tlen = 0;
    rc = he_payload_encode(&p, tiny, sizeof(tiny), &tlen);
    check(rc == HE_PAYLOAD_E_OVERFLOW, "small buffer => overflow error");

    /* Param guard. */
    rc = he_payload_encode(NULL, out, sizeof(out), &out_len);
    check(rc == HE_PAYLOAD_E_PARAM, "null predicate => param error");

    /* A multi-byte window_ms and 64-byte nonce (max) round-trips lengths. */
    memset(&p, 0, sizeof(p));
    p.version = 1;
    p.nonce_len = 64;
    for (int i = 0; i < 64; i++)
        p.nonce[i] = (uint8_t)i;
    p.window_ms = 70000; /* forces 4-byte uint */
    rc = he_payload_encode(&p, out, sizeof(out), &out_len);
    check(rc == HE_PAYLOAD_OK, "max nonce + large window encodes");

    if (fails) {
        printf("test_payload: %d FAILURE(S)\n", fails);
        return 1;
    }
    printf("test_payload: all passed\n");
    return 0;
}
