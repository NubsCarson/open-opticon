/*
 * Unit test: COSE_Sign1 (RFC 9052) encoder. Checks the Sig_structure and the
 * COSE_Sign1 message byte-for-byte against hand-derived golden vectors for a
 * tiny synthetic payload, plus overflow handling. Returns non-zero on failure.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "he_cose.h"

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
    printf("test_cose:\n");

    /* A tiny synthetic payload (he_cose wraps arbitrary bytes). */
    static const uint8_t payload[] = {0xAB, 0xCD};

    /* Sig_structure = [ "Signature1", protected, ext_aad(empty), payload ]:
     *   84                              array(4)
     *   6a 5369676e617475726531         text(10) "Signature1"
     *   43 a10126                       bstr(3) {1:-7}  (protected, ES256)
     *   40                              bstr(0)         (external_aad)
     *   42 abcd                         bstr(2) payload                          */
    static const uint8_t golden_sig[] = {
        0x84,
        0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
        0x43, 0xa1, 0x01, 0x26,
        0x40,
        0x42, 0xAB, 0xCD,
    };

    uint8_t out[HE_COSE_MAX_LEN];
    size_t out_len = 0;
    int rc = he_cose_sig_structure(payload, sizeof(payload), out, sizeof(out), &out_len);
    check(rc == HE_COSE_OK, "sig_structure encodes OK");
    check(out_len == sizeof(golden_sig), "sig_structure length matches golden");
    check(out_len == sizeof(golden_sig) && memcmp(out, golden_sig, out_len) == 0,
          "sig_structure bytes match golden");

    /* COSE_Sign1 = 18([ protected, unprotected{}, payload, signature ]):
     *   d2                              tag(18)
     *   84                              array(4)
     *   43 a10126                       bstr(3) {1:-7}  (protected)
     *   a0                              map(0)          (unprotected)
     *   42 abcd                         bstr(2) payload
     *   5840 <64 bytes>                 bstr(64) signature                       */
    uint8_t sig[64];
    memset(sig, 0x11, sizeof(sig));
    static const uint8_t golden_msg_head[] = {
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x42, 0xAB, 0xCD, 0x58, 0x40,
    };
    rc = he_cose_sign1(payload, sizeof(payload), sig, out, sizeof(out), &out_len);
    check(rc == HE_COSE_OK, "cose_sign1 encodes OK");
    check(out_len == sizeof(golden_msg_head) + 64, "cose_sign1 length is head + 64-byte sig");
    check(memcmp(out, golden_msg_head, sizeof(golden_msg_head)) == 0,
          "cose_sign1 header bytes match golden");
    int sig_ok = 1;
    for (size_t i = 0; i < 64; i++)
        if (out[sizeof(golden_msg_head) + i] != 0x11)
            sig_ok = 0;
    check(sig_ok, "cose_sign1 carries the 64-byte signature verbatim");

    /* Overflow: a tiny buffer must be rejected, not overrun. */
    uint8_t tiny[4];
    size_t tlen = 0;
    rc = he_cose_sign1(payload, sizeof(payload), sig, tiny, sizeof(tiny), &tlen);
    check(rc == HE_COSE_E_OVERFLOW, "small buffer => overflow error");

    /* Param guard. */
    rc = he_cose_sig_structure(NULL, 0, out, sizeof(out), &out_len);
    check(rc == HE_COSE_E_PARAM, "null payload => param error");

    if (fails) {
        printf("test_cose: %d FAILURE(S)\n", fails);
        return 1;
    }
    printf("test_cose: all passed\n");
    return 0;
}
