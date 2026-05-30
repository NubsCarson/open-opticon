/*
 * Honest Ear — TA-side attest-audio command (declaration).
 * See he_audio_ta.c and INTEGRATION.md.
 */
#ifndef HE_AUDIO_TA_H
#define HE_AUDIO_TA_H

#include <tee_internal_api.h>

/* New TA command ids (add to include/remote_attestation_ta.h). */
#ifndef TA_REMOTE_ATTESTATION_CMD_ATTEST_AUDIO
#define TA_REMOTE_ATTESTATION_CMD_ATTEST_AUDIO 3
#endif
#ifndef TA_REMOTE_ATTESTATION_CMD_TRIP_TAMPER
#define TA_REMOTE_ATTESTATION_CMD_TRIP_TAMPER 4
#endif

/*
 * Run the in-enclave detector over an audio buffer and return a signed
 * bound-output bundle.
 *
 *   [in]  params[0]  audio, int16 little-endian mono PCM (secure-world copy)
 *   [in]  params[1]  nonce (verifier's fresh challenge, <= HE_NONCE_MAX)
 *   [out] params[2]  bundle: u16_be(payload_len) || payload || sig[64]
 *   [in]  params[3]  (optional) packed key PubX||PubY||blob, forwarded to PTA
 *
 * The audio buffer is zeroized before return. Nothing but the small predicate
 * leaves the enclave.
 */
TEE_Result he_attest_audio(uint32_t param_types, TEE_Param params[4]);

/*
 * Latch the persistent tamper flag. After this, he_attest_audio refuses with
 * TEE_ERROR_SECURITY until the device is re-provisioned. Invoked by the
 * tamper watcher on enclosure breach (defense-in-depth; works even where the
 * signing key cannot be physically destroyed, e.g. the QEMU embedded key).
 */
TEE_Result he_trip_tamper(void);

#endif /* HE_AUDIO_TA_H */
