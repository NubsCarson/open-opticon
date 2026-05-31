// zkVM guest: runs the published integer detector (oo_detector, a faithful port
// of src/common/he_detector.c) over the input samples and commits ONLY the
// verdict (plus a binding to the verifier's nonce) to the public journal. The
// audio samples are private witness data — the proof attests "the published
// detector produced this verdict for this challenge" in zero knowledge of the
// audio.
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

fn main() {
    let pcm: alloc::vec::Vec<i16> = env::read();
    let nonce: alloc::vec::Vec<u8> = env::read();
    let v = oo_detector::detect(&pcm);

    // Bind this proof two ways, so an on-chain quorum can require the ZK leg and
    // the device's signature to attest the SAME observation, not just an agreeing
    // verdict:
    //   - sha256(nonce): the same verifier challenge (session), and
    //   - sha256(audio): the same input bytes (content) — matches the device
    //     payload's input_hash (s16le sample bytes).
    // Each digest is committed as eight u32 from little-endian chunks, so the
    // journal's 32-byte windows are exactly the digests (no endianness surprises).
    let nonce_hash = digest_words(&Sha256::digest(&nonce));
    let audio_bytes: alloc::vec::Vec<u8> = pcm.iter().flat_map(|s| s.to_le_bytes()).collect();
    let audio_hash = digest_words(&Sha256::digest(&audio_bytes));

    // public journal: (event, presence, voice_active, frames, active_frames,
    //                  n_samples, sha256(nonce), sha256(audio))
    env::commit(&(
        v.event,
        v.presence,
        v.voice_active,
        v.frames,
        v.active_frames,
        pcm.len() as u32,
        nonce_hash,
        audio_hash,
    ));
}

// Pack a 32-byte digest into eight u32 from little-endian chunks, so the journal
// bytes equal the digest exactly.
fn digest_words(h: &[u8]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]))
}

extern crate alloc;
