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

    // Bind this proof to the verifier's challenge: commit sha256(nonce) so an
    // on-chain quorum can require the ZK leg and the device's signature to share
    // the same nonce (i.e. attest the same observation session). Committed as
    // eight u32 built from little-endian chunks, so the journal's trailing 32
    // bytes are exactly the sha256 digest (no endianness surprises on-chain).
    let h = Sha256::digest(&nonce);
    let nonce_hash: [u32; 8] =
        core::array::from_fn(|i| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]));

    // public journal: (event, presence, voice_active, frames, active_frames,
    //                  n_samples, sha256(nonce))
    env::commit(&(
        v.event,
        v.presence,
        v.voice_active,
        v.frames,
        v.active_frames,
        pcm.len() as u32,
        nonce_hash,
    ));
}

extern crate alloc;
