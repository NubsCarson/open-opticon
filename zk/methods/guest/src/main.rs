// zkVM guest: runs the published integer detector (oo_detector, a faithful port
// of src/common/he_detector.c) over the input samples and commits ONLY the
// verdict to the public journal. The audio samples are private witness data —
// the proof attests "the published detector produced this verdict" in zero
// knowledge of the audio.
use risc0_zkvm::guest::env;

fn main() {
    let pcm: alloc::vec::Vec<i16> = env::read();
    let v = oo_detector::detect(&pcm);
    // public journal: (event, presence, voice_active, frames, active_frames, n_samples)
    env::commit(&(v.event, v.presence, v.voice_active, v.frames, v.active_frames, pcm.len() as u32));
}

extern crate alloc;
