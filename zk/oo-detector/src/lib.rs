//! Faithful Rust port of the published C detector (src/common/he_detector.c) —
//! integer-only Goertzel + VAD. This is the SAME classification the OP-TEE TA
//! computes; it is validated against the C reference verdicts (see zk/README.md)
//! and runs unchanged inside the zkVM guest. no_std so it compiles for the guest.
#![no_std]

const Q28_ONE: i64 = 1 << 28;
const PI_Q28: i64 = 843314857;
const TWO_PI_Q28: i64 = 1686629714;
const HALF_PI_Q28: i64 = 421657428;

const SAMPLE_RATE: i64 = 16000;
const FRAME_SAMPLES: usize = 256;
const TONE_FREQ_HZ: i64 = 3100;
const INPUT_SHIFT: i64 = 6;
const ENERGY_FLOOR: i64 = 200000;
const MIN_ACTIVE_FRAMES: u32 = 8;
const TONE_RATIO_MIN: i64 = 40;

/// Event classes (mirror he_detector.h): 0=none, 1=voice, 2=alarm_tone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Verdict {
    pub event: u32,
    pub presence: u32,
    pub voice_active: u32,
    pub frames: u32,
    pub active_frames: u32,
    pub tone_frames: u32,
    pub voice_frames: u32,
}

fn cos_q28(mut a: i64) -> i64 {
    let mut sign: i64 = 1;
    a %= TWO_PI_Q28;
    if a < 0 { a += TWO_PI_Q28; }
    if a > PI_Q28 { a = TWO_PI_Q28 - a; }
    if a > HALF_PI_Q28 { a = PI_Q28 - a; sign = -1; }
    let x2 = (a * a) >> 28;
    let mut acc = Q28_ONE;
    acc -= x2 / 2;
    let mut t = (x2 * x2) >> 28;
    acc += t / 24;
    t = (t * x2) >> 28;
    acc -= t / 720;
    sign * acc
}

/// Run the detector over little-endian s16 mono PCM samples.
pub fn detect(pcm: &[i16]) -> Verdict {
    let theta_q28 = (TWO_PI_Q28 * TONE_FREQ_HZ) / SAMPLE_RATE;
    let cos_val = cos_q28(theta_q28);
    let coeff_q15: i64 = ((2 * cos_val) >> 13) as i32 as i64; // mirror C int32_t coeff
    let n_frames = pcm.len() / FRAME_SAMPLES;
    let (mut frames, mut active, mut tone, mut voice) = (0u32, 0u32, 0u32, 0u32);
    for f in 0..n_frames {
        let frame = &pcm[f * FRAME_SAMPLES..f * FRAME_SAMPLES + FRAME_SAMPLES];
        let (mut s1, mut s2, mut energy): (i64, i64, i64) = (0, 0, 0);
        for &sample in frame {
            let x = (sample as i64) >> INPUT_SHIFT;
            let s0 = x + ((coeff_q15 * s1) >> 15) - s2;
            s2 = s1;
            s1 = s0;
            energy += x * x;
        }
        frames += 1;
        if energy < ENERGY_FLOOR { continue; }
        active += 1;
        let mut power = s1 * s1 + s2 * s2 - ((coeff_q15 * s1) >> 15) * s2;
        if power < 0 { power = 0; }
        if power >= energy * TONE_RATIO_MIN { tone += 1; } else { voice += 1; }
    }
    let presence = if active >= MIN_ACTIVE_FRAMES { 1 } else { 0 };
    let (event, voice_active) = if presence == 1 && tone * 2 >= active {
        (2, 0)
    } else if presence == 1 && voice >= MIN_ACTIVE_FRAMES {
        (1, 1)
    } else {
        (0, 0)
    };
    Verdict { event, presence, voice_active, frames, active_frames: active, tone_frames: tone, voice_frames: voice }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    // A pure 3.1 kHz tone classifies as alarm_tone; silence as none — matching
    // the C reference (he-detect) on the same inputs.
    #[test]
    fn tone_is_alarm_silence_is_none() {
        let n = 16000usize; // 1 s @ 16 kHz
        let mut tone: Vec<i16> = Vec::with_capacity(n);
        // integer-stepped sine ~3100 Hz, amplitude 8000 (matches gen_frames)
        for i in 0..n {
            // s = 8000 * sin(2*pi*3100*i/16000), via the same fixed-point cos shifted by pi/2
            let ang = (TWO_PI_Q28 * 3100 * i as i64) / SAMPLE_RATE - HALF_PI_Q28;
            let s = (8000i64 * cos_q28(ang)) >> 28;
            tone.push(s as i16);
        }
        assert_eq!(detect(&tone).event, 2, "3.1kHz tone must be alarm_tone");
        let silence = std::vec![0i16; n];
        assert_eq!(detect(&silence).event, 0, "silence must be none");
    }
}
