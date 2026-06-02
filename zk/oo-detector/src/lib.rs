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
const TONE_BINS: usize = 3; // probe 3 frequencies across the band ...
const TONE_BAND_HZ: i64 = 200; // ... 2900 / 3100 / 3300 Hz (matches he_detector.c defaults)

/// The detector's verdict, mirroring he_detect_result_t in he_detector.h.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Verdict {
    /// Event class (mirror he_detector.h): 0=none, 1=voice, 2=alarm_tone.
    pub event: u32,
    pub presence: u32,
    pub voice_active: u32,
    pub frames: u32,
    pub active_frames: u32,
    // tone_frames/voice_frames exist for parity with the C struct; the event
    // decision uses the locals, and the guest commits neither (see guest main).
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

/// Goertzel coefficient 2*cos(2*pi*f/fs) in Q15 (mirrors he_coeff_q15 in C).
fn coeff_q15(f: i64, fs: i64) -> i64 {
    let theta_q28 = (TWO_PI_Q28 * f) / fs;
    let cos_val = cos_q28(theta_q28);
    ((2 * cos_val) >> 13) as i32 as i64 // mirror C int32_t coeff
}

/// The k-th probe frequency across the band (mirrors he_probe_freq in C).
fn probe_freq(k: usize, bins: usize) -> i64 {
    if bins <= 1 {
        return TONE_FREQ_HZ;
    }
    TONE_FREQ_HZ - TONE_BAND_HZ + (2 * TONE_BAND_HZ * k as i64) / (bins as i64 - 1)
}

/// Run the detector over little-endian s16 mono PCM samples.
pub fn detect(pcm: &[i16]) -> Verdict {
    // Probe a small band of frequencies around the center (mirrors he_detector.c):
    // take the strongest Goertzel power across the probes per frame.
    let bins = TONE_BINS;
    let mut coeff = [0i64; TONE_BINS];
    for k in 0..bins {
        coeff[k] = coeff_q15(probe_freq(k, bins), SAMPLE_RATE);
    }
    let n_frames = pcm.len() / FRAME_SAMPLES;
    let (mut frames, mut active, mut tone, mut voice) = (0u32, 0u32, 0u32, 0u32);
    for f in 0..n_frames {
        let frame = &pcm[f * FRAME_SAMPLES..f * FRAME_SAMPLES + FRAME_SAMPLES];
        let mut s1 = [0i64; TONE_BINS];
        let mut s2 = [0i64; TONE_BINS];
        let mut energy: i64 = 0;
        for &sample in frame {
            let x = (sample as i64) >> INPUT_SHIFT;
            for k in 0..bins {
                let s0 = x + ((coeff[k] * s1[k]) >> 15) - s2[k];
                s2[k] = s1[k];
                s1[k] = s0;
            }
            energy += x * x;
        }
        frames += 1;
        if energy < ENERGY_FLOOR { continue; }
        active += 1;
        let mut max_power: i64 = 0;
        for k in 0..bins {
            let mut power = s1[k] * s1[k] + s2[k] * s2[k] - ((coeff[k] * s1[k]) >> 15) * s2[k];
            if power < 0 { power = 0; }
            if power > max_power { max_power = power; }
        }
        if max_power >= energy * TONE_RATIO_MIN { tone += 1; } else { voice += 1; }
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

    // The FULL tone verdict (not just .event): a 3.1 kHz tone is alarm_tone with
    // presence, no voice, tone frames dominating, and frames == n/frame_samples.
    #[test]
    fn tone_full_verdict_fields() {
        let n = 16000usize;
        let mut tone: Vec<i16> = Vec::with_capacity(n);
        for i in 0..n {
            let ang = (TWO_PI_Q28 * 3100 * i as i64) / SAMPLE_RATE - HALF_PI_Q28;
            tone.push(((8000i64 * cos_q28(ang)) >> 28) as i16);
        }
        let r = detect(&tone);
        assert_eq!(r.event, 2, "alarm_tone");
        assert_eq!(r.presence, 1, "tone => presence");
        assert_eq!(r.voice_active, 0, "a tone is not voice");
        assert!(r.tone_frames > r.voice_frames, "tone frames dominate");
        assert_eq!(r.frames, (n / 256) as u32, "frame count is n/frame_samples");
    }

    // The C reference's deterministic LCG noise_sample (test/test_detector.c:34-40).
    fn lcg_noise(n: usize, amp: i32) -> Vec<i16> {
        let mut rng: u32 = 0x1234_5678;
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
            let v = ((rng >> 16) & 0xffff) as i32 - 32768;
            buf.push(((v * amp) / 32768) as i16);
        }
        buf
    }

    // Broadband "voice-like" noise (amp 14000) => VOICE, matching the C reference;
    // the same noise below the floor (amp 150) => NONE (privacy: a quiet room).
    #[test]
    fn broadband_is_voice_quiet_is_none() {
        let r = detect(&lcg_noise(16000, 14000));
        assert_eq!(r.event, 1, "broadband => VOICE");
        assert_eq!(r.voice_active, 1, "broadband => voice_active");
        assert!(r.voice_frames > r.tone_frames, "voice frames dominate");

        let q = detect(&lcg_noise(16000, 150));
        assert_eq!(q.event, 0, "below-floor noise => NONE");
        assert_eq!(q.presence, 0, "below-floor => no presence");
    }
}
