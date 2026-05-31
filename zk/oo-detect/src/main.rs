// oo-detect — run the Rust port (oo_detector) over a PCM file and print the
// verdict in the SAME format as the C CLI `he-detect` (sim/he_detect_cli.c), so
// test/run_port_diff.sh can assert the two implementations agree line-for-line.
// This is the automated half of the "faithful port" claim in zk/README.md.
use oo_detector::detect;
use std::fs;

fn main() {
    let path = std::env::args().nth(1).expect("usage: oo-detect <pcm_s16le_mono>");
    let bytes = fs::read(&path).expect("read pcm");
    let pcm: Vec<i16> = bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let v = detect(&pcm);
    let name = ["none", "voice", "alarm_tone"][v.event as usize];
    println!(
        "event={name} presence={} voice_active={} frames={} active={} tone={} voice={}",
        v.presence, v.voice_active, v.frames, v.active_frames, v.tone_frames, v.voice_frames
    );
}
