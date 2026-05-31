// Prove + verify that the published detector produced a verdict over some audio,
// in zero knowledge of the audio. Usage: he-zk-prove <pcm_s16le_mono>
use methods::{DETECTOR_ELF, DETECTOR_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::fs;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let path = std::env::args().nth(1).expect("usage: he-zk-prove <pcm_s16le_mono>");
    let bytes = fs::read(&path).expect("read pcm");
    let pcm: Vec<i16> = bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    let env = ExecutorEnv::builder().write(&pcm).unwrap().build().unwrap();
    let receipt = default_prover().prove(env, DETECTOR_ELF).unwrap().receipt;

    // Anyone can verify the receipt against the published guest image id.
    receipt.verify(DETECTOR_ID).expect("zk receipt failed to verify");

    let (event, presence, voice_active, frames, active, n): (u32, u32, u32, u32, u32, u32) =
        receipt.journal.decode().unwrap();
    let name = ["none", "voice", "alarm_tone"][event as usize];
    println!("ZK-VERIFIED  detector(audio) proven in zero knowledge");
    println!("  event        : {name}");
    println!("  presence     : {presence}");
    println!("  voice_active : {voice_active}");
    println!("  frames       : {frames}  (active {active})");
    println!("  samples      : {n}  (audio itself never revealed)");
    println!("  image_id     : {}", hex_id(&DETECTOR_ID));
}

fn hex_id(id: &[u32; 8]) -> String {
    id.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join("")
}
