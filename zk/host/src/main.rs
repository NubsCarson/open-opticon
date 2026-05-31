// Prove + verify that the published detector produced a verdict over some audio,
// in zero knowledge of the audio, bound to a verifier nonce.
// Usage: he-zk-prove <pcm_s16le_mono> [nonce_hex]
use methods::{DETECTOR_ELF, DETECTOR_ID};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::fs;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let path = std::env::args().nth(1).expect("usage: he-zk-prove <pcm_s16le_mono> [nonce_hex]");
    let nonce_hex = std::env::args().nth(2).unwrap_or_else(|| "aabbccdd".to_string());
    let nonce = decode_hex(&nonce_hex);
    let bytes = fs::read(&path).expect("read pcm");
    let pcm: Vec<i16> = bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    let env = ExecutorEnv::builder()
        .write(&pcm)
        .unwrap()
        .write(&nonce)
        .unwrap()
        .build()
        .unwrap();
    let receipt = default_prover().prove(env, DETECTOR_ELF).unwrap().receipt;

    // Anyone can verify the receipt against the published guest image id.
    receipt.verify(DETECTOR_ID).expect("zk receipt failed to verify");

    let (event, presence, voice_active, frames, active, n, nonce_hash): (
        u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        [u32; 8],
    ) = receipt.journal.decode().unwrap();
    let name = ["none", "voice", "alarm_tone"][event as usize];
    let nh: String = nonce_hash.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect();
    println!("ZK-VERIFIED  detector(audio) proven in zero knowledge");
    println!("  event        : {name}");
    println!("  presence     : {presence}");
    println!("  voice_active : {voice_active}");
    println!("  frames       : {frames}  (active {active})");
    println!("  samples      : {n}  (audio itself never revealed)");
    println!("  nonce_sha256 : {nh}  (binds the proof to the challenge)");
    // Canonical risc0 image id (same bytes the on-chain verifier + he-zk-export use).
    println!("  image_id     : {}", Digest::from(DETECTOR_ID));
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "nonce hex must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad nonce hex"))
        .collect()
}
