// Produce a Groth16 receipt of the detector and export it for on-chain
// verification. Usage: he-zk-export <pcm_s16le_mono> <out.json>
//
// A Groth16 proof is a succinct SNARK an EVM contract can verify cheaply (the
// STARK receipt is first proven, then wrapped STARK->SNARK). This step needs an
// x86 host with Docker (the wrap runs in a container); it is a batch/audit
// operation, like the STARK proof itself. The output JSON carries the image id,
// the public journal (the verdict — never the audio), and the Ethereum-encoded
// seal, consumed by onchain/test/HonestEarVerifier.t.sol.
use methods::{DETECTOR_ELF, DETECTOR_ID};
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use std::fs;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let path = std::env::args().nth(1).expect("usage: he-zk-export <pcm> <out.json> [nonce_hex]");
    let out = std::env::args().nth(2).expect("usage: he-zk-export <pcm> <out.json> [nonce_hex]");
    // The verifier's challenge the proof is bound to (must match the device
    // bundle's nonce for the on-chain quorum to accept the pair).
    let nonce_hex = std::env::args().nth(3).unwrap_or_else(|| "aabbccdd".to_string());
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
    let receipt = default_prover()
        .prove_with_opts(env, DETECTOR_ELF, &ProverOpts::groth16())
        .expect("groth16 prove (needs x86 + Docker)")
        .receipt;
    receipt.verify(DETECTOR_ID).expect("zk receipt failed to verify");

    let seal = encode_seal(&receipt).expect("encode seal for ethereum");
    let journal = receipt.journal.bytes.clone();
    let image_id = Digest::from(DETECTOR_ID);

    let json = format!(
        "{{\n  \"imageId\": \"0x{}\",\n  \"journal\": \"0x{}\",\n  \"seal\": \"0x{}\"\n}}\n",
        hex(image_id.as_bytes()),
        hex(&journal),
        hex(&seal)
    );
    fs::write(&out, json).expect("write fixture");
    eprintln!(
        "wrote {out}: journal {} bytes, seal {} bytes, image_id 0x{}",
        journal.len(),
        seal.len(),
        hex(image_id.as_bytes())
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "nonce hex must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad nonce hex"))
        .collect()
}
