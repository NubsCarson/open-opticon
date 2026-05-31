# onchain — permissionless verification of the detector

The optional public-trust layer: anyone can verify, with **no trust in any
operator or enclave**, that the *published* detector produced a verdict — by
checking the [zk](../zk/README.md) receipt in a stateless EVM contract.

This is **not** the sensor and **not** a zkEVM. The device stays chain-free (a
chain adds nothing to verifying a local signature). The RISC-V zkVM proves the
*computation*; the EVM only provides *permissionless public verification* of
that proof, so the verdict isn't gated on a single off-chain verifier.

## What's here

```
src/HonestEarVerifier.sol   wraps RISC Zero's IRiscZeroVerifier: checkVerdict(seal,
                            journal) confirms a Groth16 proof for the pinned guest
                            imageId, then decodes the six-u32 journal (event,
                            presence, voice_active, frames, active_frames, n) — the
                            audio is never in it. recordVerdict() also logs the fact.
test/HonestEarVerifier.t.sol  deploys the real RiscZeroGroth16Verifier + the wrapper
                            and verifies a REAL proof fixture on a local EVM; tampering
                            the journal or the seal must revert.
test/proof_fixture.json     a genuine Groth16 receipt of the alarm_short clip
                            (imageId + journal + Ethereum-encoded seal), produced by
                            `he-zk-export` (zk/host). Committed so the test is
                            reproducible without re-proving (which needs Docker).
script/Deploy.s.sol         deploy the wrapper against a canonical RISC Zero verifier.
```

## Verify the proof yourself (local, no funds)

```sh
cd onchain
forge install foundry-rs/forge-std
forge install risc0/risc0-ethereum@v3.0.1
forge test -vv     # deploys the verifier + checks the real proof on a local EVM
```

`forge test` needs no network and no testnet funds: it runs the real RISC Zero
Groth16 verifier in-process and confirms the committed proof verifies for our
`imageId` and yields `event=alarm_tone, presence=1` — and that any tamper
reverts.

## Regenerate the proof fixture (needs x86 + Docker)

```sh
cd zk
cargo run --release --bin he-zk-export -- \
    ../test/fixtures/alarm_short.pcm ../onchain/test/proof_fixture.json
```

The STARK→SNARK wrap runs in a container; it is a batch/audit step (minutes),
like the STARK proof. The seal it emits is what the EVM verifier checks.

## Deploying to a testnet (the only deferred step)

Verifying the proof is fully proven locally above. A *live* deployment is the
one piece that needs a funded key + an RPC, so it is left as a documented step
rather than faked here. On a live chain, reuse RISC Zero's canonical, audited
[verifier router](https://dev.risczero.com/api/blockchain-integration/contracts/verifier)
for that chain — do not deploy your own Groth16 verifier in production:

```sh
RISC0_VERIFIER=0x<canonical router> IMAGE_ID=0x<guest imageId> \
    forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --private-key $PK
```

Anchoring the transparency-log checkpoints to an L2 (the censorship-resistant
registry) is the companion item on the roadmap; it shares this deployment path.
