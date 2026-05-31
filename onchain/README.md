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
src/CheckpointAnchor.sol    anchors the transparency-log signed checkpoints to an
                            immutable ledger: each new checkpoint must be a proven
                            append-only extension of the last (RFC 9162 consistency
                            verified on-chain via the SHA-256 precompile), so a fork
                            or rewrite is rejected. A faithful port of
                            VerifyConsistency in src/verifier/transparency.go.
test/CheckpointAnchor.t.sol + test/checkpoint_fixture.json  a REAL consistency proof
                            (tree size 3 -> 5 from `he-log consistency`) anchors;
                            a forked root and a rollback both revert.
src/HonestEarQuorum.sol     heterogeneous 2-of-3, on-chain: returns a verdict only
                            if a ZK proof (Groth16) AND the device's secp256r1
                            signature over its bound-output payload (OpenZeppelin
                            P256) AGREE on (event, presence). Decodes the device
                            verdict from the deterministic-CBOR payload directly.
test/HonestEarQuorum.t.sol + test/quorum_fixture.json  a real proof + a real device
                            bundle for the same clip agree; a disagreeing bundle, a
                            tampered receipt, and a tampered signature all revert.
script/Deploy.s.sol         deploy the wrapper against a canonical RISC Zero verifier.
script/DeployLocal.s.sol    deploy the FULL stack + run live txs on a local EVM.
```

## The 2-of-3, on-chain

The off-chain Go verifier is stdlib-only and cannot verify a STARK; the EVM can
verify both a Groth16 receipt and a secp256r1 signature, so the heterogeneous
2-of-3 lives here: `HonestEarQuorum` checks an independent **ZK proof of the
computation** and the **device's hardware-bound P-256 signature** and returns a
verdict only if they agree. A single broken enclave, or a forged signature, is
not enough.

## Deploy the whole stack on a local EVM (no funds)

```sh
anvil &
forge script script/DeployLocal.s.sol --rpc-url http://localhost:8545 \
    --broadcast --private-key <anvil key>
```

This deploys the verifier, the receipt wrapper, the log anchor, and the quorum,
then runs live transactions — anchoring a consistency-proven checkpoint sequence
and reading back both the zk verdict and the 2-of-3 agreed verdict. The same
script targets a public testnet with a funded key + RPC (the one deferred step).

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
registry) is implemented as `CheckpointAnchor.sol` — its consistency enforcement
is proven locally by `forge test`; the same live-deploy step (funded key + RPC)
is all that's deferred, sharing this deployment path.
