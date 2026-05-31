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
src/HonestEarQuorum.sol     heterogeneous dual-root check (both-required 2-of-2),
                            on-chain: returns a verdict only if a ZK proof (Groth16)
                            AND the device's secp256r1 signature over its
                            bound-output payload (OpenZeppelin P256) AGREE on the
                            predicate (event, presence, voice_active, frames).
                            Decodes the device verdict from the deterministic-CBOR
                            payload; recordVerdict enforces counter anti-replay.
test/HonestEarQuorum.t.sol + test/quorum_fixture.json  a real proof + a real device
                            bundle for the same clip agree; a disagreeing bundle, a
                            tampered receipt, and a tampered signature all revert.
script/Deploy.s.sol         deploy the wrapper against a canonical RISC Zero verifier.
script/DeployLocal.s.sol    deploy the FULL stack + run live txs on a local EVM.
```

## The dual-root check, on-chain (a both-required 2-of-2)

The off-chain Go verifier is stdlib-only and cannot verify a STARK; the EVM can
verify both a Groth16 receipt and a secp256r1 signature, so the heterogeneous
check lives here: `HonestEarQuorum` requires an independent **ZK proof of the
computation** AND the **device's hardware-bound P-256 signature**, and returns a
verdict only if both verify and agree. A single broken enclave, or a forged
signature, is not enough. The two roots are **cryptographically bound to the same
observation** — the same verifier nonce AND the same input bytes: the guest
commits sha256(nonce) and sha256(audio), and the contract requires both to equal
the device payload's nonce hash and its `input_hash`. So a proof and a signature
from different sessions OR different audio cannot be combined, even against a
misbehaving device. `recordVerdict` adds on-chain anti-replay (the device counter
must advance). This is one realisable leg of the broader 2-of-3 vision ({TEE, ZK,
phone}).

## Live on Sepolia (public testnet)

A full stack is deployed live on Ethereum Sepolia — anyone can call it
permissionlessly (no trust in this repo or its operator). The deployed contracts
below are the **nonce-bound (v1)** version; the **audio+nonce-bound version in
this repo** is verified locally (`forge test`, 12/12) and a live re-deploy is
pending a small testnet top-up (the addresses will be updated when it lands).

| Contract (v1, nonce-bound — live) | Address |
|---|---|
| HonestEarQuorum (ZK + device P-256, 2-of-2) | [`0x5d91D5C07048A3e9a8f57A9198f031F7021707f6`](https://sepolia.etherscan.io/address/0x5d91D5C07048A3e9a8f57A9198f031F7021707f6) |
| HonestEarVerifier (zk receipt) | [`0xA14D86C47B9D7702b81EF1789b5152f81a2c4817`](https://sepolia.etherscan.io/address/0xA14D86C47B9D7702b81EF1789b5152f81a2c4817) |
| CheckpointAnchor (log anchor) | [`0x9B50374B32E88123c36ca6227a59ce8fb76D9240`](https://sepolia.etherscan.io/address/0x9B50374B32E88123c36ca6227a59ce8fb76D9240) |
| RiscZeroGroth16Verifier | [`0xe0ABbE2DA2D8aA05C41bF11F7E335663637f17E7`](https://sepolia.etherscan.io/address/0xe0ABbE2DA2D8aA05C41bF11F7E335663637f17E7) |

The two `CheckpointAnchor.anchor()` transactions (a consistency-proven 3→5
extension) executed on-chain, and a live `eth_call` to that v1
`HonestEarQuorum.verdict` returned `(2, 1)` — alarm_tone, presence — i.e. the ZK
proof and the device signature agree, on a public chain. (Deployed from a
disposable testnet key; in production you'd reuse RISC Zero's canonical verifier
router rather than deploy your own.)

## Deploy the whole stack on a local EVM (no funds)

```sh
anvil &
forge script script/DeployLocal.s.sol --rpc-url http://localhost:8545 \
    --broadcast --private-key <anvil key>
```

anvil is a real EVM implementation (a local devnet, not a public testnet). The
script deploys the verifier, the receipt wrapper, the log anchor, and the quorum,
then runs live state-changing transactions — anchoring a consistency-proven
checkpoint sequence — and reads back both the zk verdict and the dual-root agreed
verdict via view calls. The same script deployed the live Sepolia stack above
(`--rpc-url <sepolia> --private-key <funded>`).

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

## Deploying to another chain (production note)

The Sepolia stack above was deployed with `DeployLocal.s.sol` (which also deploys
its own RISC Zero verifier — fine for a self-contained demo). On a production
chain, reuse RISC Zero's canonical, audited
[verifier router](https://dev.risczero.com/api/blockchain-integration/contracts/verifier)
for that chain instead of deploying your own Groth16 verifier:

```sh
RISC0_VERIFIER=0x<canonical router> IMAGE_ID=0x<guest imageId> \
    forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --private-key $PK
```

Anchoring the transparency-log checkpoints to an L2 (the censorship-resistant
registry) is implemented as `CheckpointAnchor.sol` — its consistency enforcement
is proven locally by `forge test`; the same live-deploy step (funded key + RPC)
is all that's deferred, sharing this deployment path.
