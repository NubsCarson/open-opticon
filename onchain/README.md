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

The full **audio+nonce-bound** stack is deployed live on Ethereum Sepolia — anyone
can call it permissionlessly (no trust in this repo or its operator):

| Contract | Address |
|---|---|
| HonestEarQuorum (ZK + device P-256, audio+nonce-bound 2-of-2) | [`0x05DAa5dc9C21f4d17e930a158A3fc636de5D1815`](https://sepolia.etherscan.io/address/0x05DAa5dc9C21f4d17e930a158A3fc636de5D1815) |
| HonestEarVerifier (zk receipt) | [`0xdf52D19185CE798b7842874649344Ae5de5e40e2`](https://sepolia.etherscan.io/address/0xdf52D19185CE798b7842874649344Ae5de5e40e2) |
| CheckpointAnchor (log anchor) | [`0xB6F85c08e35799300Fa66dD421D10C3467b54634`](https://sepolia.etherscan.io/address/0xB6F85c08e35799300Fa66dD421D10C3467b54634) |
| RiscZeroGroth16Verifier | [`0x819162b456674F8B98f560d1aB375aD4e5401507`](https://sepolia.etherscan.io/address/0x819162b456674F8B98f560d1aB375aD4e5401507) |

The two `CheckpointAnchor.anchor()` transactions (a consistency-proven 3→5
extension) executed on-chain, and a live `eth_call` to `HonestEarQuorum.verdict`
returns `(2, 1)` — alarm_tone, presence — i.e. the ZK proof and the device
signature, bound to the SAME nonce and the SAME audio, agree on a public chain.
(Deployed from a disposable testnet key; in production you'd reuse RISC Zero's
canonical verifier router rather than deploy your own.)

**Schema freeze (honest):** this contract is an *immutable* PoC snapshot deployed
from rev `e47cf21`, before commit `25b89ff` added the streaming-hash-chain
`prev_digest` (CBOR key 10) that grew the device payload from a 10-map to an
11-map. So the live `eth_call` uses [`test/sepolia_fixture.json`](test/sepolia_fixture.json)
— the era-matched 10-map fixtures the contract was deployed against. The *current*
11-map fixtures (`test/quorum_fixture.json`) drive the **local** `forge test` at
today's schema and would revert `not a 10-map` against the frozen deploy; that gap
(deployed bytecode vs current source) closes only on a redeploy — the runbook for
that (verified locally; needs only a funded key + your go) is [`REDEPLOY.md`](REDEPLOY.md).

Verify it yourself (view-only, no funds): `bash onchain/call-sepolia.sh`.

## On-chain scope & limitations (honest)

This is a PoC public-verification leg, not a hardened production deployment. What
it does and does not guarantee:

- **The device leg is Tier-1 on the live deploy.** `HonestEarQuorum` pins one
  device key (`devicePubX/Y`); on Sepolia that is the *published* QEMU test key
  (see [THREAT_MODEL](../docs/THREAT_MODEL.md)). So the device leg proves "genuine
  published code signed this", not "a specific non-cloneable device" — the same
  Tier-1 caveat as the off-chain verifier. With a public key anyone can mint device
  payloads, so on-chain counter anti-replay is only meaningful once the device key
  is a non-extractable per-device key (Tier 2 / i.MX CAAM). The source bounds the
  counter below `type(uint64).max` so the monotonic check can't be wedged at the
  integer boundary, but that is hygiene, not a substitute for a real device key.
- **No domain separation (cross-chain / cross-instance replay).** The P-256
  signature and the zk receipt are bound to each *other* (same nonce + same audio)
  but NOT to a chain id or contract address, so a bundle valid here is replayable
  into another deployment of the same contract (another chain, or a second
  instance). Binding `chainid` + the contract address into the signed payload AND
  the zk journal closes this; it needs a TA + zk-guest wire change and a re-prove,
  so it is tracked in [ROADMAP](../docs/ROADMAP.md), not done in this PoC.
- **`CheckpointAnchor.anchor()` is permissionless; the signature is authenticated
  off-chain.** On-chain it guarantees *append-only consistency* (each checkpoint
  must prove an RFC 9162 extension of the anchored one — a fork/rewrite reverts).
  It does NOT verify the checkpoint's P-256 signature on-chain; that signature is
  emitted in the `Anchored` event for off-chain authentication against the
  published log key. A consistency proof to a *different* root needs the operator's
  own leaf data, so a third party can only relay the operator's real checkpoints,
  not forge new ones — but the *first* (seeding) call on a fresh deploy is
  unauthenticated (the live instance is already seeded by the deployer). On-chain
  log-key verification (RIP-7212 / OpenZeppelin P256) is the documented upgrade.
- **The live contracts are an immutable PoC snapshot.** The Sepolia addresses were
  deployed from an earlier source revision and cannot be changed. Hardening added
  to the source after deploy (the counter-boundary guard, strictly-ascending CBOR
  keys) applies to any *future* deploy; the live instances are not upgraded.

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
