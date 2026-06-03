# Redeploying to Sepolia — closing the schema-freeze gap

> **✅ Executed 2026-06-03.** The stack was redeployed at the **current 11-map
> schema** (path A below), so the live deployment now tracks `src/`. The live
> `eth_call` reads the same `test/proof_fixture.json` + `test/quorum_fixture.json`
> as the local `forge test`; the era-matched `test/sepolia_fixture.json` was removed
> (path-B step). Current live addresses are in [`README.md`](README.md) — HonestEarQuorum
> `0x31695C18…`, HonestEarVerifier `0xFEBFAdf6…`, CheckpointAnchor `0x742Ad456…`,
> RiscZeroGroth16Verifier `0x956CD961…`. This runbook is retained for any **future**
> redeploy (e.g. another device-schema change).

Background: the *previous* live contracts were an immutable PoC snapshot deployed
from rev `e47cf21`, before commit `25b89ff` grew the device payload from a 10-map to
an 11-map (the `prev_digest` hash-chain link, CBOR key 10). The frozen `HonestEarQuorum`
could only decode the old 10-map fixture, while the current source + fixtures are an
11-map — so the live deployment had to be **redeployed** to track today's source.

Everything below the broadcast step is verified locally first; the deploy itself is a
real, irreversible public-chain action, so it is run deliberately with a funded key.

## What's already verified (no key, no funds)

The current-schema stack deploys and the dual-root quorum agrees, in a simulated EVM:

```sh
cd onchain
forge script script/DeployQuorum.s.sol -vv
#   2-of-2 agreed event    : 2     (alarm_tone)
#   2-of-2 agreed presence : 1
```

and `forge test` (the `onchain-verify` CI job) deploys the full stack against a real
EVM and checks the proof + device signature + anchor every push. So a redeploy is
known-good *before* you spend a single testnet wei.

## Step 1 — deploy (needs a funded Sepolia key + RPC)

You have two paths. Both read the committed `test/*.json` fixtures; neither needs
r0vm (the proof is already generated and committed).

**A. Exact mirror of the current live setup** (verifier + wrapper + anchor + quorum,
and it anchors the same consistency-proven 3→5 checkpoint):

```sh
cd onchain
forge script script/DeployLocal.s.sol \
    --rpc-url "$RPC" --private-key "$PK" --broadcast
# prints the 4 new addresses + anchor latestSize=5 + agreed (2,1)
```

**B. Production-shaped** (recommended for a "real" deploy): reuse RISC Zero's
canonical, audited verifier **router** instead of deploying your own Groth16
verifier, then deploy just the wrapper (and, if you want the quorum/anchor, adapt
`DeployQuorum`/`DeployLocal` to take the router address):

```sh
RISC0_VERIFIER=0x<canonical sepolia router> IMAGE_ID=0x<guest imageId> \
forge script script/Deploy.s.sol --rpc-url "$RPC" --private-key "$PK" --broadcast
```

`IMAGE_ID` is the canonical guest image id printed by `he-zk-prove`/`he-zk-export`
(it must match `test/proof_fixture.json`'s `imageId`).

> Key hygiene: use a **disposable** testnet key with only Sepolia funds. Never commit
> it; pass it via `$PK`/env, not a file in the repo. (The original deploy used a
> throwaway key for exactly this reason.)

## Step 2 — repoint the committed live-trackers at the new deploy

A fresh deploy uses the **current 11-map schema**, so the era-matched
`sepolia_fixture.json` workaround is no longer needed — the live check can read the
current fixtures again. Update, in one commit:

1. **`onchain/call-sepolia.sh`** — set `QUORUM=0x<new HonestEarQuorum>`. Since the new
   contract speaks the current schema, either (a) regenerate
   `test/sepolia_fixture.json` from the *current* fixtures —
   `seal`/`journal` from `proof_fixture.json`, `payload`/`sig`/`expect` from
   `quorum_fixture.json`'s `alarm` (0x-prefix each), update its `_note` — or (b)
   simpler, point the script back at `quorum_fixture.json` + `proof_fixture.json` and
   delete `sepolia_fixture.json`. Keep the loud-fail `(event,presence)` guard.
2. **`docs/transparency.html`** — set `ANCHOR` to the new `CheckpointAnchor` address.
   `COMMITTED_ROOT`/`COMMITTED_SIZE` stay as-is **iff** you anchored the same
   `checkpoint_fixture.json` (path A does; `latestSize=5`,
   `latestRoot=0xd3fb…462`). If you anchored a different sequence, update them to the
   new `latestRoot`/`latestSize`.
3. **`onchain/README.md`** — replace the four addresses in the "Live on Sepolia" table,
   and **drop the "Schema freeze (honest)" paragraph** (it no longer applies once the
   live bytecode matches `src/`). Keep the disposable-key / not-production-hardened
   notes.

## Step 3 — verify the new deploy (view-only, no funds)

```sh
bash onchain/call-sepolia.sh        # expect: event=2 (alarm_tone), presence=1, exit 0
# open docs/transparency.html (make sites) -> green "matches the committed checkpoint"
```

`call-sepolia.sh` exits non-zero unless the live `(event,presence)` equals the
expected tuple, so a wrong/failed deploy fails loudly rather than looking fine.

## What this does and does NOT change

- **Closes:** the deployed-bytecode-vs-current-source drift; the live `eth_call` then
  exercises the *same* 11-map payload the local tests and the verifier use.
- **Does not change** the honest scope: the device leg is still the *published* QEMU
  test key (Tier-1, "genuine published code signed this", not device identity), the
  anchor's first seeding call is still unauthenticated, and there is still no
  cross-chain domain separation. Those are documented in `README.md` and are
  hardware/design items, not redeploy items.
