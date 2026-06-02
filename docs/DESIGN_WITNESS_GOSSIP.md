# Design: witness-to-witness gossip (frontier — design, not built)

> Status: **design only.** Nothing here is implemented. This scopes the next slice
> of the transparency-witness story honestly — including the one part that is a
> clean, buildable-now slice and the part that is genuinely frontier and would be a
> stub if rushed. It is a planning artifact, not a claim of capability.

## What ships today

The anti-equivocation layer is real and tested:

- `he-logd` serves signed checkpoints + RFC 9162 consistency proofs.
- `he-witness check` polls a log, consistency-checks it, and **refuses to cosign** a
  fork or rewind (`poll` / `TestWitnessAcceptsConsistentExtensionRefusesFork`).
- `he-witness compare` does a **pairwise** witness-to-witness cross-check
  (`crossCheck` / `TestCrossCheck`).
- `he-witness serve --peer name,url,pubXhex,pubYhex` runs a daemon that
  **continuously cross-checks a set of PINNED peers** and latches
  `equivocation_detected` (flipping `/health` to 503) the moment a peer reports a
  divergent root at the same size (`checkPeers` / `TestDaemonPeerCrossCheck`).

The guarantee that buys: with *k* independent, pinned-key witnesses, a single log
operator cannot show different roots to different people without at least one
witness catching it — the off-chain analogue of `CheckpointAnchor`.

## The gap (and the honest tension)

Today the peer set is **explicitly configured and key-pinned**, and a detected
equivocation stays local to the daemon that saw it (surfaced only in its own
`/health`). Three things are missing for a true mesh:

1. **Propagation** — a fork seen by witness A is not relayed to B, C, … .
2. **Membership/discovery** — peers must be listed by hand; there is no way to learn
   new witnesses.
3. **Anti-entropy** — no epidemic reconciliation under partial connectivity / churn.

The tension that constrains the design: the whole anti-equivocation guarantee rests
on peers being **independent, pinned keys**. Naive "gossip discovery" /
trust-on-first-use would let an adversary inject witnesses it controls and *dilute*
the quorum — i.e. discovery doesn't just add convenience, it can **weaken** the
property. So a mesh here must gossip **among an enrolled, pinned set**, never
bootstrap trust from the network.

## The clean, buildable-now slice: a transferable fork proof

The high-value piece that needs **no new trust model and no new crypto** is making a
detected fork into a **portable fraud proof** anyone can verify independently.

When `checkPeers` latches `equivocation_detected`, the daemon already holds two
checkpoint bodies for the **same size** signed under the **same pinned log key** with
**different roots**. That pair *is* a self-contained proof of equivocation. The slice:

- **Expose it:** add `GET /equivocation-proof` returning
  `{size, checkpoint_a:{body,sig}, checkpoint_b:{body,sig}, log_pub_x/y}`.
- **Verify it:** a function (reusing the existing `verifySig` + checkpoint-body parse)
  that accepts the proof **iff** both signatures verify under the pinned log key, both
  are at the same size, and the roots differ. A CLI verb
  (`he-witness verify-equivocation --file proof.json --log-pub-x/-y`) and a unit test
  mirroring `TestDaemonPeerCrossCheck`.
- **Relay it:** on latching, a daemon POSTs the proof to its pinned peers'
  `/equivocation-proof` intake; a peer that verifies it latches too. This is
  propagation **without** discovery — strictly within the already-pinned set.

Why this is a clean slice, not a stub: it is deterministic, fully testable offline
(two conflicting signed checkpoints → one boolean), reuses the project's single
ECDSA path, and strengthens a property that already exists. It is the
"fork is now *transferable evidence*, not just a local 503" upgrade.

## What stays frontier (would be a stub if rushed)

- **Epidemic propagation under partial connectivity / churn** — push-pull anti-entropy,
  fan-out, dedup, backoff, eclipse-resistance. A real distributed-systems build; a
  small version would fake the hard parts (the failure modes are the point).
- **Membership beyond a pinned list** — any discovery mechanism must preserve "every
  counted witness is an independently pinned key," so this is a governance/enrollment
  design question, not just code. Trust-on-first-use is explicitly **rejected** (it
  weakens the guarantee, per the tension above).
- **Gossiping the full log (not just checkpoints/proofs)** — bandwidth/storage model
  for replicating entries, out of scope for an anti-equivocation mesh.

## Recommendation

Build the **transferable fork proof** slice (intake + verify + relay among pinned
peers) when the witness layer is next touched — it is small, testable, and turns the
existing local equivocation latch into shareable evidence. Defer epidemic gossip and
discovery until there is a concrete multi-operator deployment to design them against;
until then they remain honestly listed as frontier in [`ROADMAP.md`](ROADMAP.md), not
half-built.
