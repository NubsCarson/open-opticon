# Design: witness-to-witness gossip (frontier — design, not built)

> Status: the **transferable fork proof** below is now **SHIPPED** (produce +
> verify — see "The clean slice" section); the gossip **mesh / discovery** remain
> design-only and are honestly frontier. This doc scopes the difference: the part
> that was a clean buildable slice (built) vs the part that would be a stub if
> rushed (not built). A planning artifact, not a claim that the mesh exists.

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

## The clean slice: a transferable fork proof (SHIPPED — produce + verify)

The high-value piece needs **no new trust model and no new crypto**: make a detected
fork into a **portable fraud proof** anyone can verify independently. When
`checkPeers` latches a **same-size** split, the daemon holds two checkpoint bodies at
that size with **different roots**, each cosigned by a distinct **pinned witness**
(its own cosigned view + the divergent peer's). That pair *is* a self-contained proof.

Built and gated (`make witness-e2e`, `TestVerifyEquivocation`,
`TestDaemonServesEquivocationProof`):

- **Expose it** ✅ — `GET /equivocation-proof` returns `{schema, a, b}`, each side
  `{witness, checkpoint_body, cosignature, witness_pub_x/y}` (404 until detected).
- **Verify it** ✅ — `verifier.VerifyEquivocation(...)` accepts **iff** both
  cosignatures verify under the **caller-PINNED** witness keys (never the
  self-reported ones), same origin+size, different roots. CLI:
  `he-witness verify-equivocation --file proof.json --a-pub-x/-y --b-pub-x/-y`,
  so anyone — not just the detecting witness — can confirm the log equivocated.

Scope note (honest): the proof binds each half to a **pinned witness** cosignature
(the C2SP witness-cosigning model), so it proves *two independent pinned witnesses
saw conflicting roots* → the log equivocated. It covers the **same-size** split; the
inconsistent-extension case (different sizes) needs a failing consistency proof and
is intentionally out of scope of this artifact.

**Still to build (the next sub-slice, not a stub):** *relay* — on latching, a daemon
POSTs the proof to its pinned peers' intake so a peer that verifies it latches too.
Propagation **without** discovery, strictly within the already-pinned set. Deferred
only because it adds an intake endpoint with its own auth surface; produce+verify is
complete and valuable standalone (the detecting witness already holds both halves).

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

The **transferable fork proof** (produce + verify) is **done** — the local
equivocation latch is now shareable, offline-verifiable evidence. The next sub-slice
is *relay among pinned peers*; after that, defer epidemic gossip and discovery until
there is a concrete multi-operator deployment to design them against. Until then they
remain honestly listed as frontier in [`ROADMAP.md`](ROADMAP.md), not half-built.
