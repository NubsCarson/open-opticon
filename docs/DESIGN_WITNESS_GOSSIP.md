# Design: witness-to-witness gossip (frontier — design, not built)

> Status: the **transferable fork proof** below is **SHIPPED** — produce + verify +
> **one-hop relay among pinned peers**. Only **epidemic re-flooding** and
> **discovery / membership** remain design-only and are honestly frontier. This doc
> scopes the difference: the parts that were clean buildable slices (built) vs the
> parts that would be a stub if rushed (not built). A planning artifact, not a claim
> that the full mesh exists.

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

- **Relay it (one-hop)** ✅ — on assembling a proof, a serve daemon best-effort POSTs
  it to each pinned peer's `POST /equivocation-intake`; the receiver **re-verifies it
  under ITS OWN pinned keys** (resolving each witness name from self + `--peer`,
  never the self-reported keys) and only then latches + re-serves it. So a verified
  fork propagates to a peer that pinned the two witnesses but had not yet cross-checked
  the split. Self-authenticating: a bogus POST can't force a false latch
  (`TestDaemonAdoptsRelayedProof`, `make witness-e2e`).

Strictly within the already-pinned set, **one hop, no transitive re-flood**.

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

The **transferable fork proof** is **done** — produce, offline verify, and one-hop
relay among pinned peers. What remains is genuinely frontier: **epidemic re-flooding**
(transitive propagation under partial connectivity — fan-out, dedup, loop/eclipse
resistance) and **discovery / membership** (which must preserve "every counted witness
is an independently pinned key" — trust-on-first-use is rejected). Defer both until a
concrete multi-operator deployment exists to design them against; until then they stay
honestly listed as frontier in [`ROADMAP.md`](ROADMAP.md), not half-built.
