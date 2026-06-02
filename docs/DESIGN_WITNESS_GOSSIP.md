# Design: witness-to-witness gossip (frontier — design, not built)

> Status: the **transferable fork proof** below is **SHIPPED** end-to-end — produce +
> verify + relay with **transitive flooding** (each node re-pushes once; the `d.proof`
> latch is the seen-set, so it terminates) + **pull-based anti-entropy** (a node that
> was offline during the flood catches up by GET-ing peers' proofs on its next tick).
> What remains is **eclipse resistance** (an inherent limit of *any* pinned-trust model,
> not a feature to build) and **discovery / membership** (genuine frontier;
> trust-on-first-use is rejected because it weakens the guarantee). This doc scopes the
> difference: the parts that were clean buildable slices (built) vs the parts that are
> a stub-if-rushed or an inherent trust-model limit (not built). A planning artifact.

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

- **Flood it (transitive)** ✅ — on the FIRST adoption (its own detection or a relayed
  proof), a daemon re-pushes to its pinned peers. The `d.proof != nil` latch is the
  seen-set: each node re-pushes **at most once**, so cycles can't loop and the flood
  **terminates** (total messages are O(edges), not exponential). A fork detected
  anywhere spreads to every connected node in the pinned mesh
  (`TestDaemonRelayIsTransitiveOncePerNode`). **Limitation (honest):** the single
  `d.proof` flood slot means a node *propagates* only the *first* distinct fork it
  adopts; the 503 equivocation alarm is set unconditionally and is permanent, so the
  safety verdict ("this log is dishonest") is unaffected. This is a *propagation* limit,
  not a forensic one — see "Retain it" next. What stays deferred (below) is *flooding
  additional forks across the mesh* beyond the first, which would change the validated
  flood-termination invariant (the single-slot seen-set).

- **Retain it (local forensics)** ✅ — separate from the single-slot flood, a witness
  **keeps every distinct fork it verifies** in a local set, deduped by a canonical
  order-independent `proofKey` (a hash of the two checkpoint *bodies*, not the
  non-deterministic cosignatures) and bounded at `maxRetainedProofs = 64`. The full set
  is served at `GET /equivocation-proofs` (`{count, proofs}`), so a node is a complete
  forensic record of the forks it has seen even though it only re-floods the first
  (`TestDaemonRetainsDistinctProofs`). A relying party can pull-and-verify a peer's
  current proof in one step with
  `he-witness fetch-proof --peer-url URL --a-pub-x/-y --b-pub-x/-y [--origin O]`.

- **Catch up (pull anti-entropy)** ✅ — the push flood is best-effort, so a node that
  was offline or transiently unreachable would miss it. On each tick, a node that holds
  NO proof also GETs each pinned peer's `/equivocation-proof` and adopts the first valid
  one (same `tryAdopt` path — verified under our pinned keys, origin-scoped). Because the
  entire replicated state is a *single* proof, a per-tick pull is **complete**
  reconciliation, not a sketch (`TestDaemonPullsProofFromPeer`).

Strictly within the already-pinned set.

## What stays frontier (would be a stub if rushed)

- **Eclipse resistance** — an adversary who controls *all* of a node's pinned peers can
  hide a fork from it. This is NOT a feature to build: it is an inherent property of any
  pinned-trust model (you trust your pins). The honest mitigation is operational — pin
  several independent peers — and it is a documented limitation, not a TODO.
- **Membership / discovery beyond a pinned list** — any discovery mechanism must preserve
  "every counted witness is an independently pinned key," so it is a governance/enrollment
  design question, not just code. Trust-on-first-use is explicitly **rejected** (it
  weakens the guarantee, per the tension above). Genuine frontier.
- **Gossiping the full log (not just checkpoints/proofs)** — bandwidth/storage model
  for replicating entries, out of scope for an anti-equivocation mesh.

## Recommendation

The **transferable fork proof** is **done** end-to-end — produce, offline verify,
relay with terminating transitive flooding, and pull-based anti-entropy so an offline
node catches up. What's left is not a clean slice: **eclipse resistance** is an inherent
limit of the pinned-trust model (mitigated operationally by pinning several independent
peers, not by code), and **discovery / membership** is genuine governance frontier
(trust-on-first-use is rejected). Defer discovery until a concrete multi-operator
deployment exists to design it against; until then it stays honestly listed as frontier
in [`ROADMAP.md`](ROADMAP.md), not half-built.
