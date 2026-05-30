# What is this for?

**A hardware oracle for physical reality:** open-opticon proves a specific fact
about what a sensor heard (later: saw) while proving it leaked nothing else.
*"X happened"* becomes verifiable to a third party **without** the raw feed ever
existing outside the chip.

Two moves make it work, and they're the whole idea:

1. **Minimal disclosure** — raw audio is destroyed inside the enclave; only a
   tiny signed predicate (`alarm_tone @ 14:03`, `voice present`, `2 occupants`)
   ever leaves.
2. **Attested restraint** — the published, auditable firmware *has no code path*
   that emits the raw data, and remote attestation proves that exact firmware is
   running. *"Trust me, I'm not recording"* becomes *"**verify** there is no
   recording path."*

It inverts surveillance: not a spying device with a privacy promise bolted on,
but a device that is **structurally incapable** of feeding a panopticon — and
can prove it.

## Audio — shippable now

Each scenario lists the **safety/coordination value**, the **exact predicate
emitted**, and **why non-panopticon matters there**.

| Scenario | Value | Predicate emitted | Why it must be non-panopticon |
|---|---|---|---|
| **Sensitive-space "proof of non-recording"** (therapy office, hotel/Airbnb, locker room, voting booth, workplace) | Resolves "is this thing bugging me?" with proof, not a promise | *nothing* beyond an opt-in safety event (e.g. `smoke_alarm`); attestation shows there's no exfil path | The entire value is the absence of a wiretap — only attestation can *prove* absence |
| **Eldercare / safety events** (falls, alarms, glass-break, a scream) | "Did grandma cry out / did the alarm sound at 2am?" → dispatch, insurance, family peace of mind | `alarm_tone` / `voice present` + timestamp; no audio retained | A nanny-cam/always-on-mic in a bedroom or bathroom is unacceptable; an attested event sensor isn't |
| **Smart-building occupancy** (HVAC, lighting, room utilization) | Run systems on real presence, prove you only count presence | `presence` / `voice_active` count — never *who* or *what* | Tenants/employees can verify the building isn't transcribing them |
| **Noise-ordinance / venue compliance** | "The level breached the limit at 2am" without recording the neighbors | a dB-threshold breach event | Enforcement shouldn't require recording everyone's conversations |
| **Industrial acoustic monitoring** | Machine-fault / leak / safety-alarm detection on the floor | an anomaly/alarm flag | Labor privacy — prove it isn't recording worker conversations |

The flagship use case pairs the first two: **proof-of-non-recording + a verifiable
safety event** — least ML risk, cleanest privacy story.

## Video — the next step (same primitive, richer predicate)

- **Incident attestation** — "an assault/robbery/fire occurred at T," with the
  clip optionally *sealed in-enclave* under a multi-party / warrant key. Verifiable
  evidence with no bingeable live feed.
- **"Did X leave / is the room clear?" without hurting roommates** — the camera
  sees everyone but emits one consented fact (an egress event, or "person
  matching *their own* token crossed the door"). Bystanders never enter any
  output. (Co-parenting handoffs, eldercare, shared living.)
- **Cameras that prove their own limits** — fall / weapon / fire detection in
  schools, hospitals, transit, with attested firmware proving **no
  face-recognition and no recording path**. Crowd-counting that proves "no faces,
  no tracking."
- **Attested-capture authenticity (anti-deepfake)** — "a *real* camera saw this,
  unedited," proven in-enclave (the C2PA gap closed) — and you can prove
  authenticity *without publishing* footage full of bystanders.

Audio is the right MVP precisely because video ML in a TEE is heavy; the audio
detector is light enough to run the real thing today.

## The deep version (why d/acc cares)

Generalized, this is **verifiable claims about reality with minimal disclosure** —
the missing oracle layer for the physical world:

- **Physical-event oracles** for insurance, prediction markets, supply chains,
  "info-finance" — *did the fire happen / shipment arrive / flight land* without a
  trusted human reporter **or** a surveillance feed.
- **Anti-deepfake / authenticity infrastructure** for an AI-saturated information
  environment.
- **Surveillance that distributes power instead of concentrating it** — you
  cannot assemble a panopticon out of devices that each prove they don't feed one.

## Honest limits (read [`THREAT_MODEL.md`](THREAT_MODEL.md))

- **The predicate is a *chosen* leak.** "2 occupants" still reveals something;
  designing the *minimal* useful fact is the real product work.
- **"What counts as an event" is policy, and policy must be open** — that's why
  the detector config is hashed into the signed output (auditable, not a hidden
  knob).
- **Integrity ≠ model accuracy.** Attestation proves the audited code ran, not
  that the detector is never wrong.
- **Not confidentiality** against a physical / side-channel adversary — it's
  integrity + provenance. It *minimizes* what a broken enclave could leak.
- **Sealed-clip-under-warrant** (video) is its own key-custody design, not built.
