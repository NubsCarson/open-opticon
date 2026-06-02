package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// coseBundleJSON builds a COSE_Sign1 bundle (signed over the Sig_structure) as the
// on-wire JSON the quorum/co-attest JSON paths consume.
func coseBundleJSON(t *testing.T, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	msg, err := SignCOSESign1(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(COSEBundle{
		Schema: "honest-ear/cose-sign1/v1", COSE: hex.EncodeToString(msg),
		PubX: hex.EncodeToString(leftPad(key.PublicKey.X.Bytes(), 32)),
		PubY: hex.EncodeToString(leftPad(key.PublicKey.Y.Bytes(), 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A quorum can mix envelopes: one prover submits a raw bundle, another a COSE_Sign1
// bundle, and the JSON path dispatches each to its correct verifier (COSE signs the
// Sig_structure, not the raw payload) — so a COSE-emitting fleet IS quorum-verifiable.
func TestQuorumJSONAcceptsCOSE(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	rb, kb := newProver(t, "tee-second-vendor")
	roots := []Prover{ra, rb}
	rawA, err := json.Marshal(signWith(t, golden, ka))
	if err != nil {
		t.Fatal(err)
	}
	coseB := coseBundleJSON(t, golden, kb)
	res := VerifyQuorumJSON([][]byte{rawA, coseB}, QuorumOptions{
		ExpectedNonce: mustHex("aabb"), Roots: roots, Threshold: 2, LastCounter: 6,
	})
	if !res.OK {
		t.Fatalf("mixed raw+COSE quorum failed: %s", res.Reason)
	}
	if res.Event != "alarm_tone" || len(res.PassedRoots) != 2 {
		t.Errorf("res = %+v", res)
	}
}

// Co-attestation likewise accepts a COSE modality alongside a raw one.
func TestCoAttestationJSONAcceptsCOSE(t *testing.T) {
	_, k := newProver(t, "device")
	opt := Options{ExpectedNonce: mustHex("aabb"), LastCounter: 6}
	audioRaw, err := json.Marshal(signWith(t, golden, k))
	if err != nil {
		t.Fatal(err)
	}
	visionCOSE := coseBundleJSON(t, goldenVision, k) // distinct input_hash
	res := VerifyCoAttestationJSON([][]byte{audioRaw, visionCOSE}, opt, 2)
	if !res.OK || len(res.Modalities) != 2 {
		t.Fatalf("raw+COSE co-attestation failed: ok=%v mods=%v reason=%s", res.OK, res.Modalities, res.Reason)
	}
}

// goldenNone is the golden payload with the event class changed to "none" (0)
// instead of "alarm_tone" (2): byte pair 0202 -> 0200. Used to test that
// provers reporting different events do not form a quorum.
var goldenNone = mustHex(
	"ab" + "0001" + "0142aabb" + "0200" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32 +
		"095820" + inp32 + "0a5820" + prev32)

func newProver(t *testing.T, name string) (Prover, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Prover{Name: name,
		PubX: leftPad(k.PublicKey.X.Bytes(), 32),
		PubY: leftPad(k.PublicKey.Y.Bytes(), 32)}, k
}

func TestQuorumReached(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	rb, kb := newProver(t, "tee-second-vendor")
	rc, _ := newProver(t, "tpm-measured-boot")
	roots := []Prover{ra, rb, rc}

	// Two independent provers both produce a fresh, valid, agreeing bundle.
	bundles := []Bundle{signWith(t, golden, ka), signWith(t, golden, kb)}
	res := VerifyQuorum(bundles, QuorumOptions{
		ExpectedNonce: mustHex("aabb"), Roots: roots, Threshold: 2, LastCounter: 6,
	})
	if !res.OK {
		t.Fatalf("expected quorum, got: %s", res.Reason)
	}
	if res.Event != "alarm_tone" {
		t.Errorf("agreed event = %q, want alarm_tone", res.Event)
	}
	if len(res.PassedRoots) != 2 {
		t.Errorf("passed roots = %v, want 2", res.PassedRoots)
	}
}

func TestQuorumNotEnoughProvers(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	rb, _ := newProver(t, "tee-second-vendor")
	roots := []Prover{ra, rb}
	res := VerifyQuorum([]Bundle{signWith(t, golden, ka)}, QuorumOptions{
		ExpectedNonce: mustHex("aabb"), Roots: roots, Threshold: 2, LastCounter: 6,
	})
	if res.OK {
		t.Error("single prover formed a 2-of-2 quorum; must fail")
	}
}

func TestQuorumIgnoresUnenrolledRoot(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	rb, _ := newProver(t, "tee-second-vendor")
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	roots := []Prover{ra, rb}
	// One enrolled pass + one bundle from a key nobody enrolled -> only 1 counts.
	res := VerifyQuorum(
		[]Bundle{signWith(t, golden, ka), signWith(t, golden, stranger)},
		QuorumOptions{ExpectedNonce: mustHex("aabb"), Roots: roots, Threshold: 2, LastCounter: 6})
	if res.OK {
		t.Error("an unenrolled key was counted toward the quorum; must fail")
	}
}

func TestQuorumRejectsDisagreement(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	rb, kb := newProver(t, "tee-second-vendor")
	roots := []Prover{ra, rb}
	// Prover A says alarm_tone, prover B says none -> no agreement.
	res := VerifyQuorum(
		[]Bundle{signWith(t, golden, ka), signWith(t, goldenNone, kb)},
		QuorumOptions{ExpectedNonce: mustHex("aabb"), Roots: roots, Threshold: 2, LastCounter: 6})
	if res.OK {
		t.Error("disagreeing provers formed a quorum; must fail")
	}
}

func TestQuorumRejectsStaleNonce(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	rb, kb := newProver(t, "tee-second-vendor")
	roots := []Prover{ra, rb}
	res := VerifyQuorum([]Bundle{signWith(t, golden, ka), signWith(t, golden, kb)},
		QuorumOptions{ExpectedNonce: mustHex("ccdd"), Roots: roots, Threshold: 2, LastCounter: 6})
	if res.OK {
		t.Error("stale nonce formed a quorum; must fail")
	}
}

func TestQuorumRejectsOneVotePerRoot(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	rb, _ := newProver(t, "tee-second-vendor")
	roots := []Prover{ra, rb}
	// Same root submitting two bundles must not count as two.
	res := VerifyQuorum([]Bundle{signWith(t, golden, ka), signWith(t, golden, ka)},
		QuorumOptions{ExpectedNonce: mustHex("aabb"), Roots: roots, Threshold: 2, LastCounter: 6})
	if res.OK {
		t.Error("one root voted twice and formed a quorum; must fail")
	}
}

func TestQuorumBadThreshold(t *testing.T) {
	ra, ka := newProver(t, "tee-optee")
	for _, th := range []int{0, 2} { // 0 invalid; 2 > len(roots)=1
		res := VerifyQuorum([]Bundle{signWith(t, golden, ka)},
			QuorumOptions{ExpectedNonce: mustHex("aabb"), Roots: []Prover{ra}, Threshold: th})
		if res.OK {
			t.Errorf("threshold %d accepted; must fail", th)
		}
	}
}

// goldenVision mimics a SECOND modality bound to the SAME nonce (aabb) but with a
// distinct input_hash (0x44*32 instead of inp32's 0x22*32) and event "none" — a
// vision verdict alongside the audio one. Same key (one multi-sensor device).
var inpVision = "4444444444444444444444444444444444444444444444444444444444444444"
var goldenVision = mustHex(
	"ab" + "0001" + "0142aabb" + "0200" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32 +
		"095820" + inpVision + "0a5820" + prev32)

func TestCoAttestationDistinctModalities(t *testing.T) {
	_, k := newProver(t, "device")
	opt := Options{ExpectedNonce: mustHex("aabb"), LastCounter: 6}
	// Audio (golden, input_hash inp32) + vision (goldenVision, input_hash 0x44*32),
	// both for nonce aabb, signed by the same device key.
	audio := signWith(t, golden, k)
	vision := signWith(t, goldenVision, k)
	res := VerifyCoAttestation([]Bundle{audio, vision}, opt, 2)
	if !res.OK {
		t.Fatalf("co-attestation should reach 2 modalities: %s", res.Reason)
	}
	if len(res.Modalities) != 2 {
		t.Errorf("got %d modalities, want 2: %v", len(res.Modalities), res.Modalities)
	}
}

func TestCoAttestationRejectsReplayedModality(t *testing.T) {
	_, k := newProver(t, "device")
	opt := Options{ExpectedNonce: mustHex("aabb"), LastCounter: 6}
	// The SAME bundle twice is one modality (identical input_hash), not two.
	b := signWith(t, golden, k)
	res := VerifyCoAttestation([]Bundle{b, b}, opt, 2)
	if res.OK {
		t.Error("one modality replayed as two should NOT reach a 2-modality co-attestation")
	}
}

func TestCoAttestationRejectsWrongNonce(t *testing.T) {
	_, k := newProver(t, "device")
	// A vision bundle bound to aabb but the verifier expects a different nonce:
	// neither modality is fresh for the challenge, so co-attestation fails.
	opt := Options{ExpectedNonce: mustHex("ccdd"), LastCounter: 6}
	res := VerifyCoAttestation([]Bundle{signWith(t, golden, k), signWith(t, goldenVision, k)}, opt, 2)
	if res.OK {
		t.Error("bundles bound to a different nonce than expected should not co-attest")
	}
}
