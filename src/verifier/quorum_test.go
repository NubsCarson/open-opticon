package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

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
