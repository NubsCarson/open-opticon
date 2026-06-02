package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

// Anchored RFC 6962 vectors we are certain of: the empty tree hashes the empty
// string, and a one-leaf tree hashes 0x00||leaf.
func TestMerkleAnchors(t *testing.T) {
	var empty MerkleLog
	er := empty.Root()
	if got := hex.EncodeToString(er[:]); got !=
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root = %s", got)
	}
	one := MerkleLog{Leaves: [][]byte{{}}}
	or := one.Root()
	if got := hex.EncodeToString(or[:]); got !=
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Errorf("single-empty-leaf root = %s", got)
	}
}

func buildLog(n int) *MerkleLog {
	l := &MerkleLog{}
	for i := 0; i < n; i++ {
		l.Add([]byte(fmt.Sprintf("entry-%d", i)))
	}
	return l
}

// For every tree size 1..24 and every index, the inclusion proof must verify and
// must fail under any corruption.
func TestInclusionExhaustive(t *testing.T) {
	for n := 1; n <= 24; n++ {
		l := buildLog(n)
		root := l.Root()
		for i := 0; i < n; i++ {
			proof, err := l.InclusionProof(i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(l.Leaves[i], i, n, proof, root) {
				t.Fatalf("n=%d i=%d: valid proof rejected", n, i)
			}
			// wrong entry
			if VerifyInclusion([]byte("forged"), i, n, proof, root) {
				t.Fatalf("n=%d i=%d: forged entry accepted", n, i)
			}
			// corrupted root
			bad := root
			bad[0] ^= 0xff
			if VerifyInclusion(l.Leaves[i], i, n, proof, bad) {
				t.Fatalf("n=%d i=%d: bad root accepted", n, i)
			}
			// corrupted proof element
			if len(proof) > 0 {
				cp := append([][32]byte{}, proof...)
				cp[0][0] ^= 0xff
				if VerifyInclusion(l.Leaves[i], i, n, cp, root) {
					t.Fatalf("n=%d i=%d: tampered proof accepted", n, i)
				}
			}
		}
	}
}

// For every (oldSize, newSize) the consistency proof must verify and fail under
// corruption — this is the append-only / no-rewrite guarantee.
func TestConsistencyExhaustive(t *testing.T) {
	for n := 1; n <= 24; n++ {
		newLog := buildLog(n)
		newRoot := newLog.Root()
		for m := 1; m <= n; m++ {
			oldRoot := (&MerkleLog{Leaves: newLog.Leaves[:m]}).Root()
			proof, err := newLog.ConsistencyProof(m)
			if err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			if !VerifyConsistency(m, n, proof, oldRoot, newRoot) {
				t.Fatalf("n=%d m=%d: valid consistency proof rejected", n, m)
			}
			// a different (wrong) old root must fail
			bad := oldRoot
			bad[0] ^= 0xff
			if VerifyConsistency(m, n, proof, bad, newRoot) {
				t.Fatalf("n=%d m=%d: wrong old root accepted", n, m)
			}
			if len(proof) > 0 {
				cp := append([][32]byte{}, proof...)
				cp[len(cp)-1][0] ^= 0xff
				if VerifyConsistency(m, n, cp, oldRoot, newRoot) {
					t.Fatalf("n=%d m=%d: tampered consistency proof accepted", n, m)
				}
			}
		}
	}
}

func TestCheckpointAndLoggedEndorsement(t *testing.T) {
	logKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lpx := leftPad(logKey.PublicKey.X.Bytes(), 32)
	lpy := leftPad(logKey.PublicKey.Y.Bytes(), 32)

	// Log three device endorsements (pub_x||pub_y).
	l := &MerkleLog{}
	var endorsements [][]byte
	for i := 0; i < 3; i++ {
		dk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		e := append(leftPad(dk.PublicKey.X.Bytes(), 32), leftPad(dk.PublicKey.Y.Bytes(), 32)...)
		endorsements = append(endorsements, e)
		l.Add(e)
	}
	root := l.Root()
	cpBody := CheckpointBody("honest-ear.log/v1", l.Size(), root)
	cpSig, err := SignCheckpoint("honest-ear.log/v1", l.Size(), root, logKey)
	if err != nil {
		t.Fatal(err)
	}

	// A genuine endorsement with its proof under the signed checkpoint passes.
	for i, e := range endorsements {
		proof, _ := l.InclusionProof(i)
		if err := CheckLoggedEndorsement(e, i, proof, cpBody, cpSig, lpx, lpy); err != nil {
			t.Fatalf("i=%d: genuine logged endorsement rejected: %v", i, err)
		}
	}

	// A key that was never logged must fail.
	proof0, _ := l.InclusionProof(0)
	if err := CheckLoggedEndorsement([]byte("never-logged-key................................................."),
		0, proof0, cpBody, cpSig, lpx, lpy); err == nil {
		t.Error("unlogged endorsement accepted")
	}

	// A checkpoint signed by the wrong key must fail.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := CheckLoggedEndorsement(endorsements[0], 0, proof0, cpBody, cpSig,
		leftPad(wrongKey.PublicKey.X.Bytes(), 32), leftPad(wrongKey.PublicKey.Y.Bytes(), 32)); err == nil {
		t.Error("checkpoint verified under wrong log key")
	}

	// A tampered checkpoint body (claims a different size) must fail the signature.
	if err := CheckLoggedEndorsement(endorsements[0], 0, proof0,
		CheckpointBody("honest-ear.log/v1", 99, root), cpSig, lpx, lpy); err == nil {
		t.Error("tampered checkpoint accepted")
	}
}

func TestWitnessCosigning(t *testing.T) {
	l := buildLog(5)
	root := l.Root()
	cpBody := CheckpointBody("honest-ear.log/v1", l.Size(), root)

	// Three independent witnesses, ENROLLED (their keys are pinned by the verifier).
	var cosigs []Cosignature
	var enrolled []Prover
	for _, name := range []string{"witness-a", "witness-b", "witness-c"} {
		wk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sig, err := CosignCheckpoint(cpBody, wk)
		if err != nil {
			t.Fatal(err)
		}
		px := leftPad(wk.PublicKey.X.Bytes(), 32)
		py := leftPad(wk.PublicKey.Y.Bytes(), 32)
		cosigs = append(cosigs, Cosignature{Witness: name, PubX: px, PubY: py, Sig: sig})
		enrolled = append(enrolled, Prover{Name: name, PubX: px, PubY: py})
	}

	if got := VerifyCheckpointWitnesses(cpBody, cosigs, enrolled); len(got) != 3 {
		t.Fatalf("expected 3 valid witnesses, got %v", got)
	}

	// Anti-equivocation: those cosignatures do NOT validate a different checkpoint
	// (the operator can't reuse witness cosigs to back a forked history).
	forked := CheckpointBody("honest-ear.log/v1", l.Size(), [32]byte{0xff})
	if got := VerifyCheckpointWitnesses(forked, cosigs, enrolled); len(got) != 0 {
		t.Errorf("witnesses validated a checkpoint they never signed: %v", got)
	}

	// Duplicate witness names are deduped — one key can't pad the threshold.
	dup := []Cosignature{cosigs[0], cosigs[0], cosigs[0]}
	if got := VerifyCheckpointWitnesses(cpBody, dup, enrolled); len(got) != 1 {
		t.Errorf("duplicate witness counted more than once: %v", got)
	}

	// The core anti-equivocation property: a malicious operator mints a fresh key
	// under a novel name (a valid signature, but NOT enrolled) — it must NOT count.
	rogue, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsig, _ := CosignCheckpoint(cpBody, rogue)
	mint := Cosignature{
		Witness: "witness-x",
		PubX:    leftPad(rogue.PublicKey.X.Bytes(), 32),
		PubY:    leftPad(rogue.PublicKey.Y.Bytes(), 32),
		Sig:     rsig,
	}
	if got := VerifyCheckpointWitnesses(cpBody, []Cosignature{mint}, enrolled); len(got) != 0 {
		t.Errorf("unenrolled minted key counted as a witness: %v", got)
	}
	// An enrolled name paired with a different (rogue) key must also not count.
	imposter := Cosignature{Witness: "witness-a", PubX: mint.PubX, PubY: mint.PubY, Sig: rsig}
	if got := VerifyCheckpointWitnesses(cpBody, []Cosignature{imposter}, enrolled); len(got) != 0 {
		t.Errorf("enrolled name with wrong key counted: %v", got)
	}
}

// A signed endorsement separates the ENDORSER (who vouches for a device key) from
// the log operator (who only appends). The verifier checks both: the endorser's
// signature over the canonical body, AND that the body is logged under a signed
// checkpoint. Reuses SignNote / VerifyCheckpointSig (no new crypto path).
func TestSignedEndorsement(t *testing.T) {
	endorserKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	epx, epy := PubXY(endorserKey)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dpx, dpy := PubXY(deviceKey)

	body, err := EndorsementBody("acme-provisioning", dpx, dpy)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignNote(body, endorserKey)
	if err != nil {
		t.Fatal(err)
	}

	// The endorser genuinely signed this body.
	if !VerifyCheckpointSig(body, sig, epx, epy) {
		t.Fatal("genuine endorsement signature rejected")
	}
	// Parsed fields match (after verifying, the device key is trustworthy).
	gotName, gotX, gotY, err := ParseEndorsement(body)
	if err != nil || gotName != "acme-provisioning" || !bytes.Equal(gotX, dpx) || !bytes.Equal(gotY, dpy) {
		t.Fatalf("parse mismatch: %q %x %x %v", gotName, gotX, gotY, err)
	}
	// A different endorser key must NOT verify (anti-impersonation).
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ox, oy := PubXY(other)
	if VerifyCheckpointSig(body, sig, ox, oy) {
		t.Error("endorsement verified under a wrong endorser key")
	}
	// A tampered body (swap in a different device key) breaks the signature.
	badBody, _ := EndorsementBody("acme-provisioning", ox, oy)
	if VerifyCheckpointSig(badBody, sig, epx, epy) {
		t.Error("tampered endorsement body verified")
	}
	// Malformed bodies are rejected by the parser.
	if _, _, _, err := ParseEndorsement([]byte("not an endorsement")); err == nil {
		t.Error("parser accepted a non-endorsement body")
	}
	if _, err := EndorsementBody("bad\nname", dpx, dpy); err == nil {
		t.Error("a newline in the endorser name was accepted")
	}

	// End-to-end: the signed body is logged, and a verifier confirms BOTH the
	// endorser signature AND inclusion under the log's signed checkpoint.
	logKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lpx, lpy := PubXY(logKey)
	l := &MerkleLog{}
	idx := l.Add(body)
	root := l.Root()
	cpBody := CheckpointBody("honest-ear.log/v1", l.Size(), root)
	cpSig, _ := SignCheckpoint("honest-ear.log/v1", l.Size(), root, logKey)
	proof, _ := l.InclusionProof(idx)
	if !VerifyCheckpointSig(body, sig, epx, epy) {
		t.Fatal("endorser signature failed in the logged case")
	}
	if err := CheckLoggedEndorsement(body, idx, proof, cpBody, cpSig, lpx, lpy); err != nil {
		t.Fatalf("signed endorsement not confirmed as logged: %v", err)
	}
}

// A COSE_Sign1-wrapped endorsement verifies under the endorser key and yields the
// inner device key; a wrong key or tampered message is rejected. Reuses the one
// COSE encode/verify path (SignCOSESign1 / parseCOSESign1).
func TestCOSEEndorsement(t *testing.T) {
	endorser, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	epx, epy := PubXY(endorser)
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dpx, dpy := PubXY(device)

	cose, err := SignCOSEEndorsement("acme-provisioning", dpx, dpy, endorser)
	if err != nil {
		t.Fatal(err)
	}
	name, gx, gy, err := VerifyCOSEEndorsement(cose, epx, epy)
	if err != nil || name != "acme-provisioning" || !bytes.Equal(gx, dpx) || !bytes.Equal(gy, dpy) {
		t.Fatalf("verify mismatch: %q %x %x %v", name, gx, gy, err)
	}
	// Wrong endorser key must fail.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ox, oy := PubXY(other)
	if _, _, _, err := VerifyCOSEEndorsement(cose, ox, oy); err == nil {
		t.Error("COSE endorsement verified under a wrong endorser key")
	}
	// A tampered byte in the COSE message must fail.
	bad := append([]byte(nil), cose...)
	bad[len(bad)-1] ^= 0xff // flip a signature byte
	if _, _, _, err := VerifyCOSEEndorsement(bad, epx, epy); err == nil {
		t.Error("tampered COSE endorsement verified")
	}
}
