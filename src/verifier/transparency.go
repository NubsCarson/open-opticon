// Transparency log for Honest Ear endorsements and reference values.
//
// Why: pinning a device key (Options.PinPubX/Y) or trusting a firmware
// measurement only helps if everyone sees the SAME set of endorsements. A
// malicious issuer could hand one verifier a key it shows no one else
// ("equivocation"). The fix is the Certificate-Transparency model: every
// endorsement/reference-value is appended to a public, append-only Merkle log;
// the log periodically signs a checkpoint (size + root); a verifier only trusts
// an endorsement if it comes with an inclusion proof against a signed
// checkpoint, and auditors gossip checkpoints + consistency proofs to ensure the
// log never forks or rewrites history.
//
// This is RFC 6962 / RFC 9162 tree hashing (leaf = SHA-256(0x00||entry), node =
// SHA-256(0x01||left||right)) with a C2SP-style signed-note checkpoint, but the
// checkpoint is signed with the same P-256 primitive as the rest of the project
// (reusing verifySig) rather than pulling in an Ed25519 note dependency. Stdlib
// only, like the rest of this package.
package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MerkleLog is an append-only log of opaque entries (raw bytes). Callers decide
// the entry encoding; for a device endorsement it is pub_x||pub_y (64 bytes).
type MerkleLog struct {
	Leaves [][]byte
}

// Add appends an entry and returns its zero-based index.
func (l *MerkleLog) Add(entry []byte) int {
	l.Leaves = append(l.Leaves, append([]byte(nil), entry...))
	return len(l.Leaves) - 1
}

func hashLeaf(b []byte) [32]byte { return sha256.Sum256(append([]byte{0x00}, b...)) }

func hashNode(l, r [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = 0x01
	copy(buf[1:33], l[:])
	copy(buf[33:], r[:])
	return sha256.Sum256(buf[:])
}

// largestPow2Below returns the largest power of two strictly less than n (n>1).
func largestPow2Below(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// mth is the RFC 6962 Merkle Tree Hash over leaves[lo:hi].
func mth(leaves [][]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return hashLeaf(leaves[0])
	}
	k := largestPow2Below(len(leaves))
	return hashNode(mth(leaves[:k]), mth(leaves[k:]))
}

// Root is the current Merkle Tree Hash.
func (l *MerkleLog) Root() [32]byte { return mth(l.Leaves) }

// Size is the number of entries.
func (l *MerkleLog) Size() int { return len(l.Leaves) }

// path is the RFC 6962 inclusion audit path for leaf m within leaves.
func path(m int, leaves [][]byte) [][32]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := largestPow2Below(len(leaves))
	if m < k {
		return append(path(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(path(m-k, leaves[k:]), mth(leaves[:k]))
}

// InclusionProof returns the audit path proving entry index is in the tree.
func (l *MerkleLog) InclusionProof(index int) ([][32]byte, error) {
	if index < 0 || index >= len(l.Leaves) {
		return nil, errors.New("index out of range")
	}
	return path(index, l.Leaves), nil
}

// subproof is the RFC 6962 consistency subproof.
func subproof(m int, leaves [][]byte, b bool) [][32]byte {
	if m == len(leaves) {
		if b {
			return nil
		}
		return [][32]byte{mth(leaves)}
	}
	k := largestPow2Below(len(leaves))
	if m <= k {
		return append(subproof(m, leaves[:k], b), mth(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), mth(leaves[:k]))
}

// ConsistencyProof proves the current tree is an append-only extension of the
// earlier tree of size oldSize.
func (l *MerkleLog) ConsistencyProof(oldSize int) ([][32]byte, error) {
	if oldSize < 0 || oldSize > len(l.Leaves) {
		return nil, errors.New("oldSize out of range")
	}
	if oldSize == 0 || oldSize == len(l.Leaves) {
		return nil, nil
	}
	return subproof(oldSize, l.Leaves, true), nil
}

// VerifyInclusion recomputes the root from an entry + audit path and reports
// whether it matches root (RFC 9162 §2.1.3.2).
func VerifyInclusion(entry []byte, index, size int, proof [][32]byte, root [32]byte) bool {
	if index < 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := hashLeaf(entry)
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = hashNode(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = hashNode(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// VerifyConsistency checks that newRoot (size newSize) is an append-only
// extension of oldRoot (size oldSize) given a consistency proof (RFC 9162
// §2.1.4.2).
func VerifyConsistency(oldSize, newSize int, proof [][32]byte, oldRoot, newRoot [32]byte) bool {
	if oldSize < 0 || newSize <= 0 || oldSize > newSize {
		return false
	}
	if oldSize == newSize {
		return len(proof) == 0 && oldRoot == newRoot
	}
	if oldSize == 0 {
		return len(proof) == 0
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	var fr, sr [32]byte
	idx := 0
	if fn == 0 {
		fr, sr = oldRoot, oldRoot
	} else {
		if len(proof) == 0 {
			return false
		}
		fr, sr = proof[0], proof[0]
		idx = 1
	}
	for ; idx < len(proof); idx++ {
		if sn == 0 {
			return false
		}
		c := proof[idx]
		if fn&1 == 1 || fn == sn {
			fr = hashNode(c, fr)
			sr = hashNode(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = hashNode(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && fr == oldRoot && sr == newRoot
}

// ---- signed checkpoint (C2SP-style note, P-256 signed) ----

// CheckpointBody is the signed text of a checkpoint: origin, size, base64(root),
// each on its own line. This is the message the log signs and auditors gossip.
func CheckpointBody(origin string, size int, root [32]byte) []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%s\n",
		origin, size, base64.StdEncoding.EncodeToString(root[:])))
}

// signNote signs an exact note body with a P-256 key, returning the 64-byte
// r||s signature used everywhere else in this project. One signing path shared
// by the log operator (SignCheckpoint) and witnesses (CosignCheckpoint).
func signNote(body []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	h := sha256.Sum256(body)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// SignCheckpoint signs a checkpoint body with the log's P-256 key, returning the
// 64-byte r||s signature used everywhere else in this project.
func SignCheckpoint(origin string, size int, root [32]byte, key *ecdsa.PrivateKey) ([]byte, error) {
	return signNote(CheckpointBody(origin, size, root), key)
}

// SignNote signs an arbitrary canonical note body with a P-256 key (64-byte
// r||s) — the one signing primitive, exported for other signed-note producers
// (e.g. restraint receipts). Verify with VerifyCheckpointSig.
func SignNote(body []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	return signNote(body, key)
}

// VerifyCheckpointSig reports whether sig (64-byte r||s) is a valid signature by
// the key (pubX,pubY) over the checkpoint body — i.e. the log operator (or any
// note signer) genuinely signed these exact bytes. Reuses the single ECDSA path.
// A witness calls this to pin the log's key before trusting a checkpoint.
func VerifyCheckpointSig(cpBody, sig, pubX, pubY []byte) bool {
	return verifySig(cpBody, sig, pubX, pubY) == nil
}

// ParseCheckpoint extracts (origin, size, root) from a checkpoint body.
func ParseCheckpoint(body []byte) (origin string, size int, root [32]byte, err error) {
	lines := bytes.Split(bytes.TrimRight(body, "\n"), []byte("\n"))
	if len(lines) != 3 {
		return "", 0, root, errors.New("checkpoint must have 3 lines")
	}
	origin = string(lines[0])
	if size, err = strconv.Atoi(string(lines[1])); err != nil || size < 0 {
		return "", 0, root, errors.New("bad checkpoint size")
	}
	raw, err := base64.StdEncoding.DecodeString(string(lines[2]))
	if err != nil || len(raw) != 32 {
		return "", 0, root, errors.New("bad checkpoint root")
	}
	copy(root[:], raw)
	return origin, size, root, nil
}

// endorsementSchema tags the canonical endorser-signed body.
const endorsementSchema = "honest-ear/endorsement/v1"

// EndorsementBody is the canonical text an ENDORSER signs to vouch for a device
// key: a schema line, the endorser's name, and the endorsed device's P-256 X and
// Y (hex), each on its own line. Signing this (with SignNote) and logging it as a
// leaf separates two roles the bare-pubkey entry conflated — WHO vouched for the
// key (the endorser's signature) vs. that it was merely appended (the log
// checkpoint). The verifier checks both: VerifyCheckpointSig over this body under
// the endorser key, and CheckLoggedEndorsement for inclusion. The endorser name
// must not contain a newline (it is one line of the body).
func EndorsementBody(endorser string, devicePubX, devicePubY []byte) ([]byte, error) {
	if strings.Contains(endorser, "\n") {
		return nil, errors.New("endorser name must not contain a newline")
	}
	if len(devicePubX) != 32 || len(devicePubY) != 32 {
		return nil, errors.New("device pub_x and pub_y must be 32 bytes each")
	}
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n", endorsementSchema, endorser,
		hex.EncodeToString(devicePubX), hex.EncodeToString(devicePubY))), nil
}

// ParseEndorsement extracts (endorser, devicePubX, devicePubY) from a body after
// its endorser signature has been verified (verify first, then trust the fields).
func ParseEndorsement(body []byte) (endorser string, devicePubX, devicePubY []byte, err error) {
	lines := bytes.Split(bytes.TrimRight(body, "\n"), []byte("\n"))
	if len(lines) != 4 || string(lines[0]) != endorsementSchema {
		return "", nil, nil, errors.New("not a v1 endorsement body")
	}
	x, err := hex.DecodeString(string(lines[2]))
	if err != nil || len(x) != 32 {
		return "", nil, nil, errors.New("bad device pub_x")
	}
	y, err := hex.DecodeString(string(lines[3]))
	if err != nil || len(y) != 32 {
		return "", nil, nil, errors.New("bad device pub_y")
	}
	return string(lines[1]), x, y, nil
}

// SignCOSEEndorsement wraps an EndorsementBody in a tagged COSE_Sign1 (ES256)
// signed by the endorser, so standard RATS/COSE tooling can consume it. The
// payload is the exact EndorsementBody bytes; reuses the one COSE encoder.
func SignCOSEEndorsement(endorser string, devicePubX, devicePubY []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	body, err := EndorsementBody(endorser, devicePubX, devicePubY)
	if err != nil {
		return nil, err
	}
	return SignCOSESign1(body, key)
}

// VerifyCOSEEndorsement verifies a COSE_Sign1-wrapped endorsement under the
// pinned endorser key and returns the inner fields. Reuses the same COSE parse +
// Sig_structure + ECDSA path as VerifyCOSEBundle (parseCOSESign1 already requires
// ES256); verify first, then trust the returned device key.
func VerifyCOSEEndorsement(cose, endorserPubX, endorserPubY []byte) (endorser string, devicePubX, devicePubY []byte, err error) {
	protBstr, payload, payloadBstr, sig, perr := parseCOSESign1(cose)
	if perr != nil {
		return "", nil, nil, fmt.Errorf("cose: %w", perr)
	}
	if verr := verifySig(coseSigStruct(protBstr, payloadBstr), sig, endorserPubX, endorserPubY); verr != nil {
		return "", nil, nil, fmt.Errorf("endorser signature: %w", verr)
	}
	return ParseEndorsement(payload)
}

// CheckLoggedEndorsement is the verifier-side gate: it confirms an endorsement
// (e.g. pub_x||pub_y of a trusted device key, or an EndorsementBody) is included
// in a checkpoint that the log operator actually signed. Reuses verifySig for the
// checkpoint signature so there is one ECDSA verification path in the package.
func CheckLoggedEndorsement(entry []byte, index int, proof [][32]byte,
	cpBody, cpSig, logPubX, logPubY []byte) error {
	if err := verifySig(cpBody, cpSig, logPubX, logPubY); err != nil {
		return fmt.Errorf("checkpoint signature: %w", err)
	}
	_, size, root, err := ParseCheckpoint(cpBody)
	if err != nil {
		return err
	}
	if !VerifyInclusion(entry, index, size, proof, root) {
		return errors.New("endorsement not included under the signed checkpoint root")
	}
	return nil
}

// ---- witness cosigning (anti-equivocation, C2SP/Sigstore model) ----

// A Cosignature is an independent witness's signature over a checkpoint body.
// Witnesses gossip and cosign only checkpoints they have verified are consistent
// extensions of what they last saw (VerifyConsistency), so a single log operator
// cannot present a forked or rewound history without colluding with the
// witnesses — the off-chain analogue of the on-chain CheckpointAnchor.
type Cosignature struct {
	Witness string // enrolled witness name
	PubX    []byte
	PubY    []byte
	Sig     []byte // 64-byte r||s over the checkpoint body
}

// CosignCheckpoint signs an exact checkpoint body with a witness key (the witness
// signs the bytes it verified, not a rebuilt body). Same ECDSA primitive as the
// log operator's signature.
func CosignCheckpoint(cpBody []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	return signNote(cpBody, key)
}

// VerifyEquivocation reports whether two cosigned checkpoints are transferable
// evidence that a log equivocated: SAME origin and SAME size but DIFFERENT roots,
// each validly cosigned under the witness key the caller PINNED (aX/aY for the
// first, bX/bY for the second). Because each half is bound to an independently
// pinned witness, a true result convicts the log of showing conflicting roots
// without the verifier having to trust whoever produced the proof — it only trusts
// the two witness keys it pinned. (Pin two DISTINCT witnesses for "the log
// equivocated"; the same key twice still proves one witness cosigned conflicting
// roots, which is itself misbehavior.)
//
// Scope: this is the same-size split-view case. The inconsistent-extension case (a
// peer ahead whose tree does not append-only-extend ours) is also equivocation but
// its evidence is a FAILING consistency proof, not a two-checkpoint pair, so it is
// intentionally out of scope here and reported false with a reason.
func VerifyEquivocation(bodyA, cosigA, aX, aY, bodyB, cosigB, bX, bY []byte) (bool, string) {
	if !VerifyCheckpointSig(bodyA, cosigA, aX, aY) {
		return false, "checkpoint A cosignature does not verify under the pinned A key"
	}
	if !VerifyCheckpointSig(bodyB, cosigB, bX, bY) {
		return false, "checkpoint B cosignature does not verify under the pinned B key"
	}
	oA, sA, rA, err := ParseCheckpoint(bodyA)
	if err != nil {
		return false, "parse checkpoint A: " + err.Error()
	}
	oB, sB, rB, err := ParseCheckpoint(bodyB)
	if err != nil {
		return false, "parse checkpoint B: " + err.Error()
	}
	if oA != oB {
		return false, fmt.Sprintf("different origins (%q vs %q) — not the same log", oA, oB)
	}
	if sA != sB {
		return false, fmt.Sprintf("different sizes (%d vs %d) — not a same-size split view", sA, sB)
	}
	if rA == rB {
		return false, "identical roots — the witnesses agree, no equivocation"
	}
	return true, fmt.Sprintf("log %q equivocated at size %d: root %x… vs %x…", oA, sA, rA[:4], rB[:4])
}

// VerifyCheckpointWitnesses returns the names of distinct ENROLLED witnesses
// whose cosignature over cpBody is valid (deduped by name). A cosignature only
// counts if its (name, public key) matches an enrolled witness — otherwise a
// malicious operator could mint fresh names/keys to clear the threshold, which
// would defeat the whole point. The verifier requires at least a threshold of
// these in addition to the operator's signature, so no single operator can
// equivocate. Reuses verifySig (one ECDSA path) and the Prover enrolment shape.
func VerifyCheckpointWitnesses(cpBody []byte, cosigs []Cosignature, enrolled []Prover) []string {
	seen := map[string]bool{}
	var ok []string
	for _, c := range cosigs {
		name := matchWitness(c, enrolled)
		if name == "" || seen[name] {
			continue
		}
		if verifySig(cpBody, c.Sig, c.PubX, c.PubY) == nil {
			seen[name] = true
			ok = append(ok, name)
		}
	}
	return ok
}

// matchWitness returns the enrolled witness name iff the cosignature's name AND
// pinned public key both match an enrolled witness (constant-time key compare,
// mirroring matchProver) — so an unenrolled key, or an enrolled name paired with
// a different key, does not count.
func matchWitness(c Cosignature, enrolled []Prover) string {
	for _, w := range enrolled {
		if w.Name == c.Witness &&
			subtle.ConstantTimeCompare(c.PubX, w.PubX) == 1 &&
			subtle.ConstantTimeCompare(c.PubY, w.PubY) == 1 {
			return w.Name
		}
	}
	return ""
}
