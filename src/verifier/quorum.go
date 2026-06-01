// Multi-prover quorum verification.
//
// A single TEE is one trust assumption: if that vendor's enclave is broken, a
// forged PASS is possible. The standard answer (the "2-of-3 multi-prover"
// pattern) is to require agreement from several INDEPENDENT roots that fail
// differently — e.g. the OP-TEE device, a second-vendor TEE, and a measured-boot
// TPM quote. A verdict is trusted only if at least k of the n enrolled roots
// independently produce a valid, fresh, agreeing bound output.
//
// This reuses VerifyBundle per prover (one ECDSA/freshness/anti-replay path) and
// adds only the quorum + agreement logic on top.
package verifier

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
)

// Prover is one enrolled, independent prover identified by its P-256 public key.
type Prover struct {
	Name       string
	PubX, PubY []byte
}

// QuorumOptions configures k-of-n verification.
type QuorumOptions struct {
	ExpectedNonce []byte
	Roots         []Prover
	Threshold     int // k: how many distinct roots must independently verify
	LastCounter   uint64
}

// QuorumResult is the outcome of quorum verification.
type QuorumResult struct {
	OK     bool
	Reason string
	// Event is the only field the quorum guarantees the provers agree on; other
	// predicate fields (counter, presence, frames) are legitimately per-device.
	Event       string
	PassedRoots []string
}

// matchProver returns the enrolled root whose key signed this bundle, or nil.
func matchProver(b Bundle, roots []Prover) *Prover {
	px, err := hex.DecodeString(b.PubX)
	if err != nil {
		return nil
	}
	py, err := hex.DecodeString(b.PubY)
	if err != nil {
		return nil
	}
	for i := range roots {
		if subtle.ConstantTimeCompare(px, roots[i].PubX) == 1 &&
			subtle.ConstantTimeCompare(py, roots[i].PubY) == 1 {
			return &roots[i]
		}
	}
	return nil
}

// VerifyQuorum requires at least Threshold distinct enrolled roots to each
// produce a bundle that independently passes VerifyBundle (pinned to that root)
// for the same fresh nonce, and to agree on the event class.
func VerifyQuorum(bundles []Bundle, qopt QuorumOptions) QuorumResult {
	if qopt.Threshold <= 0 || qopt.Threshold > len(qopt.Roots) {
		return QuorumResult{Reason: "threshold must be between 1 and the number of enrolled roots"}
	}
	passed := map[string]*Predicate{}
	for _, b := range bundles {
		root := matchProver(b, qopt.Roots)
		if root == nil {
			continue // not from an enrolled root — ignored
		}
		if _, done := passed[root.Name]; done {
			continue // one vote per root
		}
		res := VerifyBundle(b, Options{
			ExpectedNonce: qopt.ExpectedNonce,
			PinPubX:       root.PubX,
			PinPubY:       root.PubY,
			LastCounter:   qopt.LastCounter,
		})
		if res.OK {
			passed[root.Name] = res.Predicate
		}
	}
	if len(passed) < qopt.Threshold {
		return QuorumResult{Reason: fmt.Sprintf(
			"only %d of the required %d independent provers verified",
			len(passed), qopt.Threshold)}
	}
	names := make([]string, 0, len(passed))
	for name := range passed {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order, independent of map iteration
	event := passed[names[0]].EventName()
	for _, name := range names {
		if passed[name].EventName() != event {
			return QuorumResult{Reason: "independent provers disagree on the event class"}
		}
	}
	return QuorumResult{OK: true, Reason: "quorum reached", Event: event, PassedRoots: names}
}

// CoAttestation is the outcome of multi-modal co-attestation (see below).
type CoAttestation struct {
	OK     bool
	Reason string
	// Modalities lists each accepted modality's event label, in deterministic
	// order. Unlike a quorum, these are NOT required to agree — different sensors
	// report different verdicts ("alarm_tone", "occupied"); the shared fact is the
	// nonce they are all bound to.
	Modalities []string
}

// VerifyCoAttestation verifies that several DIFFERENT-modality bound outputs
// (e.g. an audio verdict and a vision verdict) are each a valid, fresh signature
// over the SAME challenge nonce. This is the cross-modal sibling of VerifyQuorum,
// but with deliberately different semantics:
//
//   - a quorum requires k INDEPENDENT roots to AGREE on one event (redundancy);
//   - co-attestation requires k modalities each bound to the SAME nonce, and does
//     NOT require them to agree — an alarm tone and an occupied room are different
//     facts about the same moment.
//
// To stop one modality being replayed as two, the accepted bundles must have
// DISTINCT input_hash values (each attests a distinct sensor input). Bundles are
// pinned to the device key when PinPubX/Y are set (one multi-sensor device).
//
// HONEST SCOPE: this proves the signing key produced a fresh, signed verdict for
// each modality bound to one challenge. It does NOT prove the modalities observed
// the same physical scene, nor (on Tier-1, shared test key) that they came from a
// specific physical device — only that they share the challenge and the key.
func VerifyCoAttestation(bundles []Bundle, opt Options, threshold int) CoAttestation {
	if threshold <= 0 {
		return CoAttestation{Reason: "threshold must be >= 1"}
	}
	seenInput := map[string]bool{}
	var modalities []string
	for _, b := range bundles {
		res := VerifyBundle(b, opt)
		if !res.OK || res.Predicate == nil {
			continue
		}
		ih := hex.EncodeToString(res.Predicate.InputHash)
		if seenInput[ih] {
			continue // same sensor input — not an independent modality
		}
		seenInput[ih] = true
		modalities = append(modalities, res.Predicate.EventName())
	}
	if len(modalities) < threshold {
		return CoAttestation{Reason: fmt.Sprintf(
			"only %d of the required %d distinct modalities bound to this nonce verified",
			len(modalities), threshold)}
	}
	sort.Strings(modalities)
	return CoAttestation{OK: true, Reason: "co-attestation reached", Modalities: modalities}
}
