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

// Root is one enrolled, independent prover identified by its P-256 public key.
type Root struct {
	Name       string
	PubX, PubY []byte
}

// QuorumOptions configures k-of-n verification.
type QuorumOptions struct {
	ExpectedNonce []byte
	Roots         []Root
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

// matchRoot returns the enrolled root whose key signed this bundle, or nil.
func matchRoot(b Bundle, roots []Root) *Root {
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
		root := matchRoot(b, qopt.Roots)
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
