package verifier

// Restraint receipts — a portable "proof of restraint" for ANY local-first
// sensor/processing app (e.g. VoxTerm transcription), in the same spirit as the
// bound-output envelope but for apps whose output is text/metadata rather than a
// detector verdict. Each receipt commits, per processing batch:
//
//   - the SHA-256 of the input window that was processed and DISCARDED (proves
//     which input existed without storing it),
//   - the SHA-256 of the only thing emitted (e.g. the transcript text),
//   - an explicit "input retained?" flag,
//   - a prev-digest hash-chain (so a silently dropped batch is a detectable gap).
//
// A receipt is signed with a P-256 key (the one signing primitive; on Arm an
// OP-TEE/CAAM key, on Apple a Secure Enclave key, on PC a TPM key — the verifier
// is root-agnostic) and verified with VerifyCheckpointSig. Receipts are designed
// to be transparency-log leaves, so a session's receipt stream is append-only,
// witness-cosignable, and on-chain-anchorable with the EXISTING he-log machinery.
//
// HONEST SCOPE: a receipt proves a tamper-evident, gap-free, signed binding of
// input->output per batch under a hardware-backed key — an accountability layer
// strictly stronger than a bare promise. It does NOT by itself prove which code
// ran or that no covert exfil path exists; that needs firmware measurement (a
// TEE) and/or reproducible builds + open source. Stated plainly so it isn't
// mistaken for a hardware confidentiality proof.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// ReceiptOrigin is the canonical origin/version line for restraint receipts.
const ReceiptOrigin = "honest-ear/restraint-receipt/v1"

// Receipt is the decoded content of a restraint receipt.
type Receipt struct {
	Origin     string
	Session    string
	Batch      uint64
	InputHash  []byte // SHA-256 of the processed-then-discarded input window
	OutputHash []byte // SHA-256 of the only emitted artifact (e.g. transcript text)
	Retained   bool   // did the app retain the raw input? (the honest claim is false)
	PrevDigest []byte // SHA-256 of the previous receipt body (chain; 32 zero bytes at genesis)
}

// ReceiptBody is the exact, canonical bytes a receipt signs and that become a
// transparency-log leaf — newline-delimited, like CheckpointBody, so it needs no
// CBOR/COSE library and is trivially reproducible:
//
//	<origin>\n<session>\n<batch>\n<input_hex>\n<output_hex>\n<retained 0|1>\n<prev_hex>\n
func ReceiptBody(r Receipt) []byte {
	retained := "0"
	if r.Retained {
		retained = "1"
	}
	return []byte(fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n%s\n%s\n",
		r.Origin, r.Session, r.Batch,
		hex.EncodeToString(r.InputHash), hex.EncodeToString(r.OutputHash),
		retained, hex.EncodeToString(r.PrevDigest)))
}

// ReceiptDigest is SHA-256 of the receipt body — its transparency-log leaf and
// the prev_digest the NEXT receipt in the session must carry.
func ReceiptDigest(body []byte) []byte {
	h := sha256.Sum256(body)
	return h[:]
}

// ParseReceipt decodes a receipt body back into its fields (the inverse of
// ReceiptBody), validating shape and hash lengths.
func ParseReceipt(body []byte) (*Receipt, error) {
	// 7 fields + trailing newline -> SplitN on '\n' yields 8 parts (last empty).
	s := string(body)
	parts := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	if len(parts) != 8 || parts[7] != "" {
		return nil, errors.New("receipt must have 7 newline-terminated lines")
	}
	r := &Receipt{Origin: parts[0], Session: parts[1]}
	if r.Origin != ReceiptOrigin {
		return nil, fmt.Errorf("unexpected receipt origin %q", r.Origin)
	}
	batch, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return nil, errors.New("bad batch number")
	}
	r.Batch = batch
	if r.InputHash, err = hexLen(parts[3], 32); err != nil {
		return nil, fmt.Errorf("input_hash: %w", err)
	}
	if r.OutputHash, err = hexLen(parts[4], 32); err != nil {
		return nil, fmt.Errorf("output_hash: %w", err)
	}
	switch parts[5] {
	case "0":
		r.Retained = false
	case "1":
		r.Retained = true
	default:
		return nil, errors.New("retained must be 0 or 1")
	}
	if r.PrevDigest, err = hexLen(parts[6], 32); err != nil {
		return nil, fmt.Errorf("prev_digest: %w", err)
	}
	return r, nil
}

func hexLen(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("expected %d bytes, got %d", n, len(b))
	}
	return b, nil
}

// ReceiptBundle is the on-the-wire signed receipt (hex fields, like Bundle).
type ReceiptBundle struct {
	Schema string `json:"schema"`
	Body   string `json:"body"` // the canonical ReceiptBody text
	Sig    string `json:"sig"`  // 64-byte r||s over SHA-256(body)
	PubX   string `json:"pub_x"`
	PubY   string `json:"pub_y"`
}

// ReceiptResult is the outcome of verifying a receipt.
type ReceiptResult struct {
	Receipt    *Receipt
	OK         bool
	Reason     string
	NextDigest []byte // = ReceiptDigest(body); the next receipt's expected prev_digest
}

// ReceiptOptions pins what the verifier expects of a receipt.
type ReceiptOptions struct {
	// ExpectedPrevDigest, if set, must equal the receipt's prev_digest — i.e. this
	// receipt must chain onto the last one accepted (use the previous NextDigest;
	// 32 zero bytes for the genesis receipt). Leave nil to skip the chain check.
	ExpectedPrevDigest []byte
	// PinPubX/PinPubY, if set, must match the receipt's key (the enrolled device).
	PinPubX, PinPubY []byte
	// RequireNotRetained, if true, rejects a receipt that admits retaining input.
	RequireNotRetained bool
}

// VerifyReceipt checks a signed restraint receipt: the P-256 signature over the
// body, the optional key pin and chain link, and (optionally) that it does not
// admit retaining the raw input.
func VerifyReceipt(b ReceiptBundle, opt ReceiptOptions) ReceiptResult {
	body := []byte(b.Body)
	sig, err := hex.DecodeString(b.Sig)
	if err != nil {
		return ReceiptResult{Reason: "sig hex: " + err.Error()}
	}
	px, err := hex.DecodeString(b.PubX)
	if err != nil {
		return ReceiptResult{Reason: "pub_x hex: " + err.Error()}
	}
	py, err := hex.DecodeString(b.PubY)
	if err != nil {
		return ReceiptResult{Reason: "pub_y hex: " + err.Error()}
	}
	if !pinOK(px, py, Options{PinPubX: opt.PinPubX, PinPubY: opt.PinPubY}) {
		return ReceiptResult{Reason: "public key does not match pinned device"}
	}
	if !VerifyCheckpointSig(body, sig, px, py) {
		return ReceiptResult{Reason: "signature does not verify"}
	}
	r, err := ParseReceipt(body)
	if err != nil {
		return ReceiptResult{Reason: "decode: " + err.Error()}
	}
	if opt.RequireNotRetained && r.Retained {
		return ReceiptResult{Receipt: r, Reason: "receipt admits the raw input was retained"}
	}
	if opt.ExpectedPrevDigest != nil {
		if subtle.ConstantTimeCompare(r.PrevDigest, opt.ExpectedPrevDigest) != 1 {
			return ReceiptResult{Receipt: r,
				Reason: "prev_digest mismatch (a batch was suppressed or the chain forked)"}
		}
	}
	return ReceiptResult{Receipt: r, OK: true, Reason: "verified", NextDigest: ReceiptDigest(body)}
}
