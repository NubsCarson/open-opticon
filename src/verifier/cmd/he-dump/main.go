// he-dump — decode an Honest Ear bound-output bundle to human-readable fields,
// WITHOUT verifying it. An audit aid: it lets anyone inspect exactly what a
// device committed (the deterministic-CBOR predicate) without writing Go or
// reading CBOR by hand. It performs NO cryptographic checks — use he-verify for
// the signature, freshness, and anti-replay gates.
//
//	he-dump [bundle.json]            # decode the payload inside a bundle (or stdin)
//	he-dump --payload <hex>          # decode a raw deterministic-CBOR payload
//
// Exits 0 on a clean decode, 1 on a decode error, 2 on usage/IO error.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), `he-dump — decode a bound-output bundle/payload to human-readable fields (NO verification).

  he-dump [bundle.json]      decode the payload inside a bundle (file arg or stdin)
  he-dump --payload <hex>    decode a raw deterministic-CBOR payload

This does NOT check the signature, nonce freshness, or counter — use he-verify for that.

flags:
`)
		flag.PrintDefaults()
	}
	payloadHex := flag.String("payload", "", "decode a raw payload hex directly (instead of a bundle)")
	flag.Parse()

	if *payloadHex != "" {
		payload, err := hex.DecodeString(*payloadHex)
		if err != nil {
			cli.Die("bad --payload hex: %v", err)
		}
		pred, derr := verifier.DecodePayload(payload)
		render(os.Stdout, nil, pred, payload, derr)
		if derr != nil {
			os.Exit(1)
		}
		return
	}

	var raw []byte
	var err error
	if flag.NArg() >= 1 {
		raw, err = os.ReadFile(flag.Arg(0))
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		cli.Die("reading bundle: %v", err)
	}
	b, payload, pred, derr := decodeBundle(raw)
	render(os.Stdout, b, pred, payload, derr)
	if derr != nil {
		os.Exit(1)
	}
}

// decodeBundle parses a bundle JSON and decodes its payload. The returned error
// is the decode error (if any); a parse error is fatal via cli.Die.
func decodeBundle(raw []byte) (*verifier.Bundle, []byte, *verifier.Predicate, error) {
	var b verifier.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		cli.Die("parsing bundle JSON: %v", err)
	}
	payload, err := hex.DecodeString(b.Payload)
	if err != nil {
		return &b, nil, nil, fmt.Errorf("bad payload hex: %w", err)
	}
	pred, err := verifier.DecodePayload(payload)
	return &b, payload, pred, err
}

// render writes the decoded predicate (and any bundle metadata) to w. It always
// prints the NOT-VERIFIED banner so output is never mistaken for a verdict.
func render(w io.Writer, b *verifier.Bundle, p *verifier.Predicate, payload []byte, decodeErr error) {
	fmt.Fprintln(w, "he-dump — DECODE ONLY (no signature / freshness / anti-replay check)")
	if b != nil {
		fmt.Fprintf(w, "  schema       : %s\n", b.Schema)
		fmt.Fprintf(w, "  payload_len  : %d bytes\n", len(payload))
		fmt.Fprintf(w, "  sig          : %s\n", short(b.Sig))
		fmt.Fprintf(w, "  pub_x        : %s\n", short(b.PubX))
		fmt.Fprintf(w, "  pub_y        : %s\n", short(b.PubY))
	}
	if decodeErr != nil {
		fmt.Fprintf(w, "  decode       : FAILED — %v\n", decodeErr)
		return
	}
	fmt.Fprintln(w, "  predicate:")
	fmt.Fprintf(w, "    version    : %d\n", p.Version)
	fmt.Fprintf(w, "    event      : %s (%d)\n", p.EventName(), p.EventID)
	fmt.Fprintf(w, "    presence   : %d\n", p.Presence)
	fmt.Fprintf(w, "    voice      : %v\n", p.VoiceActive)
	fmt.Fprintf(w, "    frames     : %d  (~%d ms observed)\n", p.Frames, p.WindowMs)
	fmt.Fprintf(w, "    counter    : %d\n", p.Counter)
	fmt.Fprintf(w, "    nonce      : %x\n", p.Nonce)
	fmt.Fprintf(w, "    config_hash: %x\n", p.ConfigHash)
	fmt.Fprintf(w, "    input_hash : %x\n", p.InputHash)
	prev := p.PrevDigest
	if isZero(prev) {
		fmt.Fprintf(w, "    prev_digest: %x  (genesis — first in the stream)\n", prev)
	} else {
		fmt.Fprintf(w, "    prev_digest: %x\n", prev)
	}
}

// short abbreviates a long hex string for readable single-line output.
func short(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:16] + "…" + s[len(s)-8:]
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return len(b) > 0
}
