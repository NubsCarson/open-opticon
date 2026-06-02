//go:build js && wasm

// he-verify-wasm exposes the Honest Ear bound-output verifier to the browser.
//
// Built with GOOS=js GOARCH=wasm, it registers a global `heVerify(bundleJSON,
// opts)` that runs the EXACT same stdlib-only verification as the `he-verify`
// CLI — signature + freshness + anti-replay, plus the optional endorsement pin
// and the optional streaming hash-chain (prev_digest) check. The same Go
// package (`honest-ear/verifier`) compiles to the CLI and to this wasm, so the
// bytes the browser accepts are the bytes the CLI accepts: a verifier anyone can
// run with no server and no install. The audio is never involved — this checks a
// signed verdict, exactly as a phone or a third party would.
package main

import (
	"encoding/hex"
	"encoding/json"
	"syscall/js"

	verifier "honest-ear/verifier"
)

func fail(reason string) any {
	return map[string]any{"ok": false, "reason": reason}
}

func envelopeName(cose string) string {
	if cose != "" {
		return "cose-sign1"
	}
	return "raw"
}

func getString(o js.Value, key string) string {
	if o.Type() != js.TypeObject {
		return ""
	}
	v := o.Get(key)
	if v.Type() == js.TypeString {
		return v.String()
	}
	return ""
}

// heVerify(bundleJSON string, opts object) -> result object.
//
// Accepts either envelope and auto-detects: a raw bound-output bundle
// ({payload,sig,pub_x,pub_y}) or a COSE_Sign1 bundle ({cose,pub_x,pub_y}). The
// result includes "envelope": "raw" | "cose-sign1".
//
// opts (all optional except nonce):
//
//	nonce       hex — the fresh challenge the bundle must echo (required)
//	pinX, pinY  hex — pin the endorsement key (both or neither)
//	lastCounter num — highest counter already accepted (anti-replay)
//	expectPrev  hex — the digest this window must chain from (gap detection)
func heVerify(this js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return fail("usage: heVerify(bundleJSON, opts) — bundleJSON must be a string")
	}
	// Accept BOTH envelopes: a raw bound-output bundle (has "payload"+"sig") or a
	// COSE_Sign1 bundle (has "cose"). Detected by which field is present.
	var probe struct {
		Schema  string `json:"schema"`
		Payload string `json:"payload"`
		COSE    string `json:"cose"`
		Sig     string `json:"sig"`
		PubX    string `json:"pub_x"`
		PubY    string `json:"pub_y"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &probe); err != nil {
		return fail("invalid bundle JSON: " + err.Error())
	}

	var opt verifier.Options
	var nonceHex, pinXHex, pinYHex string
	if len(args) >= 2 {
		o := args[1]
		nonceHex = getString(o, "nonce")
		pinXHex = getString(o, "pinX")
		pinYHex = getString(o, "pinY")
		if o.Type() == js.TypeObject {
			if lc := o.Get("lastCounter"); lc.Type() == js.TypeNumber {
				opt.LastCounter = uint64(lc.Float())
			}
		}
		if ep := getString(o, "expectPrev"); ep != "" {
			pd, err := hex.DecodeString(ep)
			if err != nil {
				return fail("bad expectPrev hex: " + err.Error())
			}
			opt.ExpectedPrevDigest = pd
		}
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return fail("bad nonce hex: " + err.Error())
	}
	opt.ExpectedNonce = nonce

	if (pinXHex == "") != (pinYHex == "") {
		return fail("pinX and pinY must be provided together")
	}
	if pinXHex != "" {
		if opt.PinPubX, err = hex.DecodeString(pinXHex); err != nil {
			return fail("bad pinX hex: " + err.Error())
		}
		if opt.PinPubY, err = hex.DecodeString(pinYHex); err != nil {
			return fail("bad pinY hex: " + err.Error())
		}
	}

	var res verifier.VerifyResult
	if probe.COSE != "" {
		res = verifier.VerifyCOSEBundle(verifier.COSEBundle{
			Schema: probe.Schema, COSE: probe.COSE, PubX: probe.PubX, PubY: probe.PubY,
		}, opt)
	} else {
		res = verifier.VerifyBundle(verifier.Bundle{
			Schema: probe.Schema, Payload: probe.Payload, Sig: probe.Sig,
			PubX: probe.PubX, PubY: probe.PubY,
		}, opt)
	}
	out := map[string]any{
		"ok":         res.OK,
		"reason":     res.Reason,
		"nextDigest": hex.EncodeToString(res.NextDigest),
		"envelope":   envelopeName(probe.COSE),
	}
	if res.Predicate != nil {
		p := res.Predicate
		out["predicate"] = map[string]any{
			"event":       p.EventName(),
			"presence":    float64(p.Presence),
			"voiceActive": p.VoiceActive,
			"frames":      float64(p.Frames),
			"windowMs":    float64(p.WindowMs),
			"counter":     float64(p.Counter),
			"nonce":       hex.EncodeToString(p.Nonce),
			"configHash":  hex.EncodeToString(p.ConfigHash),
			"inputHash":   hex.EncodeToString(p.InputHash),
			"prevDigest":  hex.EncodeToString(p.PrevDigest),
		}
		// Additive proof-explorer fields (do not affect the verdict): the
		// gate-by-gate walk and the credible-sensors 5-question answers, emitted
		// ONLY on a PASS — nothing is "proven" or "answered" on a FAIL, so a failed
		// bundle shows just the verdict + reason, like the live /v page.
		if res.OK {
			out["steps"] = verifySteps(res, opt)
			out["answers"] = fiveAnswers(p)
		}
	}
	return out
}

// verifySteps describes, gate by gate, what the verifier checked — derived from
// the options, in the verifier's own gate order. Only called on a PASS, so every
// applicable gate passed; an applicable gate is "pass", an unused optional gate
// (no pin / no expected-prev / no nonce) is "skipped". It is a presentation of
// the result, not a re-verification.
func verifySteps(res verifier.VerifyResult, opt verifier.Options) []any {
	pinned := len(opt.PinPubX) > 0 && len(opt.PinPubY) > 0
	chained := len(opt.ExpectedPrevDigest) > 0
	st := func(name, proves string, applicable bool) map[string]any {
		status := "skipped"
		if applicable {
			status = "pass"
		}
		return map[string]any{"gate": name, "proves": proves, "status": status}
	}
	return []any{
		st("endorsement pin", "the signing key matches the enrolled device key", pinned),
		st("signature", "a key the device controls signed this exact verdict (ECDSA-P256 over SHA-256 of the payload)", true),
		st("freshness", "the signed nonce equals the challenge — not a replayed or photographed verdict", len(opt.ExpectedNonce) > 0),
		st("anti-replay", "the monotonic counter advanced past the last accepted one", true),
		st("stream chain", "this window chains onto the previous one (a dropped window is a visible gap)", chained),
	}
}

// fiveAnswers mirrors the live /v walk-up page: the credible-sensors 5 questions
// answered from the verified predicate, with the SAME honest tiers — green
// "proven" attaches only to what the signature carries; firmware/hardware claims
// are marked. tier: "proven" | "attestation" | "integrity".
func fiveAnswers(p *verifier.Predicate) []any {
	qa := func(q, a, tier, notProven string) map[string]any {
		return map[string]any{"q": q, "a": a, "tier": tier, "notProven": notProven}
	}
	return []any{
		qa("what gets captured?",
			"sound is analyzed for one thing — "+p.EventName()+". the signed output is a verdict, not a recording or transcript.",
			"proven",
			"that the raw audio is wiped in-enclave and never reaches the OS is firmware behavior — not proven by this signature (attestation tier)."),
		qa("where does it go?",
			"the bundle is a signed verdict with no audio field — that is the whole artifact.",
			"proven",
			"that the device has no separate covert channel rests on firmware measurement + source audit, not on one signature."),
		qa("who can access or release it?",
			"no retained audio to release; only a key the device controls can mint a valid verdict, and replays are rejected.",
			"integrity",
			"tying the verdict to a specific physical device needs a non-extractable hardware key (i.MX CAAM / ST element)."),
		qa("how long is it kept?",
			"only a monotonic counter persists across windows — it carries no audio; the analyzed window is a fingerprint (input_hash), not stored audio.",
			"attestation",
			"the in-enclave zeroize is firmware behavior — verified on QEMU and by reading the source, not by this signature."),
		qa("how is it used?",
			"to compute this coarse verdict under a published policy; config_hash is bound into the signature so the rules are auditable from source.",
			"proven",
			"config_hash makes the policy checkable, not correct — the detector is a heuristic, not an audited model."),
	}
}

// heVerifyEquivocation(proofJSON string, keys object) -> {ok, reason, witnessA,
// witnessB}. Verifies a transferable equivocation proof (honest-ear/equivocation-
// proof/v1, served by he-witness /equivocation-proof) entirely in the browser, under
// the two witness keys the CALLER PINS (keys.aPubX/aPubY/bPubX/bPubY hex) — never the
// self-reported keys in the proof. Mirrors `he-witness verify-equivocation`: a true
// result is offline-verifiable evidence the log equivocated.
func heVerifyEquivocation(this js.Value, args []js.Value) any {
	if len(args) < 2 || args[0].Type() != js.TypeString {
		return fail("usage: heVerifyEquivocation(proofJSON, {aPubX,aPubY,bPubX,bPubY})")
	}
	var p struct {
		Schema string `json:"schema"`
		A      struct {
			Witness        string `json:"witness"`
			CheckpointBody string `json:"checkpoint_body"`
			Cosignature    string `json:"cosignature"`
		} `json:"a"`
		B struct {
			Witness        string `json:"witness"`
			CheckpointBody string `json:"checkpoint_body"`
			Cosignature    string `json:"cosignature"`
		} `json:"b"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &p); err != nil {
		return fail("invalid proof JSON: " + err.Error())
	}
	keys := args[1]
	pin := func(name string) ([]byte, error) { return hex.DecodeString(getString(keys, name)) }
	aX, err := pin("aPubX")
	if err != nil {
		return fail("bad aPubX hex: " + err.Error())
	}
	aY, err := pin("aPubY")
	if err != nil {
		return fail("bad aPubY hex: " + err.Error())
	}
	bX, err := pin("bPubX")
	if err != nil {
		return fail("bad bPubX hex: " + err.Error())
	}
	bY, err := pin("bPubY")
	if err != nil {
		return fail("bad bPubY hex: " + err.Error())
	}
	cosigA, err := hex.DecodeString(p.A.Cosignature)
	if err != nil {
		return fail("bad A cosignature hex: " + err.Error())
	}
	cosigB, err := hex.DecodeString(p.B.Cosignature)
	if err != nil {
		return fail("bad B cosignature hex: " + err.Error())
	}
	ok, reason := verifier.VerifyEquivocation(
		[]byte(p.A.CheckpointBody), cosigA, aX, aY,
		[]byte(p.B.CheckpointBody), cosigB, bX, bY)
	return map[string]any{"ok": ok, "reason": reason, "witnessA": p.A.Witness, "witnessB": p.B.Witness}
}

func main() {
	js.Global().Set("heVerify", js.FuncOf(heVerify))
	js.Global().Set("heVerifyEquivocation", js.FuncOf(heVerifyEquivocation))
	if c := js.Global().Get("console"); c.Type() == js.TypeObject {
		c.Call("log", "honest-ear verifier (wasm) ready — heVerify(bundleJSON, {nonce}); heVerifyEquivocation(proofJSON, {aPubX,...})")
	}
	select {} // keep the Go runtime alive so the exports stay callable
}
