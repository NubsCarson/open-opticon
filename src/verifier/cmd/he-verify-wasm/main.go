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
	var b verifier.Bundle
	if err := json.Unmarshal([]byte(args[0].String()), &b); err != nil {
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

	res := verifier.VerifyBundle(b, opt)
	out := map[string]any{
		"ok":         res.OK,
		"reason":     res.Reason,
		"nextDigest": hex.EncodeToString(res.NextDigest),
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
	}
	return out
}

func main() {
	js.Global().Set("heVerify", js.FuncOf(heVerify))
	if c := js.Global().Get("console"); c.Type() == js.TypeObject {
		c.Call("log", "honest-ear verifier (wasm) ready — heVerify(bundleJSON, {nonce})")
	}
	select {} // keep the Go runtime alive so heVerify stays callable
}
