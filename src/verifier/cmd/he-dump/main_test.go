package main

import (
	"bytes"
	"strings"
	"testing"
)

// A real genesis bundle (alarm clip, published test key) — same shape the host
// signer emits. Used to confirm he-dump decodes and renders without verifying.
const sampleBundle = `{
  "schema": "honest-ear/bound-output/v1",
  "payload": "ab00010148d15ea5edc0ffee00020203f40401050c0618c0070108582051e7de71c7f04ed661fcd4588a5399eafa51553fd6a0ac9b2d173eadab73f9d009582076fce813fbb5a4c577d78eb957bcb37962a16a89d3c1151b801acdb96b9b0e2a0a58200000000000000000000000000000000000000000000000000000000000000000",
  "sig": "fd71cb4589d42574da646dd454afe4418dfdadb2d25382309599db72dd6b54000ea476cfd09b3c97c700fe15d14a99663e7c7b06a102294264ed0774a5ec079a",
  "pub_x": "30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e",
  "pub_y": "e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723"
}`

func TestDecodeBundleAndRender(t *testing.T) {
	b, payload, pred, err := decodeBundle([]byte(sampleBundle))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pred.EventName() != "alarm_tone" {
		t.Errorf("event = %q, want alarm_tone", pred.EventName())
	}
	if pred.Counter != 1 {
		t.Errorf("counter = %d, want 1", pred.Counter)
	}
	if !isZero(pred.PrevDigest) {
		t.Errorf("prev_digest should be genesis (zeros), got %x", pred.PrevDigest)
	}

	var out bytes.Buffer
	render(&out, b, pred, payload, nil)
	s := out.String()
	for _, want := range []string{"DECODE ONLY", "alarm_tone", "genesis", "input_hash"} {
		if !strings.Contains(s, want) {
			t.Errorf("render output missing %q\n---\n%s", want, s)
		}
	}
}

func TestRenderDecodeError(t *testing.T) {
	// A truncated/garbage payload must render a FAILED decode, not panic.
	var out bytes.Buffer
	_, _, pred, err := decodeBundle([]byte(`{"schema":"x","payload":"ab00","sig":"","pub_x":"","pub_y":""}`))
	if err == nil {
		t.Fatal("expected decode error on truncated payload")
	}
	render(&out, nil, pred, nil, err)
	if !strings.Contains(out.String(), "FAILED") {
		t.Errorf("expected FAILED banner, got:\n%s", out.String())
	}
}

func TestIsZero(t *testing.T) {
	if !isZero(make([]byte, 32)) {
		t.Error("32 zero bytes should be zero")
	}
	if isZero([]byte{0, 1, 0}) {
		t.Error("non-zero slice reported zero")
	}
	if isZero(nil) {
		t.Error("empty slice should not report genesis-zero")
	}
}
