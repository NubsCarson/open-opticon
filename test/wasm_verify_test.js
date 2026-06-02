// Smoke-test the in-browser WASM verifier (docs/verify.wasm) the same way the
// page drives it: load the Go wasm runtime, instantiate the module, and call the
// exported heVerify(bundleJSON, opts). Asserts the wasm produces the SAME verdicts
// as the he-verify CLI across the happy path and the negative cases — so the
// browser path can't silently diverge (e.g. fail open). Exits non-zero on any
// mismatch. Run after `bash tools/build_wasm.sh`:  node test/wasm_verify_test.js
"use strict";
const fs = require("fs");
const path = require("path");

const DOCS = path.join(__dirname, "..", "docs");
eval(fs.readFileSync(path.join(DOCS, "wasm_exec.js"), "utf8")); // defines globalThis.Go

// A real genesis bundle (alarm clip, published test key) + its nonce.
const BUNDLE = {
  schema: "honest-ear/bound-output/v1",
  payload:
    "ab00010148d15ea5edc0ffee00020203f40401050c0618c0070108582051e7de71c7f04ed661fcd4588a5399eafa51553fd6a0ac9b2d173eadab73f9d009582076fce813fbb5a4c577d78eb957bcb37962a16a89d3c1151b801acdb96b9b0e2a0a58200000000000000000000000000000000000000000000000000000000000000000",
  sig:
    "fd71cb4589d42574da646dd454afe4418dfdadb2d25382309599db72dd6b54000ea476cfd09b3c97c700fe15d14a99663e7c7b06a102294264ed0774a5ec079a",
  pub_x: "30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e",
  pub_y: "e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723",
};
const NONCE = "d15ea5edc0ffee00";
const ZERO64 = "0".repeat(64);

// The same observation in a COSE_Sign1 (RFC 9052) envelope (HE_COSE=1 signer),
// same key + nonce — the wasm must auto-detect and verify it identically.
const COSE_BUNDLE = {
  schema: "honest-ear/cose-sign1/v1",
  cose:
    "d28443a10126a05883ab00010148d15ea5edc0ffee00020203f40401050c0618c00701085820ba3c0d6a27de9bc78a95dd53cf1045ac799cb2a90f6e61a00cfd57bc5f1feea109582076fce813fbb5a4c577d78eb957bcb37962a16a89d3c1151b801acdb96b9b0e2a0a5820000000000000000000000000000000000000000000000000000000000000000058402226ca9000a8176bb8e505b87325f1539fbf8142fb6bf93b5ef5ca5530681e253746e22ebba0d7fe057c74e2bd999987e9212e34b6f67deab40cb1c3bd121e83",
  pub_x: "30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e",
  pub_y: "e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723",
};

// A real transferable equivocation proof (two pinned witnesses cosigning conflicting
// roots at the SAME size 5) + the two PINNED witness keys — generated offline via the
// verifier package (CheckpointBody/CosignCheckpoint). The wasm must verify it under
// the pinned keys, and reject it under a substituted key.
const EQUIV_PROOF = {
  schema: "honest-ear/equivocation-proof/v1",
  a: {
    witness: "wa",
    checkpoint_body: "honest-ear.log/v1\n5\nEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    cosignature:
      "e6419adef8305fb4d0d284fee225e307070fc42307feca49f9696a871e71ebfb83767b6673d7f77b3f9b4d65e1fe207182da72bf54e67a990e74458a13b699b4",
    witness_pub_x: "172060cc5df900f5d12278121c4c77451eff1aac0b74ec2863e948e75f9397ce",
    witness_pub_y: "c672cdd561634d90c20accadd6f862254b3a05b60f8f7d2e4480ce2d4ee514fa",
  },
  b: {
    witness: "wb",
    checkpoint_body: "honest-ear.log/v1\n5\nIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    cosignature:
      "3dc5618943b1b12e3a54e74b1dbe230a1f7466697fbcd7b4c18ec05c5ba7d6c4dd1873466514094cbd73a63d4c3c4fc285fc02520c4a91a75d65de9fac8d355d",
    witness_pub_x: "0886d3d3ad4148dacc8b852afa88a8d4da4682ee96c375854127d06fced819d3",
    witness_pub_y: "7f41fece5e390beba718edc80bbcb6d3c06cdaee94558dbf9bd9237dfdc25148",
  },
};
const EQUIV_KEYS = {
  aPubX: "172060cc5df900f5d12278121c4c77451eff1aac0b74ec2863e948e75f9397ce",
  aPubY: "c672cdd561634d90c20accadd6f862254b3a05b60f8f7d2e4480ce2d4ee514fa",
  bPubX: "0886d3d3ad4148dacc8b852afa88a8d4da4682ee96c375854127d06fced819d3",
  bPubY: "7f41fece5e390beba718edc80bbcb6d3c06cdaee94558dbf9bd9237dfdc25148",
};

let failures = 0;
function check(name, cond) {
  if (cond) {
    console.log("  ok:   " + name);
  } else {
    console.log("  FAIL: " + name);
    failures++;
  }
}

(async () => {
  const go = new Go();
  const bytes = fs.readFileSync(path.join(DOCS, "verify.wasm"));
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(instance); // registers heVerify, then blocks on select{}
  const H = globalThis.heVerify;

  console.log("wasm_verify_test:");
  check("heVerify is registered", typeof H === "function");
  if (typeof H !== "function") process.exit(1);

  // Happy path -> PASS, alarm_tone, genesis chain ok.
  let r = H(JSON.stringify(BUNDLE), { nonce: NONCE, lastCounter: 0 });
  check("valid bundle verifies", r.ok === true);
  check("event is alarm_tone", r.predicate && r.predicate.event === "alarm_tone");
  check("nextDigest is returned", typeof r.nextDigest === "string" && r.nextDigest.length === 64);

  // Proof-explorer fields: the gate-by-gate walk and the 5-question answers.
  check("steps is a 5-gate walk", Array.isArray(r.steps) && r.steps.length === 5);
  check("signature step passed", r.steps && r.steps.some(s => s.gate === "signature" && s.status === "pass"));
  check("freshness step applicable on PASS", r.steps && r.steps.some(s => s.gate === "freshness" && s.status === "pass"));
  check("answers cover all 5 questions", Array.isArray(r.answers) && r.answers.length === 5);
  check("answers carry honest tiers", r.answers && r.answers.every(a => a.tier && a.notProven && a.q && a.a));
  check("a 'where' answer is present", r.answers && r.answers.some(a => /where/.test(a.q)));
  // A FAIL must not emit predicate-derived answers (nothing was proven).
  let rf = H(JSON.stringify(BUNDLE), { nonce: "deadbeef", lastCounter: 0 });
  check("no answers on FAIL", rf.ok === false && rf.answers === undefined);

  // Wrong nonce -> FAIL (freshness).
  r = H(JSON.stringify(BUNDLE), { nonce: "deadbeef", lastCounter: 0 });
  check("wrong nonce fails", r.ok === false);

  // Empty nonce must NOT fail open.
  r = H(JSON.stringify(BUNDLE), { nonce: "", lastCounter: 0 });
  check("empty nonce fails closed", r.ok === false);

  // Replay (counter not advanced) -> FAIL.
  r = H(JSON.stringify(BUNDLE), { nonce: NONCE, lastCounter: 1 });
  check("replayed counter fails", r.ok === false);

  // Tampered payload byte -> signature FAIL.
  const t = JSON.parse(JSON.stringify(BUNDLE));
  t.payload = t.payload.slice(0, 20) + ((parseInt(t.payload[20], 16) ^ 0xf).toString(16)) + t.payload.slice(21);
  r = H(JSON.stringify(t), { nonce: NONCE, lastCounter: 0 });
  check("tampered payload fails", r.ok === false);

  // Chain: genesis expects all-zero prev_digest -> PASS; non-zero -> FAIL (gap).
  r = H(JSON.stringify(BUNDLE), { nonce: NONCE, lastCounter: 0, expectPrev: ZERO64 });
  check("genesis chain verifies", r.ok === true);
  r = H(JSON.stringify(BUNDLE), { nonce: NONCE, lastCounter: 0, expectPrev: "11".repeat(32) });
  check("chain gap fails", r.ok === false);

  // Half-pin (pinX without pinY) -> usage error.
  r = H(JSON.stringify(BUNDLE), { nonce: NONCE, pinX: "30a0424c" });
  check("half pin rejected", r.ok === false);

  // Garbage JSON -> error, not a crash.
  r = H("{not json", { nonce: NONCE });
  check("bad JSON handled", r.ok === false);

  // COSE_Sign1 envelope: auto-detected and verified identically to the raw one.
  r = H(JSON.stringify(COSE_BUNDLE), { nonce: NONCE, lastCounter: 0 });
  check("COSE bundle verifies", r.ok === true);
  check("COSE envelope detected", r.envelope === "cose-sign1");
  check("COSE event is alarm_tone", r.predicate && r.predicate.event === "alarm_tone");
  r = H(JSON.stringify(COSE_BUNDLE), { nonce: "deadbeef", lastCounter: 0 });
  check("COSE wrong nonce fails", r.ok === false);
  const tc = JSON.parse(JSON.stringify(COSE_BUNDLE));
  tc.cose = tc.cose.slice(0, 40) + ((parseInt(tc.cose[40], 16) ^ 0xf).toString(16)) + tc.cose.slice(41);
  r = H(JSON.stringify(tc), { nonce: NONCE, lastCounter: 0 });
  check("tampered COSE fails", r.ok === false);

  // Equivocation proof: verified in-browser under the two PINNED witness keys.
  const E = globalThis.heVerifyEquivocation;
  check("heVerifyEquivocation is registered", typeof E === "function");
  let e = E(JSON.stringify(EQUIV_PROOF), EQUIV_KEYS);
  check("valid equivocation proof verifies", e.ok === true);
  check("proof names both witnesses", e.witnessA === "wa" && e.witnessB === "wb");
  // A WRONG pinned key (A pinned to B's key) must NOT verify.
  e = E(JSON.stringify(EQUIV_PROOF), Object.assign({}, EQUIV_KEYS, { aPubX: EQUIV_KEYS.bPubX }));
  check("wrong pinned key fails", e.ok === false);
  // Garbage proof JSON -> error, not a crash.
  e = E("{not json", EQUIV_KEYS);
  check("bad proof JSON handled", e.ok === false);

  console.log(failures === 0 ? "wasm_verify_test: all passed" : `wasm_verify_test: ${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => {
  console.error("wasm_verify_test: error:", e);
  process.exit(1);
});
