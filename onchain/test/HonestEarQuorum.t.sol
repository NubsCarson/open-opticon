// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {VerificationFailed} from "risc0/IRiscZeroVerifier.sol";
import {HonestEarQuorum} from "../src/HonestEarQuorum.sol";

/// On-chain heterogeneous dual-root check (2-of-2): a REAL Groth16 receipt (test/proof_fixture.json)
/// AND a REAL device P-256 bound-output bundle (test/quorum_fixture.json) for the
/// same alarm clip must agree before the contract returns a verdict. Verified
/// entirely on a local EVM — Groth16 via the RISC Zero verifier, P-256 via
/// OpenZeppelin. A tampered receipt, a tampered signature, or a device bundle
/// that disagrees with the proof all revert.
contract HonestEarQuorumTest is Test {
    HonestEarQuorum q;
    bytes seal;
    bytes journal;
    bytes aPayload;
    bytes aSig;
    bytes sPayload;
    bytes sSig;
    bytes altPayload;
    bytes altSig;

    function setUp() public {
        string memory pf = vm.readFile("./test/proof_fixture.json");
        bytes32 imageId = vm.parseJsonBytes32(pf, ".imageId");
        journal = vm.parseJsonBytes(pf, ".journal");
        seal = vm.parseJsonBytes(pf, ".seal");

        string memory qf = vm.readFile("./test/quorum_fixture.json");
        bytes32 devX = vm.parseJsonBytes32(qf, ".alarm.pubX");
        bytes32 devY = vm.parseJsonBytes32(qf, ".alarm.pubY");
        aPayload = vm.parseJsonBytes(qf, ".alarm.payload");
        aSig = vm.parseJsonBytes(qf, ".alarm.sig");
        sPayload = vm.parseJsonBytes(qf, ".silence.payload");
        sSig = vm.parseJsonBytes(qf, ".silence.sig");
        altPayload = vm.parseJsonBytes(qf, ".alarmAltNonce.payload");
        altSig = vm.parseJsonBytes(qf, ".alarmAltNonce.sig");

        RiscZeroGroth16Verifier rv =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        q = new HonestEarQuorum(rv, imageId, devX, devY);
    }

    function test_QuorumAgrees() public view {
        (uint32 ev, uint32 pres) = q.verdict(seal, journal, aPayload, aSig);
        assertEq(ev, 2, "agreed event should be alarm_tone");
        assertEq(pres, 1, "agreed presence");
    }

    function test_RecordEnforcesAntiReplay() public {
        (uint32 ev,) = q.recordVerdict(seal, journal, aPayload, aSig); // counter 1: ok
        assertEq(ev, 2);
        assertEq(q.lastCounter(), 1);
        // Re-submitting the same bundle (counter 1, not > 1) must be rejected.
        vm.expectRevert(bytes("counter must advance (anti-replay)"));
        q.recordVerdict(seal, journal, aPayload, aSig);
    }

    function test_RejectsAudioMismatch() public {
        // A validly-signed device bundle for a DIFFERENT clip (silence) than the
        // zk proof attests (alarm): the audio binding must reject it, so a proof
        // and a signature about different inputs can't be combined — even against
        // a misbehaving device. (Same nonce, so the audio check is what fires.)
        vm.expectRevert(bytes("audio mismatch (different input)"));
        q.verdict(seal, journal, sPayload, sSig);
    }

    function test_RejectsNonceMismatch() public {
        // A validly-signed alarm bundle for the SAME clip but a DIFFERENT nonce
        // than the zk proof is bound to: the cross-root binding must reject it,
        // so a proof and a signature from different sessions can't be combined.
        vm.expectRevert(bytes("nonce mismatch (different sessions)"));
        q.verdict(seal, journal, altPayload, altSig);
    }

    function test_RejectsTamperedReceipt() public {
        bytes memory bad = journal;
        bad[0] = bytes1(uint8(bad[0]) ^ 0xff);
        vm.expectRevert(VerificationFailed.selector);
        q.verdict(seal, bad, aPayload, aSig);
    }

    function test_RejectsTamperedDeviceSig() public {
        bytes memory bad = aSig;
        bad[0] = bytes1(uint8(bad[0]) ^ 0xff);
        vm.expectRevert(bytes("device sig"));
        q.verdict(seal, journal, aPayload, bad);
    }
}
