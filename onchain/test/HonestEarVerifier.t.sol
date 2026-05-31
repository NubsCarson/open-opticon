// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {HonestEarVerifier} from "../src/HonestEarVerifier.sol";

/// Verifies a REAL RISC Zero Groth16 receipt of the Honest Ear detector on a
/// local EVM — no testnet, no funds. The fixture (test/proof_fixture.json) is a
/// genuine proof produced by `he-zk-prove --groth16` over the alarm_short clip;
/// the audio is not in it. Tampering the journal or the seal must revert.
contract HonestEarVerifierTest is Test {
    HonestEarVerifier hev;
    bytes seal;
    bytes journal;
    bytes32 imageId;

    function setUp() public {
        string memory j = vm.readFile("./test/proof_fixture.json");
        imageId = vm.parseJsonBytes32(j, ".imageId");
        journal = vm.parseJsonBytes(j, ".journal");
        seal = vm.parseJsonBytes(j, ".seal");

        // The real Groth16 verifier for this RISC Zero version (pinned ControlID).
        RiscZeroGroth16Verifier v =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        hev = new HonestEarVerifier(v, imageId);
    }

    function test_VerifiesRealProof() public view {
        HonestEarVerifier.Verdict memory vd = hev.checkVerdict(seal, journal);
        // alarm_short: a 3.1 kHz tone -> alarm_tone, presence asserted.
        assertEq(vd.eventClass, 2, "event should be alarm_tone");
        assertEq(vd.presence, 1, "presence should be asserted");
        assertEq(vd.nSamples, 3072, "12 frames of 256 samples");
        assertEq(vd.frames, 12, "frames processed");
    }

    function test_RejectsTamperedJournal() public {
        bytes memory bad = journal;
        bad[0] = bytes1(uint8(bad[0]) ^ 0xff); // flip the event byte
        vm.expectRevert();
        hev.checkVerdict(seal, bad);
    }

    function test_RejectsTamperedSeal() public {
        bytes memory bad = seal;
        bad[bad.length - 1] = bytes1(uint8(bad[bad.length - 1]) ^ 0xff);
        vm.expectRevert();
        hev.checkVerdict(bad, journal);
    }
}
