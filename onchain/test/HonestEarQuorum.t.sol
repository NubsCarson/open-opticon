// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {VerificationFailed} from "risc0/IRiscZeroVerifier.sol";
import {HonestEarQuorum} from "../src/HonestEarQuorum.sol";

/// On-chain heterogeneous 2-of-3: a REAL Groth16 receipt (test/proof_fixture.json)
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

        RiscZeroGroth16Verifier rv =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        q = new HonestEarQuorum(rv, imageId, devX, devY);
    }

    function test_QuorumAgrees() public view {
        (uint32 ev, uint32 pres) = q.verdict(seal, journal, aPayload, aSig);
        assertEq(ev, 2, "agreed event should be alarm_tone");
        assertEq(pres, 1, "agreed presence");
    }

    function test_RejectsDisagreement() public {
        // zk proof says alarm_tone; the (validly signed) device bundle says none.
        vm.expectRevert(bytes("roots disagree"));
        q.verdict(seal, journal, sPayload, sSig);
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
