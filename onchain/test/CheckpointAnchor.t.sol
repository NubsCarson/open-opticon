// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CheckpointAnchor} from "../src/CheckpointAnchor.sol";

/// Anchors a REAL transparency-log consistency proof (tree size 3 -> 5, produced
/// by `he-log consistency`, in test/checkpoint_fixture.json) and asserts the
/// on-chain RFC 9162 check accepts the genuine append-only extension and rejects
/// a forked root and a size rollback.
contract CheckpointAnchorTest is Test {
    CheckpointAnchor anchor;
    uint256 oldSize;
    uint256 newSize;
    bytes32 oldRoot;
    bytes32 newRoot;
    bytes32[] proof;

    function setUp() public {
        anchor = new CheckpointAnchor();
        string memory j = vm.readFile("./test/checkpoint_fixture.json");
        oldSize = vm.parseJsonUint(j, ".oldSize");
        newSize = vm.parseJsonUint(j, ".newSize");
        oldRoot = vm.parseJsonBytes32(j, ".oldRoot");
        newRoot = vm.parseJsonBytes32(j, ".newRoot");
        proof = vm.parseJsonBytes32Array(j, ".proof");
    }

    function test_AnchorsConsistentExtension() public {
        anchor.anchor(oldSize, oldRoot, new bytes32[](0), ""); // seed at size 3
        anchor.anchor(newSize, newRoot, proof, ""); // proven 3 -> 5 extension
        assertEq(anchor.latestSize(), newSize);
        assertEq(anchor.latestRoot(), newRoot);
    }

    function test_RejectsForkedRoot() public {
        anchor.anchor(oldSize, oldRoot, new bytes32[](0), "");
        bytes32 forged = newRoot ^ bytes32(uint256(1)); // a root not extending oldRoot
        vm.expectRevert(bytes("inconsistent: not an append-only extension"));
        anchor.anchor(newSize, forged, proof, "");
    }

    function test_RejectsRollback() public {
        anchor.anchor(newSize, newRoot, new bytes32[](0), ""); // seed at size 5
        vm.expectRevert(bytes("size must strictly increase"));
        anchor.anchor(oldSize, oldRoot, proof, ""); // size 3 <= 5
    }

    // A larger size with the GENUINE new root but an EMPTY consistency proof must be
    // refused: without the proof the anchor can't verify the 3->5 extension, so it
    // fails closed rather than recording an unproven advance.
    function test_RejectsEmptyProof() public {
        anchor.anchor(oldSize, oldRoot, new bytes32[](0), ""); // seed at size 3
        vm.expectRevert(bytes("inconsistent: not an append-only extension"));
        anchor.anchor(newSize, newRoot, new bytes32[](0), ""); // real newRoot, no proof
    }
}
