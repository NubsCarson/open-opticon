// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CheckpointAnchor} from "../src/CheckpointAnchor.sol";

/// Differential test of the hand-ported Solidity CheckpointAnchor._verifyConsistency
/// (the on-chain anti-equivocation / anti-rewrite gate, comment: "faithful port of
/// VerifyConsistency") against the Go VerifyConsistency oracle that
/// transparency_test.go's TestConsistencyExhaustive already proves correct.
///
/// test/gen_consistency_cases.sh emits REAL RFC 9162 proofs for many (oldSize ->
/// newSize) pairs (66 of them) from a he-log transparency log. Every extension the
/// Go oracle accepts must also verify on-chain; a forged root must be rejected. This
/// exercises the ported branchy loop (the fn&1 / fn==sn / while fn&1==0 arithmetic)
/// for sizes the single committed 3->5 fixture never touches.
contract ConsistencyDiffTest is Test {
    uint256[] oldSize;
    uint256[] newSize;
    bytes32[] oldRoot;
    bytes32[] newRoot;
    bytes[] proofConcat; // each case's proof nodes concatenated into one bytes

    function setUp() public {
        string memory j = vm.readFile("./test/consistency_cases.json");
        oldSize = vm.parseJsonUintArray(j, ".oldSize");
        newSize = vm.parseJsonUintArray(j, ".newSize");
        oldRoot = vm.parseJsonBytes32Array(j, ".oldRoot");
        newRoot = vm.parseJsonBytes32Array(j, ".newRoot");
        proofConcat = vm.parseJsonBytesArray(j, ".proof");
    }

    /// Slice concatenated 32-byte nodes back into the bytes32[] the anchor expects.
    function _nodes(bytes memory b) internal pure returns (bytes32[] memory nodes) {
        require(b.length % 32 == 0, "bad proof length");
        nodes = new bytes32[](b.length / 32);
        for (uint256 k = 0; k < nodes.length; k++) {
            bytes32 n;
            assembly {
                n := mload(add(add(b, 0x20), mul(k, 0x20)))
            }
            nodes[k] = n;
        }
    }

    // Every (oldSize -> newSize) extension the Go oracle proved consistent must verify
    // on-chain through CheckpointAnchor.
    function test_AllGoProvenConsistencyVerifiesOnChain() public {
        assertGt(oldSize.length, 10, "expected many differential cases");
        for (uint256 i = 0; i < oldSize.length; i++) {
            CheckpointAnchor a = new CheckpointAnchor();
            a.anchor(oldSize[i], oldRoot[i], new bytes32[](0), ""); // seed at oldSize
            a.anchor(newSize[i], newRoot[i], _nodes(proofConcat[i]), ""); // proven extension
            assertEq(a.latestSize(), newSize[i], "consistent extension not recorded");
            assertEq(a.latestRoot(), newRoot[i], "wrong root recorded");
        }
    }

    // For every case, a forged new root with the genuine proof must be refused — the
    // on-chain check is not just rubber-stamping the size.
    function test_ForgedRootRejectedAcrossAllCases() public {
        uint256 checked;
        for (uint256 i = 0; i < oldSize.length; i++) {
            CheckpointAnchor a = new CheckpointAnchor();
            a.anchor(oldSize[i], oldRoot[i], new bytes32[](0), "");
            vm.expectRevert(bytes("inconsistent: not an append-only extension"));
            a.anchor(newSize[i], newRoot[i] ^ bytes32(uint256(1)), _nodes(proofConcat[i]), "");
            checked++;
        }
        assertGt(checked, 10, "expected many forgeable cases");
    }
}
