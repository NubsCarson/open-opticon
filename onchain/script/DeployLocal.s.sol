// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {HonestEarVerifier} from "../src/HonestEarVerifier.sol";
import {CheckpointAnchor} from "../src/CheckpointAnchor.sol";
import {HonestEarQuorum} from "../src/HonestEarQuorum.sol";

/// Full local-devnet bring-up: deploys the RISC Zero verifier, the Honest Ear
/// wrapper, and the transparency-log anchor, then runs LIVE transactions — it
/// anchors a real consistency-proven checkpoint sequence and checks a real zk
/// verdict on-chain. Run against anvil (a real EVM), no testnet funds needed:
///
///   anvil &  (or any RPC)
///   forge script script/DeployLocal.s.sol --rpc-url http://localhost:8545 \
///       --broadcast --private-key <anvil key>
contract DeployLocal is Script {
    function run() external {
        string memory pf = vm.readFile("./test/proof_fixture.json");
        bytes32 imageId = vm.parseJsonBytes32(pf, ".imageId");
        bytes memory journal = vm.parseJsonBytes(pf, ".journal");
        bytes memory seal = vm.parseJsonBytes(pf, ".seal");

        string memory cf = vm.readFile("./test/checkpoint_fixture.json");
        uint256 oldSize = vm.parseJsonUint(cf, ".oldSize");
        uint256 newSize = vm.parseJsonUint(cf, ".newSize");
        bytes32 oldRoot = vm.parseJsonBytes32(cf, ".oldRoot");
        bytes32 newRoot = vm.parseJsonBytes32(cf, ".newRoot");
        bytes32[] memory proof = vm.parseJsonBytes32Array(cf, ".proof");

        string memory qf = vm.readFile("./test/quorum_fixture.json");
        bytes32 devX = vm.parseJsonBytes32(qf, ".alarm.pubX");
        bytes32 devY = vm.parseJsonBytes32(qf, ".alarm.pubY");
        bytes memory devPayload = vm.parseJsonBytes(qf, ".alarm.payload");
        bytes memory devSig = vm.parseJsonBytes(qf, ".alarm.sig");

        vm.startBroadcast();
        RiscZeroGroth16Verifier rv =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        HonestEarVerifier hev = new HonestEarVerifier(rv, imageId);
        CheckpointAnchor anchor = new CheckpointAnchor();
        HonestEarQuorum quorum = new HonestEarQuorum(rv, imageId, devX, devY);

        // LIVE transactions: anchor the log, then extend it with the proof.
        anchor.anchor(oldSize, oldRoot, new bytes32[](0), "");
        anchor.anchor(newSize, newRoot, proof, "");
        vm.stopBroadcast();

        // Read the proven verdicts back off-chain (view calls).
        HonestEarVerifier.Verdict memory v = hev.checkVerdict(seal, journal);
        (uint32 qEvent, uint32 qPresence) = quorum.verdict(seal, journal, devPayload, devSig);

        console2.log("RiscZeroGroth16Verifier:", address(rv));
        console2.log("HonestEarVerifier      :", address(hev));
        console2.log("CheckpointAnchor       :", address(anchor));
        console2.log("HonestEarQuorum        :", address(quorum));
        console2.log("anchor latest size     :", anchor.latestSize());
        console2.log("zk-proven event class  :", v.eventClass); // 2 == alarm_tone
        console2.log("zk-proven presence     :", v.presence);
        console2.log("2-of-3 agreed event    :", qEvent); // ZK + device signature agree
        console2.log("2-of-3 agreed presence :", qPresence);
    }
}
