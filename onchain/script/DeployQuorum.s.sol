// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {HonestEarQuorum} from "../src/HonestEarQuorum.sol";

/// Slim deploy: just the RISC Zero verifier + the audio+nonce-bound dual-root
/// quorum (the headline contract), for when only modest gas is available. Reads
/// the agreed verdict back via a view call. No anchor, no state-changing txs.
contract DeployQuorum is Script {
    function run() external {
        string memory pf = vm.readFile("./test/proof_fixture.json");
        bytes32 imageId = vm.parseJsonBytes32(pf, ".imageId");
        bytes memory journal = vm.parseJsonBytes(pf, ".journal");
        bytes memory seal = vm.parseJsonBytes(pf, ".seal");

        string memory qf = vm.readFile("./test/quorum_fixture.json");
        bytes32 devX = vm.parseJsonBytes32(qf, ".alarm.pubX");
        bytes32 devY = vm.parseJsonBytes32(qf, ".alarm.pubY");
        bytes memory devPayload = vm.parseJsonBytes(qf, ".alarm.payload");
        bytes memory devSig = vm.parseJsonBytes(qf, ".alarm.sig");

        vm.startBroadcast();
        RiscZeroGroth16Verifier rv =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        HonestEarQuorum quorum = new HonestEarQuorum(rv, imageId, devX, devY);
        vm.stopBroadcast();

        (uint32 ev, uint32 pres) = quorum.verdict(seal, journal, devPayload, devSig);
        console2.log("RiscZeroGroth16Verifier:", address(rv));
        console2.log("HonestEarQuorum        :", address(quorum));
        console2.log("2-of-2 agreed event    :", ev);
        console2.log("2-of-2 agreed presence :", pres);
    }
}
