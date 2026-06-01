// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {HonestEarVerifier} from "../src/HonestEarVerifier.sol";

/// Deploy HonestEarVerifier against an already-deployed RISC Zero verifier.
///
/// On a live chain you reuse RISC Zero's canonical, audited verifier router
/// (do NOT deploy your own Groth16 verifier in production) — pass its address
/// via RISC0_VERIFIER and the guest measurement via IMAGE_ID:
///
///   RISC0_VERIFIER=0x<canonical router> IMAGE_ID=0x<guest imageId> \
///   forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --private-key $PK
///
/// IMAGE_ID is the canonical risc0 image id (as printed by he-zk-prove /
/// he-zk-export, e.g. 0x7b3b6516...), NOT a byte-reversed form.
///
/// This is the only step that needs a funded key + an RPC; everything the test
/// asserts (the proof actually verifies on the EVM) runs locally with no funds.
contract Deploy is Script {
    function run() external {
        address verifier = vm.envAddress("RISC0_VERIFIER");
        bytes32 imageId = vm.envBytes32("IMAGE_ID");

        vm.startBroadcast();
        HonestEarVerifier hev = new HonestEarVerifier(IRiscZeroVerifier(verifier), imageId);
        vm.stopBroadcast();

        console2.log("HonestEarVerifier:", address(hev));
    }
}
