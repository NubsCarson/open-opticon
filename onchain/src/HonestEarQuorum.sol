// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {P256} from "openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title Honest Ear — on-chain heterogeneous 2-of-3 quorum.
///
/// Returns the verdict ONLY if two independent roots agree:
///   (1) a RISC Zero ZK proof of the published detector — no enclave trusted for
///       the math; and
///   (2) the device's hardware-bound secp256r1 (P-256) signature over its
///       bound-output payload — the attested device identity.
/// The EVM verifies both natively (Groth16 via the RISC Zero verifier, P-256 via
/// OpenZeppelin) and checks they report the same (event, presence). A single
/// broken enclave OR a forged signature is not enough — this is the 2-of-3
/// endgame, on-chain, where both proof systems are checkable (the stdlib-only Go
/// verifier cannot verify a STARK; the EVM can).
contract HonestEarQuorum {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId; // pinned zk guest measurement
    bytes32 public immutable devicePubX; // pinned device endorsement key
    bytes32 public immutable devicePubY;

    event QuorumVerdict(uint32 indexed eventClass, uint32 presence);

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId, bytes32 _devX, bytes32 _devY) {
        verifier = _verifier;
        imageId = _imageId;
        devicePubX = _devX;
        devicePubY = _devY;
    }

    /// Verify both roots and require agreement. Reverts unless the zk receipt is
    /// valid for imageId, the device signature is a valid low-s P-256 signature by
    /// the pinned key over devicePayload, AND both report the same predicate.
    function verdict(
        bytes calldata zkSeal,
        bytes calldata zkJournal,
        bytes calldata devicePayload,
        bytes calldata deviceSig
    ) public view returns (uint32 eventClass, uint32 presence) {
        // Root 1: the ZK proof of the computation.
        verifier.verify(zkSeal, imageId, sha256(zkJournal));
        require(zkJournal.length == 24, "zk journal len");
        uint32 zkEvent = _u32le(zkJournal, 0);
        uint32 zkPresence = _u32le(zkJournal, 4);

        // Root 2: the device's hardware-bound P-256 signature over its payload.
        require(deviceSig.length == 64, "sig len");
        bytes32 r;
        bytes32 s;
        assembly {
            r := calldataload(deviceSig.offset)
            s := calldataload(add(deviceSig.offset, 32))
        }
        require(P256.verify(sha256(devicePayload), r, s, devicePubX, devicePubY), "device sig");
        (uint32 devEvent, uint32 devPresence) = _readVerdict(devicePayload);

        // Quorum: the two independent roots must agree on the predicate.
        require(zkEvent == devEvent && zkPresence == devPresence, "roots disagree");
        return (zkEvent, zkPresence);
    }

    /// Same as verdict(), but logs the agreed verdict for an indexer/L2.
    function recordVerdict(
        bytes calldata zkSeal,
        bytes calldata zkJournal,
        bytes calldata devicePayload,
        bytes calldata deviceSig
    ) external returns (uint32 eventClass, uint32 presence) {
        (eventClass, presence) = verdict(zkSeal, zkJournal, devicePayload, deviceSig);
        emit QuorumVerdict(eventClass, presence);
    }

    function _u32le(bytes calldata b, uint256 o) private pure returns (uint32) {
        return uint32(uint8(b[o])) | (uint32(uint8(b[o + 1])) << 8) | (uint32(uint8(b[o + 2])) << 16)
            | (uint32(uint8(b[o + 3])) << 24);
    }

    /// Minimal reader for the deterministic-CBOR he_payload: pull event (key 2)
    /// and presence (key 4) out of the map without a full CBOR library. Handles
    /// small uints, 1/2-byte uints, bool, and byte strings — the only value types
    /// the payload uses (see src/common/he_payload.h).
    function _readVerdict(bytes calldata p) private pure returns (uint32 ev, uint32 pres) {
        require(uint8(p[0]) == 0xa9, "not a 9-map"); // CBOR map of 9 pairs
        uint256 i = 1;
        bool haveEv;
        bool havePres;
        while (i < p.length && !(haveEv && havePres)) {
            uint8 key = uint8(p[i]); // keys are small uints 0x00..0x08 (one byte)
            i += 1;
            (uint64 v, uint256 ni) = _val(p, i);
            i = ni;
            if (key == 2) {
                ev = uint32(v);
                haveEv = true;
            } else if (key == 4) {
                pres = uint32(v);
                havePres = true;
            }
        }
        require(haveEv && havePres, "verdict fields missing");
    }

    /// Decode one CBOR value at offset i; return its (uint-ish) value and the
    /// index just past it. Booleans map to 0/1; byte strings return 0 (skipped).
    function _val(bytes calldata p, uint256 i) private pure returns (uint64 v, uint256 next) {
        uint8 b = uint8(p[i]);
        if (b <= 0x17) return (b, i + 1); // uint, inline
        if (b == 0x18) return (uint8(p[i + 1]), i + 2); // uint, 1 byte
        if (b == 0x19) return ((uint64(uint8(p[i + 1])) << 8) | uint8(p[i + 2]), i + 3); // uint, 2 bytes
        if (b == 0xf4) return (0, i + 1); // false
        if (b == 0xf5) return (1, i + 1); // true
        if (b >= 0x40 && b <= 0x57) return (0, i + 1 + (uint64(b) - 0x40)); // bstr, inline len
        if (b == 0x58) return (0, i + 2 + uint8(p[i + 1])); // bstr, 1-byte len
        revert("unsupported cbor");
    }
}
