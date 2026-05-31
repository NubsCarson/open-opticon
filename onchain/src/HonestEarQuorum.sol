// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {P256} from "openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title Honest Ear — on-chain dual-root agreement (a both-required 2-of-2).
///
/// Returns a verdict ONLY if two INDEPENDENT roots both verify and agree:
///   (1) a RISC Zero ZK proof of the published detector — no enclave trusted for
///       the math (Groth16); and
///   (2) the device's hardware-bound secp256r1 (P-256) signature over its
///       bound-output payload — the attested device identity (OpenZeppelin P256).
/// Both are mandatory (an AND of two roots, i.e. 2-of-2), and they must report
/// the SAME predicate (event, presence, voice_active, frames). The EVM can verify
/// both proof systems — which the stdlib-only Go verifier cannot (it can't verify
/// a STARK) — so this heterogeneous check lives on-chain. A broken enclave OR a
/// forged signature alone fails. It is one realisable leg of the broader "2-of-3"
/// vision ({TEE, ZK, phone}); a third enrolled root would generalise it.
///
/// Scope (honest):
///   - `recordVerdict` enforces ANTI-REPLAY via the device's monotonic counter.
///   - Nonce FRESHNESS is an interactive/off-chain property (the Go verifier's
///     gate 2); it is not re-enforced here.
///   - The two roots are not yet *cryptographically* bound to the same audio
///     window — they are matched on the full predicate. A future guest that
///     commits a hash of its input (mirrored in the device payload) would bind
///     them cryptographically; that is the documented next step.
contract HonestEarQuorum {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId; // pinned zk guest measurement
    bytes32 public immutable devicePubX; // pinned device endorsement key
    bytes32 public immutable devicePubY;
    uint64 public lastCounter; // anti-replay: highest device counter recorded

    event QuorumVerdict(uint32 indexed eventClass, uint32 presence, uint64 counter);

    struct Device {
        uint32 version;
        uint32 eventClass;
        uint32 voiceActive;
        uint32 presence;
        uint32 frames;
        uint64 counter;
    }

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId, bytes32 _devX, bytes32 _devY) {
        verifier = _verifier;
        imageId = _imageId;
        devicePubX = _devX;
        devicePubY = _devY;
    }

    /// Verify both roots and require they agree on the full predicate. Reverts
    /// unless the zk receipt is valid for imageId, the device signature is a valid
    /// low-s P-256 signature by the pinned key over a v1 payload, AND the zk
    /// journal and the device payload report identical (event, presence,
    /// voice_active, frames). View: does not enforce anti-replay — see
    /// recordVerdict.
    function verdict(
        bytes calldata zkSeal,
        bytes calldata zkJournal,
        bytes calldata devicePayload,
        bytes calldata deviceSig
    ) public view returns (uint32 eventClass, uint32 presence) {
        // Root 1: the ZK proof of the computation.
        verifier.verify(zkSeal, imageId, sha256(zkJournal));
        require(zkJournal.length == 24, "zk journal len");
        uint32 zEvent = _u32le(zkJournal, 0);
        uint32 zPresence = _u32le(zkJournal, 4);
        uint32 zVoice = _u32le(zkJournal, 8);
        uint32 zFrames = _u32le(zkJournal, 12);

        // Root 2: the device's hardware-bound P-256 signature over its payload.
        require(deviceSig.length == 64, "sig len");
        bytes32 r;
        bytes32 s;
        assembly {
            r := calldataload(deviceSig.offset)
            s := calldataload(add(deviceSig.offset, 32))
        }
        require(P256.verify(sha256(devicePayload), r, s, devicePubX, devicePubY), "device sig");
        Device memory d = _readDevice(devicePayload);
        require(d.version == 1, "payload version");

        // 2-of-2: the two independent roots must agree on the full predicate.
        require(
            zEvent == d.eventClass && zPresence == d.presence && zVoice == d.voiceActive
                && zFrames == d.frames,
            "roots disagree"
        );
        return (zEvent, zPresence);
    }

    /// Same checks, plus on-chain anti-replay: the device counter must strictly
    /// exceed the highest already recorded. Logs the agreed verdict.
    function recordVerdict(
        bytes calldata zkSeal,
        bytes calldata zkJournal,
        bytes calldata devicePayload,
        bytes calldata deviceSig
    ) external returns (uint32 eventClass, uint32 presence) {
        (eventClass, presence) = verdict(zkSeal, zkJournal, devicePayload, deviceSig);
        uint64 counter = _readDevice(devicePayload).counter;
        require(counter > lastCounter, "counter must advance (anti-replay)");
        lastCounter = counter;
        emit QuorumVerdict(eventClass, presence, counter);
    }

    function _u32le(bytes calldata b, uint256 o) private pure returns (uint32) {
        return uint32(uint8(b[o])) | (uint32(uint8(b[o + 1])) << 8) | (uint32(uint8(b[o + 2])) << 16)
            | (uint32(uint8(b[o + 3])) << 24);
    }

    /// Decode the device verdict fields from the deterministic-CBOR he_payload
    /// (see src/common/he_payload.h): version(0), event(2), voice(3), presence(4),
    /// frames(5), counter(7). A minimal reader, not a full CBOR library.
    function _readDevice(bytes calldata p) private pure returns (Device memory d) {
        require(uint8(p[0]) == 0xa9, "not a 9-map"); // CBOR map of 9 pairs
        uint256 i = 1;
        uint256 seen;
        // Walk pairs until the six fields we need (keys 0,2,3,4,5,7) are read.
        while (i < p.length && seen != 0x3f) {
            uint8 key = uint8(p[i]); // keys are small uints 0x00..0x08 (one byte)
            i += 1;
            (uint64 v, uint256 ni) = _val(p, i);
            i = ni;
            if (key == 0) {
                d.version = uint32(v);
                seen |= 0x01;
            } else if (key == 2) {
                d.eventClass = uint32(v);
                seen |= 0x02;
            } else if (key == 3) {
                d.voiceActive = uint32(v);
                seen |= 0x04;
            } else if (key == 4) {
                d.presence = uint32(v);
                seen |= 0x08;
            } else if (key == 5) {
                d.frames = uint32(v);
                seen |= 0x10;
            } else if (key == 7) {
                d.counter = v;
                seen |= 0x20;
            }
        }
        require(seen == 0x3f, "payload fields missing");
    }

    /// Decode one CBOR value at offset i; return its (uint-ish) value and the
    /// index just past it. Booleans map to 0/1; byte strings return 0 (skipped).
    /// Covers every value type the deterministic he_payload encoder can emit:
    /// uints (inline/1/2/4/8-byte), bool, and byte strings (inline/1-byte len).
    function _val(bytes calldata p, uint256 i) private pure returns (uint64 v, uint256 next) {
        uint8 b = uint8(p[i]);
        if (b <= 0x17) return (b, i + 1); // uint, inline
        if (b == 0x18) return (uint8(p[i + 1]), i + 2); // uint, 1 byte
        if (b == 0x19) return ((uint64(uint8(p[i + 1])) << 8) | uint8(p[i + 2]), i + 3); // uint, 2 bytes
        if (b == 0x1a) {
            // uint, 4 bytes (big-endian)
            return (
                (uint64(uint8(p[i + 1])) << 24) | (uint64(uint8(p[i + 2])) << 16)
                    | (uint64(uint8(p[i + 3])) << 8) | uint8(p[i + 4]),
                i + 5
            );
        }
        if (b == 0x1b) {
            // uint, 8 bytes (big-endian)
            uint64 w;
            for (uint256 k = 1; k <= 8; k++) {
                w = (w << 8) | uint8(p[i + k]);
            }
            return (w, i + 9);
        }
        if (b == 0xf4) return (0, i + 1); // false
        if (b == 0xf5) return (1, i + 1); // true
        if (b >= 0x40 && b <= 0x57) return (0, i + 1 + (uint64(b) - 0x40)); // bstr, inline len
        if (b == 0x58) return (0, i + 2 + uint8(p[i + 1])); // bstr, 1-byte len
        revert("unsupported cbor");
    }
}
