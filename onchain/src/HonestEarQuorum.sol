// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {P256} from "openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title Honest Ear — on-chain dual-root agreement (a both-required 2-of-2).
///
/// Returns a verdict ONLY if two INDEPENDENT roots both verify, are bound to the
/// SAME observation, and agree:
///   (1) a RISC Zero ZK proof of the published detector — no enclave trusted for
///       the math (Groth16); its journal commits sha256(nonce) and sha256(audio);
///   (2) the device's hardware-bound secp256r1 (P-256) signature over its
///       bound-output payload, which carries that same nonce and an input_hash
///       (= sha256(audio)) (OpenZeppelin P256).
/// The contract requires the zk journal's sha256(nonce) to equal sha256(the
/// device payload's nonce) AND the zk journal's sha256(audio) to equal the device
/// payload's input_hash, so the two proofs are CRYPTOGRAPHICALLY BOUND to the same
/// challenge AND the same input bytes — not merely matched on the predicate.
/// Combining a proof and a signature from different sessions OR different audio is
/// rejected, even against a misbehaving device. Both roots are mandatory (an AND,
/// i.e. 2-of-2) and must report the same predicate (event, presence, voice_active,
/// frames). The EVM can verify both proof systems, which the stdlib-only Go
/// verifier cannot (it can't verify a STARK), so this heterogeneous check lives
/// on-chain. One realisable leg of the broader "2-of-3" vision ({TEE, ZK, phone}).
///
/// Scope (honest): `recordVerdict` enforces ANTI-REPLAY via the device's
/// monotonic counter. Nonce FRESHNESS (that the challenge was issued recently and
/// once) remains an interactive/off-chain property (the Go verifier's gate 2);
/// the contract binds the two roots to *each other's* nonce, not to a
/// contract-issued challenge.
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
        uint256 nonceOffset; // byte offset of the nonce value in the payload
        uint256 nonceLen;
        bytes32 inputHash; // key 9: SHA-256 of the sensor input
    }

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId, bytes32 _devX, bytes32 _devY) {
        verifier = _verifier;
        imageId = _imageId;
        devicePubX = _devX;
        devicePubY = _devY;
    }

    /// Verify both roots, require they are bound to the same nonce, and require
    /// they agree on the full predicate. Reverts unless the zk receipt is valid
    /// for imageId, the device signature is a valid low-s P-256 signature by the
    /// pinned key over a v1 payload, the zk journal's sha256(nonce) equals
    /// sha256(the device payload's nonce), AND the predicates match. View: does
    /// not enforce anti-replay — see recordVerdict.
    function verdict(
        bytes calldata zkSeal,
        bytes calldata zkJournal,
        bytes calldata devicePayload,
        bytes calldata deviceSig
    ) public view returns (uint32 eventClass, uint32 presence) {
        // Root 1: the ZK proof of the computation. Journal = 6 verdict u32 (24)
        // + sha256(nonce) (32) + sha256(audio) (32) = 88.
        verifier.verify(zkSeal, imageId, sha256(zkJournal));
        require(zkJournal.length == 88, "zk journal len");
        uint32 zEvent = _u32le(zkJournal, 0);
        uint32 zPresence = _u32le(zkJournal, 4);
        uint32 zVoice = _u32le(zkJournal, 8);
        uint32 zFrames = _u32le(zkJournal, 12);
        bytes32 zkNonceHash;
        bytes32 zkAudioHash;
        assembly {
            zkNonceHash := calldataload(add(zkJournal.offset, 24))
            zkAudioHash := calldataload(add(zkJournal.offset, 56))
        }

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

        // Cross-root binding: both proofs must attest the same observation —
        // the same verifier challenge (nonce) AND the same input bytes (audio).
        bytes32 devNonceHash = sha256(devicePayload[d.nonceOffset:d.nonceOffset + d.nonceLen]);
        require(zkNonceHash == devNonceHash, "nonce mismatch (different sessions)");
        require(zkAudioHash == d.inputHash, "audio mismatch (different input)");

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
        // Bound below the type max so the contract can never store a counter of
        // type(uint64).max — a value that would make every future "counter >
        // lastCounter" impossible and brick recordVerdict. This is hygiene, NOT a
        // substitute for a non-public device key: with the Tier-1 shared QEMU key
        // anyone can mint counters (and could still advance lastCounter arbitrarily
        // high), so on-chain anti-replay is only meaningful once the device key is a
        // non-extractable per-device key (Tier 2). See THREAT_MODEL.
        require(counter < type(uint64).max, "counter at max");
        lastCounter = counter;
        emit QuorumVerdict(eventClass, presence, counter);
    }

    function _u32le(bytes calldata b, uint256 o) private pure returns (uint32) {
        return uint32(uint8(b[o])) | (uint32(uint8(b[o + 1])) << 8) | (uint32(uint8(b[o + 2])) << 16)
            | (uint32(uint8(b[o + 3])) << 24);
    }

    /// Decode the device fields from the deterministic-CBOR he_payload (see
    /// src/common/he_payload.h): version(0), nonce(1, located), event(2),
    /// voice(3), presence(4), frames(5), counter(7), input_hash(9). A minimal
    /// reader; it stops once those eight fields are seen, so the trailing
    /// prev_digest(10, the stream hash-chain link) is simply not read on-chain.
    function _readDevice(bytes calldata p) internal pure returns (Device memory d) {
        require(p.length > 0, "empty payload"); // else p[0] is an opaque OOB panic
        require(uint8(p[0]) == 0xab, "not an 11-map"); // CBOR map of 11 pairs
        uint256 i = 1;
        uint256 seen;
        uint256 prevKey;
        bool firstKey = true;
        // Walk pairs until the eight fields we need (keys 0,1,2,3,4,5,7,9) are read.
        // Enforce strictly-ascending integer keys (RFC 8949 deterministic CBOR), so
        // duplicate or out-of-order keys are rejected and the payload has exactly one
        // canonical encoding — matching he_payload.c and the Go reader, not merely
        // "some encoding that happens to carry these fields".
        while (i < p.length && seen != 0xff) {
            uint8 key = uint8(p[i]); // CBOR map has 11 fields (keys 0..10); we read the 8 we need
            if (firstKey) {
                firstKey = false;
            } else {
                require(key > prevKey, "cbor keys not ascending");
            }
            prevKey = key;
            i += 1;
            require(i < p.length, "value truncated"); // a key byte at the end -> opaque OOB; guards _val/_bstrSpan/_bstr32 (vstart == i)
            uint256 vstart = i;
            (uint64 v, uint256 ni) = _val(p, i);
            i = ni;
            if (key == 0) {
                d.version = uint32(v);
                seen |= 0x01;
            } else if (key == 1) {
                (d.nonceOffset, d.nonceLen) = _bstrSpan(p, vstart);
                seen |= 0x02;
            } else if (key == 2) {
                d.eventClass = uint32(v);
                seen |= 0x04;
            } else if (key == 3) {
                d.voiceActive = uint32(v);
                seen |= 0x08;
            } else if (key == 4) {
                d.presence = uint32(v);
                seen |= 0x10;
            } else if (key == 5) {
                d.frames = uint32(v);
                seen |= 0x20;
            } else if (key == 7) {
                d.counter = v;
                seen |= 0x40;
            } else if (key == 9) {
                d.inputHash = _bstr32(p, vstart);
                seen |= 0x80;
            }
        }
        require(seen == 0xff, "payload fields missing");
    }

    /// Locate a CBOR byte string's data: returns (offset, length) of the bytes.
    function _bstrSpan(bytes calldata p, uint256 i) internal pure returns (uint256 off, uint256 len) {
        uint8 b = uint8(p[i]);
        if (b >= 0x40 && b <= 0x57) {
            // inline length; bound the DATA so a truncated nonce reverts cleanly
            // instead of slicing adjacent (unsigned) calldata.
            uint256 n = uint256(b) - 0x40;
            require(i + 1 + n <= p.length, "nonce data truncated");
            return (i + 1, n);
        }
        if (b == 0x58) {
            // 1-byte length follows; bound the length byte AND the data it points to.
            require(i + 1 < p.length, "bstr len truncated");
            uint256 n = uint8(p[i + 1]);
            require(i + 2 + n <= p.length, "nonce data truncated");
            return (i + 2, n);
        }
        revert("nonce not a bstr");
    }

    /// Read a CBOR 32-byte byte string (0x58 0x20 || 32 bytes) as a bytes32.
    function _bstr32(bytes calldata p, uint256 i) internal pure returns (bytes32 h) {
        require(i + 1 < p.length, "bstr32 header truncated"); // before reading p[i+1]
        require(uint8(p[i]) == 0x58 && uint8(p[i + 1]) == 0x20, "input_hash not bstr32");
        // The 32 data bytes must lie inside the (signed) payload, so calldataload
        // can't pull adjacent, unsigned calldata: header 2 bytes + 32 data = 34.
        require(i + 34 <= p.length, "input_hash truncated");
        assembly {
            h := calldataload(add(p.offset, add(i, 2)))
        }
    }

    /// Decode one CBOR value at offset i; return its (uint-ish) value and the
    /// index just past it. Booleans map to 0/1; byte strings return 0 (skipped).
    /// Covers every value type the deterministic he_payload encoder can emit:
    /// uints (inline/1/2/4/8-byte), bool, and byte strings (inline/1-byte len).
    function _val(bytes calldata p, uint256 i) internal pure returns (uint64 v, uint256 next) {
        uint8 b = uint8(p[i]);
        if (b <= 0x17) return (b, i + 1); // uint, inline
        // Multi-byte heads read trailing bytes; bound each so a payload truncated
        // mid-value reverts with a clear reason rather than an opaque OOB panic.
        if (b == 0x18) {
            require(i + 1 < p.length, "cbor u8 truncated");
            return (uint8(p[i + 1]), i + 2); // uint, 1 byte
        }
        if (b == 0x19) {
            require(i + 2 < p.length, "cbor u16 truncated");
            return ((uint64(uint8(p[i + 1])) << 8) | uint8(p[i + 2]), i + 3); // uint, 2 bytes
        }
        if (b == 0x1a) {
            // uint, 4 bytes (big-endian)
            require(i + 4 < p.length, "cbor u32 truncated");
            return (
                (uint64(uint8(p[i + 1])) << 24) | (uint64(uint8(p[i + 2])) << 16)
                    | (uint64(uint8(p[i + 3])) << 8) | uint8(p[i + 4]),
                i + 5
            );
        }
        if (b == 0x1b) {
            // uint, 8 bytes (big-endian)
            require(i + 8 < p.length, "cbor u64 truncated");
            uint64 w;
            for (uint256 k = 1; k <= 8; k++) {
                w = (w << 8) | uint8(p[i + k]);
            }
            return (w, i + 9);
        }
        if (b == 0xf4) return (0, i + 1); // false
        if (b == 0xf5) return (1, i + 1); // true
        if (b >= 0x40 && b <= 0x57) {
            // bstr, inline len — bound the data so a mid-string truncation reverts.
            require(i + 1 + (uint256(b) - 0x40) <= p.length, "cbor bstr data truncated");
            return (0, i + 1 + (uint64(b) - 0x40));
        }
        if (b == 0x58) {
            require(i + 1 < p.length, "cbor bstr truncated");
            require(i + 2 + uint8(p[i + 1]) <= p.length, "cbor bstr data truncated");
            return (0, i + 2 + uint8(p[i + 1])); // bstr, 1-byte len
        }
        revert("unsupported cbor");
    }
}
