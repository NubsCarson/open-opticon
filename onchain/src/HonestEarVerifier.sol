// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

/// @title Honest Ear — permissionless on-chain verification of the detector.
///
/// Anyone can call checkVerdict() (or recordVerdict() to also log the fact)
/// with a RISC Zero receipt (seal + journal) and the contract confirms — with
/// no trust in any operator or enclave — that the *published* detector (pinned
/// by imageId) produced this verdict in zero knowledge of the audio, then
/// returns the proven predicate. This is the public-verifiability leg: the same
/// journal the off-chain quorum agrees on, checked by a stateless EVM contract
/// instead of a single verifier.
///
/// The journal is the guest's committed tuple of six little-endian u32s
/// (event, presence, voice_active, frames, active_frames, n_samples) followed by
/// sha256(nonce) and sha256(audio) (32 bytes each) that bind the proof to the
/// verifier's challenge and to the exact input; the audio itself is never in it.
/// The seal is a Groth16 proof produced by `he-zk-export` and encoded for
/// Ethereum. (HonestEarQuorum uses the two hashes; this wrapper exposes the
/// verdict.)
contract HonestEarVerifier {
    /// The RISC Zero Groth16 verifier (deployed separately, shared by all apps).
    IRiscZeroVerifier public immutable verifier;
    /// Measurement of the published detector guest — anyone can recompute it.
    bytes32 public immutable imageId;

    struct Verdict {
        uint32 eventClass; // 0=none, 1=voice, 2=alarm_tone
        uint32 presence;
        uint32 voiceActive;
        uint32 frames;
        uint32 activeFrames;
        uint32 nSamples;
    }

    /// Emitted when a verdict is verified on-chain (an auditable, anchored fact).
    event VerdictVerified(uint32 indexed eventClass, uint32 presence, uint32 frames);

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId) {
        verifier = _verifier;
        imageId = _imageId;
    }

    /// Verify a zk receipt of the published detector. Reverts if the proof is
    /// not valid for `imageId`. Pure check — no state, no permissions.
    function checkVerdict(bytes calldata seal, bytes calldata journal)
        public
        view
        returns (Verdict memory v)
    {
        // 6 verdict u32 (24) + sha256(nonce) (32) + sha256(audio) (32) = 88.
        require(journal.length == 88, "journal: 6 u32 + nonce hash + audio hash");
        verifier.verify(seal, imageId, sha256(journal));
        v.eventClass = _u32le(journal, 0);
        v.presence = _u32le(journal, 4);
        v.voiceActive = _u32le(journal, 8);
        v.frames = _u32le(journal, 12);
        v.activeFrames = _u32le(journal, 16);
        v.nSamples = _u32le(journal, 20);
    }

    /// Same check, but also logs the verdict so an indexer/L2 has an auditable
    /// record that the published detector produced a valid, ZK-proven verdict.
    function recordVerdict(bytes calldata seal, bytes calldata journal)
        external
        returns (Verdict memory v)
    {
        v = checkVerdict(seal, journal);
        emit VerdictVerified(v.eventClass, v.presence, v.frames);
    }

    /// Read a little-endian uint32 at byte offset `o` of a calldata journal.
    function _u32le(bytes calldata b, uint256 o) private pure returns (uint32) {
        return uint32(uint8(b[o])) | (uint32(uint8(b[o + 1])) << 8)
            | (uint32(uint8(b[o + 2])) << 16) | (uint32(uint8(b[o + 3])) << 24);
    }
}
