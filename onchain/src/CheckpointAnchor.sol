// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Honest Ear — on-chain anchor for the endorsement transparency log.
///
/// Anchors the log's signed checkpoints to an immutable public ledger so the log
/// operator cannot rewrite history or equivocate (present split views). Each new
/// checkpoint must be a proven append-only extension of the last: the contract
/// verifies an RFC 9162 consistency proof on-chain (SHA-256 precompile), so a
/// fork or rewrite is rejected — not merely a size rollback. This is a faithful
/// port of VerifyConsistency in src/verifier/transparency.go.
///
/// Scope (honest): the contract enforces *ordering + append-only consistency*.
/// The checkpoint's P-256 signature is recorded in the event for off-chain
/// authentication against the published log key; on-chain secp256r1 verification
/// (RIP-7212) is a possible upgrade, not done here.
contract CheckpointAnchor {
    uint256 public latestSize;
    bytes32 public latestRoot;

    event Anchored(uint256 indexed size, bytes32 root, bytes signature);

    /// Anchor a signed checkpoint. The first call (latestSize == 0) seeds the
    /// log; every later call must prove the new tree extends the anchored one.
    function anchor(uint256 size, bytes32 root, bytes32[] calldata proof, bytes calldata signature)
        external
    {
        require(size > latestSize, "size must strictly increase");
        if (latestSize != 0) {
            require(
                _verifyConsistency(latestSize, size, proof, latestRoot, root),
                "inconsistent: not an append-only extension"
            );
        }
        latestSize = size;
        latestRoot = root;
        emit Anchored(size, root, signature);
    }

    /// sha256(0x01 || l || r) — RFC 6962 interior node hash (precompile at 0x2).
    function _hashNode(bytes32 l, bytes32 r) private pure returns (bytes32) {
        return sha256(abi.encodePacked(uint8(1), l, r));
    }

    /// RFC 9162 §2.1.4.2 consistency-proof check; mirrors transparency.go.
    function _verifyConsistency(
        uint256 oldSize,
        uint256 newSize,
        bytes32[] calldata proof,
        bytes32 oldRoot,
        bytes32 newRoot
    ) private pure returns (bool) {
        if (newSize == 0 || oldSize > newSize) return false;
        if (oldSize == newSize) return proof.length == 0 && oldRoot == newRoot;
        if (oldSize == 0) return proof.length == 0;

        uint256 fn = oldSize - 1;
        uint256 sn = newSize - 1;
        while (fn & 1 == 1) {
            fn >>= 1;
            sn >>= 1;
        }

        bytes32 fr;
        bytes32 sr;
        uint256 idx;
        if (fn == 0) {
            fr = oldRoot;
            sr = oldRoot;
        } else {
            if (proof.length == 0) return false;
            fr = proof[0];
            sr = proof[0];
            idx = 1;
        }

        for (; idx < proof.length; idx++) {
            if (sn == 0) return false;
            bytes32 c = proof[idx];
            if (fn & 1 == 1 || fn == sn) {
                fr = _hashNode(c, fr);
                sr = _hashNode(c, sr);
                while (fn & 1 == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                sr = _hashNode(sr, c);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && fr == oldRoot && sr == newRoot;
    }
}
