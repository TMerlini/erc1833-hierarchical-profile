// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title HierarchicalBudgetPerLeaf — a per-leaf-storage variant of blockbird's
///        Hierarchical Budget Substrate Profile for ERC-1833.
///
/// Same MIRROR model (static capabilityRoot of `{scopeId, subCap, asset}` leaves; spend metered per
/// leaf). The diff is purely *where spend lives* — and it falls out of the specialized-MCP-agent need
/// for concurrent draws across scopes. Posted alongside the gist so the two can be diffed directly.
///
/// DIFF vs the single-mutable-`cursorRoot` mirror:
///  1. The witness carries **no `leafSpent` and no `cursorProof`** — it binds to `(id, scopeId,
///     receiptId, amount)` and the gate reads spent ON-CHAIN. So a verdict survives concurrent advances
///     to *other* leaves (it isn't pinned to one global cursor snapshot).
///  2. Spend lives **per-leaf** (`_spent[id][scopeId]`, a slot per scope), not in one mutated root — so
///     advances on different scopes don't invalidate each other (no stale-proof reverts; submit N draws
///     without rebuilding a proof between them).
///  3. Nullifier is the v2 **draw/settle split**, per leaf: `keccak(id, scopeId, receiptId, "draw")`
///     (the escrow nullifies `keccak(receiptId, "settle")` in the same namespaced registry).
///  4. Only `capabilityRoot` is a maintained tree (static, OZ sorted-pair). `getCursor()` is a derived
///     history accumulator — per-leaf spend is the *gating* state and is recomputable from `LeafAdvanced`.
///
/// What stays identical to the gist: the leaf hash `keccak(scopeId, subCap, asset)`, capabilityRoot
/// commits to the ERC-8001 agreementHash, the witness is the same ERC-8274 verdict the escrow consumes,
/// and the gate is multi-condition (valid ∧ matches ∧ in-root ∧ within-subcap ∧ unspent) — never on
/// `valid` alone, replay-nullified.

interface IBoundedAgentAction {
    event EnvelopeAdvanced(bytes32 indexed id, bytes32 prevCursor, bytes32 newCursor);
    function getCursor(bytes32 id) external view returns (bytes32 cursorRoot);
    function advanceCursor(bytes32 id, bytes calldata witness) external;
}

/// ERC-8274 verifier — our deployed BIP340Verifier implements exactly this.
interface IReceiptVerifier {
    function verify(bytes32 expectArtifactHash, bytes calldata receiptProof)
        external view returns (bool valid, bool artifactHashMatches);
}

contract HierarchicalBudgetPerLeaf is IBoundedAgentAction {
    struct Leaf { bytes32 scopeId; uint256 subCap; address asset; }

    /// No `leafSpent`, no `cursorProof` — bound to (id, scopeId, receiptId, amount), gate reads spent.
    struct AdvanceWitness {
        Leaf      leaf;
        bytes32[] capProof;     // membership of leaf in the STATIC capabilityRoot
        uint256   amount;
        bytes32   receiptId;    // the ERC-8274 verdict's receipt id (per action)
        bytes     receiptProof; // ERC-8274 verdict (packReceiptProof bytes)
    }

    IReceiptVerifier public immutable verifier;                 // ERC-8274
    mapping(bytes32 => bytes32) public capabilityRoot;          // id => static merkle{leafHash} (== 8001 agreementHash)
    mapping(bytes32 => bytes32) private _cursor;                // id => derived history accumulator
    mapping(bytes32 => mapping(bytes32 => uint256)) private _spent; // id => scopeId => spent  (PER-LEAF slots)
    mapping(bytes32 => bool) public nullified;                  // namespaced draw/settle keys

    event LeafAdvanced(bytes32 indexed id, bytes32 indexed scopeId, uint256 newSpent, bytes32 receiptId, uint256 amount);

    error AlreadyRegistered();
    error WitnessInvalid();
    error ArtifactMismatch();
    error Replay();
    error LeafNotInRoot();
    error ExceedsSubCap();

    constructor(IReceiptVerifier verifier_) { verifier = verifier_; }

    /// ⚠️ LAYER-1 SEAM (TODO, babyblueviper1) — NOT load-bearing yet. `capRoot` MUST equal the agreementHash
    /// of an *accepted* ERC-8001 mandate the registrant can prove, bound to its ERC-8004 identity. This stub
    /// is permissionless and takes the root ON FAITH — so anyone can `register(id, anyRoot)` and bounded
    /// authority would be self-asserted, a hole in the no-trusted-party property at layer 1. Authenticating
    /// the id<->capRoot binding to the 8001 acceptance is the layer-1 seam onto the witness; do not use as-is.
    function register(bytes32 id, bytes32 capRoot) external {
        if (capabilityRoot[id] != bytes32(0)) revert AlreadyRegistered();
        capabilityRoot[id] = capRoot; // TODO(layer-1): require proof capRoot == accepted 8001 agreementHash (8004-bound)
    }

    function advanceCursor(bytes32 id, bytes calldata witnessBytes) external override {
        AdvanceWitness memory w = abi.decode(witnessBytes, (AdvanceWitness));

        // Cheap reads first, the BIP-340 verify last — all checks are reads, effects are at the end (CEI),
        // so a failed draw never pays for a verify. Order: draw-once -> cap membership -> headroom -> verdict.

        // (1) DRAW-ONCE — per-leaf, namespaced (settlement uses keccak(receiptId,"settle") in the same registry).
        bytes32 drawKey = keccak256(abi.encode(id, w.leaf.scopeId, w.receiptId, "draw"));
        if (nullified[drawKey]) revert Replay();

        // (2) CAP MEMBERSHIP — static tree only.
        if (!_inRoot(_leafHash(w.leaf), w.capProof, capabilityRoot[id])) revert LeafNotInRoot();

        // (3) HEADROOM — current spent read ON-CHAIN from the per-leaf slot (no caller proof, no global root).
        uint256 spent = _spent[id][w.leaf.scopeId];
        if (spent + w.amount > w.leaf.subCap) revert ExceedsSubCap();

        // (4) AUTHORIZATION (last — the only expensive check) — ERC-8274 verdict bound to THIS draw,
        //     recomputed against the OCP/8281 commitment (no private store, no trusted issuer).
        bytes32 actionHash = keccak256(abi.encode(id, w.leaf.scopeId, w.receiptId, w.amount));
        (bool valid, bool matches) = verifier.verify(actionHash, w.receiptProof);
        if (!valid) revert WitnessInvalid();
        if (!matches) revert ArtifactMismatch();

        // --- effects (CEI): per-leaf slot + nullifier + derived accumulator ---
        uint256 newSpent = spent + w.amount;
        _spent[id][w.leaf.scopeId] = newSpent;
        nullified[drawKey] = true;
        bytes32 prev = _cursor[id];
        bytes32 next = keccak256(abi.encode(prev, w.leaf.scopeId, newSpent, w.receiptId));
        _cursor[id] = next;
        emit LeafAdvanced(id, w.leaf.scopeId, newSpent, w.receiptId, w.amount);
        emit EnvelopeAdvanced(id, prev, next);
    }

    // --- views: per-leaf spend is the gating state, recomputable from LeafAdvanced events ---

    /// NON-AUTHORITATIVE history view. `_cursor = keccak(prev, scopeId, newSpent, receiptId)` is order-dependent
    /// and exists only to give the 1833 base interface a `bytes32` handle. The authoritative, order-independent
    /// state is per-leaf `leafSpent` (recomputable from `LeafAdvanced`). Downstream MUST NOT treat the exact
    /// `getCursor` value as canonical — it's a history accumulator, not the budget.
    function getCursor(bytes32 id) external view override returns (bytes32) { return _cursor[id]; }
    function leafSpent(bytes32 id, bytes32 scopeId) external view returns (uint256) { return _spent[id][scopeId]; }
    function leafRemaining(bytes32 id, bytes32 scopeId, uint256 subCap) external view returns (uint256) {
        uint256 s = _spent[id][scopeId];
        return subCap > s ? subCap - s : 0;
    }

    function _leafHash(Leaf memory l) internal pure returns (bytes32) {
        return keccak256(abi.encode(l.scopeId, l.subCap, l.asset)); // identical to the gist's leafHash
    }

    /// OZ-style sorted-pair merkle proof — boring on purpose, recomputable off-chain.
    function _inRoot(bytes32 leaf, bytes32[] memory proof, bytes32 root) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h <= p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}
