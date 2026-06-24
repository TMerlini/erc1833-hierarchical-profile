// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HierarchicalBudgetPerLeaf, IReceiptVerifier} from "../src/HierarchicalBudgetPerLeaf.sol";

// Mock ERC-8274 verifier: receiptProof = abi.encode(bool valid, bytes32 artifactHash).
// (The real path — BIP340Verifier over a signed receipt — is proven in the recovery-escrow repo.)
contract MockVerifier is IReceiptVerifier {
    function verify(bytes32 expect, bytes calldata proof) external pure returns (bool, bool) {
        (bool v, bytes32 ah) = abi.decode(proof, (bool, bytes32));
        return (v, ah == expect);
    }
}

// Demonstrates the _verifyDraw seam (the GhostAgent-style override): swaps the binding to
// sha256(preimage) and requires the per-leaf pinned issuer be set — while the draw-once / membership /
// headroom gate stays byte-identical. Proves a verify leg slots in with NO change to the gate.
contract OverrideProfile is HierarchicalBudgetPerLeaf {
    constructor(IReceiptVerifier v) HierarchicalBudgetPerLeaf(v) {}
    function _verifyDraw(bytes32 id_, AdvanceWitness memory w)
        internal view override returns (bool valid, bool matches)
    {
        bytes32 artifact = sha256(abi.encode(id_, w.leaf.scopeId, w.receiptId, w.amount));
        (bool v, bytes32 ah) = abi.decode(w.receiptProof, (bool, bytes32));
        return (v && w.leaf.issuer != bytes32(0), ah == artifact); // issuer pinned per-leaf, recomputable
    }
}

contract HierarchicalBudgetPerLeafTest is Test {
    HierarchicalBudgetPerLeaf bud;
    bytes32 id = keccak256("job-1");
    bytes32 scopeA = keccak256("scope-A");
    bytes32 scopeB = keccak256("scope-B");
    uint256 constant CAP = 100;
    bytes32 issuer = keccak256("pinned-issuer"); // per-leaf authorizing key, committed into the leaf hash
    bytes32 leafA;
    bytes32 leafB;
    bytes32 root;

    function setUp() public {
        bud = new HierarchicalBudgetPerLeaf(new MockVerifier());
        leafA = keccak256(abi.encode(scopeA, CAP, address(0), issuer));
        leafB = keccak256(abi.encode(scopeB, CAP, address(0), issuer));
        root = leafA <= leafB ? keccak256(abi.encodePacked(leafA, leafB)) : keccak256(abi.encodePacked(leafB, leafA));
        bud.register(id, root);
    }

    // build a valid witness for (scope, amount, receiptId)
    function _w(bytes32 scope, uint256 amount, bytes32 receiptId, bool valid) internal view returns (bytes memory) {
        bytes32 actionHash = keccak256(abi.encode(id, scope, receiptId, amount));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = scope == scopeA ? leafB : leafA;
        HierarchicalBudgetPerLeaf.Leaf memory leaf =
            HierarchicalBudgetPerLeaf.Leaf({scopeId: scope, subCap: CAP, asset: address(0), issuer: issuer});
        HierarchicalBudgetPerLeaf.AdvanceWitness memory w = HierarchicalBudgetPerLeaf.AdvanceWitness({
            leaf: leaf, capProof: proof, amount: amount, receiptId: receiptId,
            receiptProof: abi.encode(valid, actionHash)
        });
        return abi.encode(w);
    }

    function test_advance_perLeaf() public {
        bud.advanceCursor(id, _w(scopeA, 30, keccak256("r1"), true));
        assertEq(bud.leafSpent(id, scopeA), 30);
    }

    // the headline: a draw on a DIFFERENT scope is independent — no cursor snapshot, no stale proof.
    function test_concurrentScopes_independent() public {
        bud.advanceCursor(id, _w(scopeA, 30, keccak256("r1"), true));
        bud.advanceCursor(id, _w(scopeB, 70, keccak256("r2"), true)); // no dependency on A's state
        assertEq(bud.leafSpent(id, scopeA), 30);
        assertEq(bud.leafSpent(id, scopeB), 70);
    }

    function test_drawOnce_nullified() public {
        bytes32 r = keccak256("r1");
        bud.advanceCursor(id, _w(scopeA, 30, r, true));
        vm.expectRevert(HierarchicalBudgetPerLeaf.Replay.selector);
        bud.advanceCursor(id, _w(scopeA, 30, r, true)); // same (id,scope,receiptId) → replay
    }

    function test_exceedsSubCap() public {
        bud.advanceCursor(id, _w(scopeA, 60, keccak256("r1"), true));
        vm.expectRevert(HierarchicalBudgetPerLeaf.ExceedsSubCap.selector);
        bud.advanceCursor(id, _w(scopeA, 50, keccak256("r2"), true)); // 60+50 > 100
    }

    function test_leafNotInRoot() public {
        // a leaf with a tampered subCap is not in capabilityRoot
        HierarchicalBudgetPerLeaf.Leaf memory bad =
            HierarchicalBudgetPerLeaf.Leaf({scopeId: scopeA, subCap: 999, asset: address(0), issuer: issuer});
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;
        bytes32 ah = keccak256(abi.encode(id, scopeA, keccak256("r1"), uint256(10)));
        HierarchicalBudgetPerLeaf.AdvanceWitness memory w = HierarchicalBudgetPerLeaf.AdvanceWitness({
            leaf: bad, capProof: proof, amount: 10, receiptId: keccak256("r1"),
            receiptProof: abi.encode(true, ah)
        });
        vm.expectRevert(HierarchicalBudgetPerLeaf.LeafNotInRoot.selector);
        bud.advanceCursor(id, abi.encode(w));
    }

    function test_neverOnValidAlone_invalidVerdict() public {
        vm.expectRevert(HierarchicalBudgetPerLeaf.WitnessInvalid.selector);
        bud.advanceCursor(id, _w(scopeA, 30, keccak256("r1"), false));
    }

    // the seam: a profile overriding ONLY _verifyDraw (sha256 binding + per-leaf pinned issuer) advances,
    // and the draw-once/membership/headroom gate still applies — proving the verify leg is swappable.
    function test_verifyDraw_override_seam() public {
        OverrideProfile op = new OverrideProfile(new MockVerifier());
        bytes32 oid = keccak256("ghost-job");
        bytes32 lh = keccak256(abi.encode(scopeA, CAP, address(0), issuer));
        op.register(oid, lh); // single-leaf tree: root == leaf
        bytes32 artifact = sha256(abi.encode(oid, scopeA, keccak256("g1"), uint256(40)));
        HierarchicalBudgetPerLeaf.Leaf memory leaf =
            HierarchicalBudgetPerLeaf.Leaf({scopeId: scopeA, subCap: CAP, asset: address(0), issuer: issuer});
        HierarchicalBudgetPerLeaf.AdvanceWitness memory w = HierarchicalBudgetPerLeaf.AdvanceWitness({
            leaf: leaf, capProof: new bytes32[](0), amount: 40, receiptId: keccak256("g1"),
            receiptProof: abi.encode(true, artifact)
        });
        op.advanceCursor(oid, abi.encode(w));
        assertEq(op.leafSpent(oid, scopeA), 40);
        vm.expectRevert(HierarchicalBudgetPerLeaf.Replay.selector); // gate intact under the override
        op.advanceCursor(oid, abi.encode(w));
    }
}
