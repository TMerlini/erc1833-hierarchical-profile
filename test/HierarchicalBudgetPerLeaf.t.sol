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

contract HierarchicalBudgetPerLeafTest is Test {
    HierarchicalBudgetPerLeaf bud;
    bytes32 id = keccak256("job-1");
    bytes32 scopeA = keccak256("scope-A");
    bytes32 scopeB = keccak256("scope-B");
    uint256 constant CAP = 100;
    bytes32 leafA;
    bytes32 leafB;
    bytes32 root;

    function setUp() public {
        bud = new HierarchicalBudgetPerLeaf(new MockVerifier());
        leafA = keccak256(abi.encode(scopeA, CAP, address(0)));
        leafB = keccak256(abi.encode(scopeB, CAP, address(0)));
        root = leafA <= leafB ? keccak256(abi.encodePacked(leafA, leafB)) : keccak256(abi.encodePacked(leafB, leafA));
        bud.register(id, root);
    }

    // build a valid witness for (scope, amount, receiptId)
    function _w(bytes32 scope, uint256 amount, bytes32 receiptId, bool valid) internal view returns (bytes memory) {
        bytes32 actionHash = keccak256(abi.encode(id, scope, receiptId, amount));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = scope == scopeA ? leafB : leafA;
        HierarchicalBudgetPerLeaf.Leaf memory leaf =
            HierarchicalBudgetPerLeaf.Leaf({scopeId: scope, subCap: CAP, asset: address(0)});
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
            HierarchicalBudgetPerLeaf.Leaf({scopeId: scopeA, subCap: 999, asset: address(0)});
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
}
