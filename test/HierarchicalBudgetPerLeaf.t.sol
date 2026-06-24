// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HierarchicalBudgetPerLeaf, IReceiptVerifier, IAgreementRegistry} from "../src/HierarchicalBudgetPerLeaf.sol";

// Mock ERC-8274 verifier: receiptProof = abi.encode(bool valid, bytes32 artifactHash).
// (The real path — BIP340Verifier over a signed receipt — is proven in the recovery-escrow repo.)
contract MockVerifier is IReceiptVerifier {
    function verify(bytes32 expect, bytes calldata proof) external pure returns (bool, bool) {
        (bool v, bytes32 ah) = abi.decode(proof, (bool, bytes32));
        return (v, ah == expect);
    }
}

// Mock ERC-8001 registry: an acceptance binds an agreementHash -> (accepting agent, committed capRoot).
// (The real path is the ERC-8001 acceptance flow; injected so the check is recomputable, no baked issuer.)
contract MockAgreements is IAgreementRegistry {
    mapping(bytes32 => address) public agentOf;
    mapping(bytes32 => bytes32) public capRootOf;
    function setAcceptance(bytes32 agreementHash, address agent, bytes32 capRoot) external {
        agentOf[agreementHash] = agent;
        capRootOf[agreementHash] = capRoot;
    }
    function acceptance(bytes32 agreementHash) external view returns (address, bytes32) {
        return (agentOf[agreementHash], capRootOf[agreementHash]);
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
    MockAgreements agreements;
    bytes32 agreementHash = keccak256("agreement-1");

    function setUp() public {
        agreements = new MockAgreements();
        bud = new HierarchicalBudgetPerLeaf(new MockVerifier(), agreements);
        leafA = keccak256(abi.encode(scopeA, CAP, address(0)));
        leafB = keccak256(abi.encode(scopeB, CAP, address(0)));
        root = leafA <= leafB ? keccak256(abi.encodePacked(leafA, leafB)) : keccak256(abi.encodePacked(leafB, leafA));
        // this test contract is the accepting agent; the agreement commits to `root`.
        agreements.setAcceptance(agreementHash, address(this), root);
        bud.register(id, agreementHash);
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

    // --- layer-1 seam (issue #1): register() authenticates capRoot against the accepted 8001 mandate ---

    // capRoot is pulled FROM the accepted agreement, never asserted by the caller.
    function test_register_pullsCapRootFromAcceptedMandate() public {
        assertEq(bud.capabilityRoot(id), root); // == the agreement's committed capRoot, set in setUp
    }

    // an unaccepted agreement can't be registered — kills the permissionless self-assertion hole.
    function test_register_rejects_unacceptedMandate() public {
        vm.expectRevert(HierarchicalBudgetPerLeaf.AgreementNotAccepted.selector);
        bud.register(keccak256("job-2"), keccak256("never-accepted"));
    }

    // only the agent that accepted the mandate can register it (ERC-8004 binding).
    function test_register_rejects_wrongAgent() public {
        bytes32 ah = keccak256("agreement-2");
        agreements.setAcceptance(ah, address(0xBEEF), root); // accepted by someone else
        vm.expectRevert(HierarchicalBudgetPerLeaf.NotMandateAgent.selector);
        bud.register(keccak256("job-2"), ah); // caller (this) != 0xBEEF
    }

    // a caller can't smuggle a bigger budget: the cap comes from the agreement, not the call.
    function test_register_cannotAssertOwnCapRoot() public {
        bytes32 ah = keccak256("agreement-3");
        bytes32 realCap = keccak256("granted-small");
        agreements.setAcceptance(ah, address(this), realCap);
        bud.register(keccak256("job-3"), ah);
        assertEq(bud.capabilityRoot(keccak256("job-3")), realCap); // the granted root, nothing the caller chose
    }
}
