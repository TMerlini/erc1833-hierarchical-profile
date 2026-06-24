# HierarchicalBudgetPerLeaf — a per-leaf-storage variant (ERC-1833 co-design)

A diff-companion to blockbird's *Hierarchical Budget Substrate Profile* gist. Same mirror model
(static `capabilityRoot` of `{scopeId, subCap, asset}` leaves), but spend lives **per-leaf** instead of
in one mutated `cursorRoot` — which falls out of the specialized-MCP-agent need for concurrent draws
across scopes. CC0. Compiles (solc 0.8.24), **6/6 forge tests**.

## The diff (vs the single-mutable-`cursorRoot` mirror)
1. The witness carries **no `leafSpent` and no `cursorProof`** — it binds to `(id, scopeId, receiptId,
   amount)` and the gate reads spent on-chain → a verdict survives concurrent advances to *other* leaves.
2. Spend lives **per-leaf** (`_spent[id][scopeId]`, a slot per scope), not one mutated root → advances on
   different scopes don't invalidate each other (no stale-proof reverts; submit N draws without rebuilding).
3. Nullifier = the v2 **draw/settle split**, per leaf: `keccak(id, scopeId, receiptId, "draw")` (the escrow
   nullifies `keccak(receiptId, "settle")` in the same namespaced registry).
4. Only `capabilityRoot` is a maintained tree (static, OZ sorted-pair). `getCursor()` is a derived history
   accumulator — per-leaf spend is the *gating* state and is recomputable from `LeafAdvanced` events.

**Identical to the gist:** leaf hash `keccak(scopeId, subCap, asset)`, `capabilityRoot` commits to the
ERC-8001 agreementHash, the witness is the same ERC-8274 verdict the recovery escrow already consumes, and
the gate is multi-condition (`valid ∧ matches ∧ in-root ∧ within-subcap ∧ unspent`) — never on `valid`
alone, replay-nullified.

## Tests (6/6 green)
- **`concurrentScopes_independent`** — the headline: a draw on a different scope is independent, no cursor snapshot.
- `drawOnce_nullified` · `exceedsSubCap` · `leafNotInRoot` · `neverOnValidAlone_invalidVerdict` · `advance_perLeaf`.

Run: `forge install foundry-rs/forge-std && forge test`.
