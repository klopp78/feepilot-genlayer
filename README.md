# FeePilot for GenLayer

Studio deployment: [`0xb8478C9E03fa0D02D084E23CdE404933ae584ad1`](https://explorer-studio.genlayer.com/address/0xb8478C9E03fa0D02D084E23CdE404933ae584ad1)

FeePilot is a real, payable execution-budget contract for a named AI-agent executor. A wallet locks GEN, defines a canonical action and expiry, then requests a GenLayer consensus authorization built from independently rendered policy and evidence sources.

## Contract lifecycle

1. `create_budget` is payable and stores the owner, named executor, canonical action fields, reserve and expiry under a caller-generated one-time nonce.
2. `authorize_budget` renders the policy and evidence source inside a GenLayer consensus block. Validators receive the exact scope, executor, payload commitment and reserve they are approving; the agreed decision and source commitments are stored in an authorization record.
3. `settle_authorized_budget` can only be called once by the named executor while the authorization is approved and unexpired. It transfers the reserved GEN to that executor and persists a settlement receipt.
4. `cancel_budget` refunds an open or denied budget to its owner, or lets anyone recover it after expiry.

FeePilot deliberately does not present an arbitrary external purchase as verified. The value transfer it records is the contract's own on-chain fee-reserve settlement.

## Test

Run `npm test` to check the lifecycle controls plus concurrent-create and canonical-action bindings. For a live test, deploy `contracts/fee_pilot.py` in Studio or Bradbury, create a small budget, then use the pre-read nonce-derived ID to read the exact persisted record after finality.

## Frontend

`docs/index.html` is a wallet-connected interface. It pre-reads the exact caller-bound budget ID, waits for final receipts, and reads that matching contract record after every state-changing action; it never relies on a global latest-budget record. Set the deployed contract address in the upper-right field before use.
