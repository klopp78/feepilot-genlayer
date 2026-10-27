# FeePilot for GenLayer

Studio deployment: [`0xb8478C9E03fa0D02D084E23CdE404933ae584ad1`](https://explorer-studio.genlayer.com/address/0xb8478C9E03fa0D02D084E23CdE404933ae584ad1)

FeePilot is a real, payable execution-budget contract for a named AI-agent executor. A wallet locks GEN, defines a canonical action and expiry, then requests a GenLayer consensus authorization built from independently rendered policy and evidence sources.

## Contract lifecycle

1. `create_budget` is payable and stores the owner, named executor, canonical action hash, reserve and expiry.
2. `authorize_budget` renders the policy and evidence source inside a GenLayer consensus block. The agreed decision and source commitments are stored in an authorization record.
3. `settle_authorized_budget` can only be called once by the named executor while the authorization is approved and unexpired. It transfers the reserved GEN to that executor and persists a settlement receipt.
4. `cancel_budget` refunds an open or denied budget to its owner, or lets anyone recover it after expiry.

FeePilot deliberately does not present an arbitrary external purchase as verified. The value transfer it records is the contract's own on-chain fee-reserve settlement.

## Test

Run `npm test` to check for the critical lifecycle and integrity controls in the submitted source. For a live test, deploy `contracts/fee_pilot.py` in Studio or Bradbury, create a small budget, then use the generated ID to read the persisted record after finality.

## Frontend

`docs/index.html` is a wallet-connected interface. It waits for final transaction receipts and reads the matching contract record after every state-changing action. Set the deployed contract address in the upper-right field before use.
