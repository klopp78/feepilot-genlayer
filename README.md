# FeePilot for GenLayer

Studio v2 deployment: [`0xe260EACa724a50Ab58939438522393521D992829`](https://explorer-studio.genlayer.com/address/0xe260EACa724a50Ab58939438522393521D992829)

FeePilot is a real, payable execution-budget contract for a named AI-agent executor. A wallet locks GEN, defines a canonical action and expiry, then requests a GenLayer consensus authorization built from independently rendered policy and evidence sources.

## Contract lifecycle

1. `create_budget` is payable and stores the owner, named executor, canonical action fields, reserve and expiry under a caller-generated one-time nonce.
2. `authorize_budget` renders the policy and evidence source inside a GenLayer consensus block. Validators receive the exact scope, executor, payload commitment and reserve they are approving; the agreed decision and source commitments are stored in an authorization record.
3. `settle_authorized_budget` can only be called once by the named executor while the authorization is approved and unexpired. It transfers the reserved GEN to that executor and persists a settlement receipt.
4. `cancel_budget` refunds an open or denied budget to its owner, or lets anyone recover it after expiry.

FeePilot deliberately does not present an arbitrary external purchase as verified. The value transfer it records is the contract's own on-chain fee-reserve settlement.

## FeePilot v2 Milestone

FeePilot v2 adds a fee-aware browser execution layer rather than merely restyling the original application. The app now:

- loads the checked-in [`docs/fee-profile.json`](docs/fee-profile.json) to define every supported payable or consensus action;
- uses the repository-defined [`docs/genlayer-adapter.js`](docs/genlayer-adapter.js), powered by GenLayerJS rather than `ethers`;
- derives a fresh `estimateTransactionFeesForWrite` quote for the specific action, then submits that exact fee distribution;
- waits for `waitForFinalization`, checks `isSuccessful`, and reads the named budget from `TransactionHashVariant.LATEST_FINAL` before reporting success;
- exposes the transaction hash, estimated fee data, finality state, and final contract record as one receipt.

The profile is intentionally a policy and coverage artifact, not hard-coded fee math: Studio/network estimates are refreshed per transaction because consensus and web-assessment paths can vary.

## Test

Run `npm test` to check the lifecycle controls, concurrent-create bindings, and v2 fee-profile/finality integration. For a live test, deploy `contracts/fee_pilot.py` in Studio or Bradbury, create a small budget, then use the pre-read nonce-derived ID to read the exact persisted record after finality.

## Frontend

`docs/index.html` is a wallet-connected GenLayerJS interface. It pre-reads the exact caller-bound budget ID, requires a live fee estimate, waits for consensus finality, and reads that matching contract record after every state-changing action; it never relies on a global latest-budget record or an ordinary EVM receipt. Set the deployed Studio contract address in the upper-right field before use.
