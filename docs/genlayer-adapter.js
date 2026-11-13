import { createClient, isSuccessful } from 'https://esm.sh/genlayer-js@2.0.0-rc.2?bundle';
import { studionet } from 'https://esm.sh/genlayer-js@2.0.0-rc.2/chains?bundle';
import { TransactionHashVariant } from 'https://esm.sh/genlayer-js@2.0.0-rc.2/types?bundle';

export class FeePilotAdapter {
  constructor(address, provider, policy) { this.address = address; this.provider = provider; this.policy = policy; this.reader = createClient({ chain: studionet }); }
  async connect() { if (!this.provider) throw Error('A GenLayer-compatible wallet is required.'); const accounts = await this.provider.request({ method: 'eth_requestAccounts' }); this.account = accounts?.[0]; if (!this.account) throw Error('No wallet account was selected.'); this.writer = createClient({ chain: studionet, account: this.account, provider: this.provider }); await this.writer.connect('studionet'); return this.account; }
  async read(functionName, args = []) { return this.reader.readContract({ address: this.address, functionName, args, transactionHashVariant: TransactionHashVariant.LATEST_FINAL }); }
  async write(functionName, args, options = {}) { if (!this.writer) throw Error('Connect a wallet first.'); if (!this.policy.actions[functionName]) throw Error('This action is not covered by the checked-in fee policy.'); const call = { address: this.address, functionName, args, ...options }; const fee = await this.writer.estimateTransactionFeesForWrite(call); const hash = await this.writer.writeContract({ ...call, fees: { distribution: fee.distribution, feeValue: fee.feeValue } }); const final = await this.writer.waitForFinalization({ hash }); if (!isSuccessful(final)) throw Error('GenLayer consensus did not finalize successfully.'); return { hash, fee: { feeValue: String(fee.feeValue), distribution: fee.distribution } }; }
}
