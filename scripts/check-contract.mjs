import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../contracts/fee_pilot.py', import.meta.url), 'utf8');
const required = [
  '@gl.public.write.payable', 'create_budget', 'authorize_budget', 'settle_authorized_budget',
  'cancel_budget', 'gl.vm.run_nondet_unsafe', 'gl.nondet.web.render', 'emit_transfer',
  'only_named_executor_can_settle', 'authorization_binding_mismatch', 'budget_expired',
  'canonical_action', 'action_hash', 'policy_snapshot_hash', 'evidence_snapshot_hash'
];
for (const marker of required) {
  if (!source.includes(marker)) throw new Error(`Missing required FeePilot lifecycle marker: ${marker}`);
}
if (source.includes('hashlib.md5') || source.includes('hashlib.sha1')) throw new Error('Weak hash forbidden');
console.log('FeePilot contract structure checks passed.');
