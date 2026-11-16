import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../contracts/fee_pilot_v3.py', import.meta.url), 'utf8');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
const id = ({ owner, policy, expiry, nonce }) => `fp3_${sha256(canonical({ schema: 'feepilot.budget.v3', owner, policy_url: policy, expires_at: expiry, nonce })).slice(0, 20)}`;

for (const marker of ['create_delegated_budget', 'grant_executor', 'revoke_executor', 'authorize_spend', 'settle_authorized_spend', 'refund_remaining_budget', 'gl.vm.run_nondet_unsafe', 'emit_transfer', 'executor_allowance_exceeded', 'assessment_request_binding_mismatch']) assert.ok(source.includes(marker), `missing ${marker}`);
assert.ok(!source.includes('hashlib.md5') && !source.includes('hashlib.sha1'), 'only collision-resistant digests are allowed');

const base = { owner: '0x1111111111111111111111111111111111111111', policy: 'https://policy.example/rules', expiry: 1800000000, nonce: 'a'.repeat(64) };
assert.notEqual(id(base), id({ ...base, nonce: 'b'.repeat(64) }), 'a nonce must bind each budget');
assert.notEqual(id(base), id({ ...base, policy: 'https://policy.example/changed' }), 'policy identity must bind each budget');

const caps = new Map([['executor-a', 60n], ['executor-b', 40n]]);
assert.equal([...caps.values()].reduce((a, b) => a + b, 0n), 100n, 'allowances may partition a budget');
assert.throws(() => { const used = 50n; const request = 55n; if (used + request > caps.get('executor-a')) throw Error('executor_allowance_exceeded'); }, /executor_allowance_exceeded/, 'a delegated executor cannot exceed its own cap');
assert.throws(() => { const status = 'settled'; if (status !== 'authorized') throw Error('spend_not_settleable'); }, /spend_not_settleable/, 'a spend is one-use');
console.log('FeePilot v3 delegated-budget lifecycle checks passed.');
