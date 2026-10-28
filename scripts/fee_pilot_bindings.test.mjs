import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
const parts = values => sha256(values.map(value => `${String(value).length}:${value}`).join(''));

function action({ owner, executor, scope, payload, policy }) {
  return {
    action_payload_hash: payload,
    action_scope: scope.trim().replace(/\s+/g, ' '),
    executor: executor.toLowerCase(),
    owner: owner.toLowerCase(),
    policy_url: policy,
    schema: 'feepilot.action.v2',
  };
}

function budgetId(input) {
  return `fpb_${parts(['feepilot.budget.v2', canonical(action(input)), String(input.reserveWei), String(input.expiresAt), input.nonce]).slice(0, 20)}`;
}

const base = {
  owner: '0x1111111111111111111111111111111111111111',
  executor: '0x2222222222222222222222222222222222222222',
  scope: 'agent: submit approved invoice',
  payload: 'a'.repeat(64),
  policy: 'https://policy.example/rules',
  reserveWei: 100000000000000000n,
  expiresAt: 1800000000,
};

// Two wallets can create simultaneously without a global latest-ID race.
const concurrent = [
  { ...base, nonce: '1'.repeat(64) },
  { ...base, owner: '0x3333333333333333333333333333333333333333', nonce: '2'.repeat(64) },
];
const predicted = concurrent.map(budgetId);
assert.equal(new Set(predicted).size, 2, 'caller-bound nonces must produce distinct IDs under concurrent creates');
assert.equal(predicted[0], budgetId(concurrent[0]), 'the pre-read ID must equal the created record ID');

// Every field validators receive is commitment-sensitive.
for (const field of ['scope', 'executor', 'payload', 'reserveWei']) {
  const changed = { ...concurrent[0], [field]: field === 'reserveWei' ? 2n : `${concurrent[0][field]}-changed` };
  assert.notEqual(budgetId(concurrent[0]), budgetId(changed), `${field} must change the budget binding`);
}

console.log('FeePilot v2 concurrent-create and canonical-action binding tests passed.');
