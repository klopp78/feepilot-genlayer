import fs from 'node:fs';
const site = fs.readFileSync('docs/index.html', 'utf8');
const adapter = fs.readFileSync('docs/genlayer-adapter.js', 'utf8');
const profile = JSON.parse(fs.readFileSync('docs/fee-profile.json', 'utf8'));
const required = ['FeePilotAdapter', 'fee-profile.json', 'estimateTransactionFeesForWrite', 'writeContract', 'waitForFinalization', 'isSuccessful', 'TransactionHashVariant.LATEST_FINAL', 'Finalized and re-read'];
const missing = required.filter(value => !(site + adapter).includes(value));
if (missing.length || /ethers@|new ethers|BrowserProvider/.test(site) || Object.keys(profile.actions).length !== 4) throw Error(`FeePilot v2 fee/finality controls missing: ${missing.join(', ')}`);
console.log('FeePilot v2 fee-profile and consensus-finality checks passed.');
