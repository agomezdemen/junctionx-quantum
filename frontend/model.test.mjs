import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseRepository, filterSessions, riskOf, formatBytes, authenticationRecorded, algorithmLabel } from './model.mjs';

assert.equal(parseRepository(' https://github.com/team/project/ ').url, 'https://github.com/team/project.git');
assert.equal(parseRepository('https://gitlab.com/group/subgroup/project.git').name, 'group/subgroup/project');
for (const url of ['garbage', 'http://github.com/team/project', 'https://github.com.evil.test/team/project', 'https://user:secret@github.com/team/project', 'https://github.com/team', 'https://github.com/team/project/tree/main', 'https://gitlab.com/team/project/-/tree/main', 'https://gitlab.com/team/project?token=secret', 'https://github.com/team/project#readme', 'https://github.com:8443/team/project']) {
  assert.throws(() => parseRepository(url), undefined, url);
}
const report = JSON.parse(await readFile(new URL('../pipeline/cbom_network_classified.json', import.meta.url), 'utf8'));
assert.equal(filterSessions(report.components, '', 'ALL').length, report.components.length);
assert.ok(filterSessions(report.components, 'ML-KEM', 'ALL').length > 0);
assert.ok(filterSessions(report.components, '', 'CRITICAL').every(c => c.risk === 'CRITICAL'));
assert.equal(filterSessions(report.components, 'no-such-session', 'ALL').length, 0);
assert.equal(riskOf({ risk: 'unrecognized' }), 'UNKNOWN');
assert.equal(riskOf(null), 'UNKNOWN');
for (const algorithm of [undefined, null, '', 'Not recorded', 'Negotiated separately', 'Not determined']) {
  assert.equal(authenticationRecorded({ algorithm }), false);
}
for (const algorithm of ['RSA', 'ECDSA', 'Unsupported signature', 'None']) {
  assert.equal(authenticationRecorded({ algorithm }), true);
}
assert.equal(authenticationRecorded(null), false);
assert.equal(algorithmLabel({ algorithm: 'AES', keySizeBits: 256, mode: 'GCM' }), 'AES · 256-bit · GCM');
assert.equal(algorithmLabel({ algorithm: 'ML-KEM', parameterSet: '768' }), 'ML-KEM · 768');
assert.equal(algorithmLabel(null), 'Not recorded');
assert.equal(formatBytes(0), '0 B');
assert.equal(formatBytes(1024), '1.0 KB');
console.log('Frontend checks passed: repository validation, report filtering, risk fallback, authentication availability, algorithm labels, and file sizes.');
