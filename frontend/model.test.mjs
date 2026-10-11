import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseRepository, filterSessions, riskOf, formatBytes, authenticationRecorded, algorithmLabel, reportEntries, riskDistribution, algorithmCounts } from './model.mjs';

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
assert.equal(riskOf({ quantumRiskAssessment: { tier: 'Critical' } }), 'CRITICAL');
assert.equal(riskOf({ quantumRiskAssessment: { tier: 'Safe' } }), 'SAFE');
assert.equal(riskOf({ quantumRiskAssessment: { tier: 'Unexpected' } }), 'UNKNOWN');
assert.equal(riskOf({ risk: 'MEDIUM', quantumRiskAssessment: { tier: 'Critical' } }), 'MEDIUM');
for (const name of ['code', 'cloud']) {
  const scanner = JSON.parse(await readFile(new URL(`../pipeline/cbom_${name}.json`, import.meta.url), 'utf8'));
  const original = JSON.stringify(scanner);
  const critical = filterSessions(scanner.components, '', 'CRITICAL');
  assert.equal(critical.length, scanner.components.filter(c => c.quantumRiskAssessment.tier === 'Critical').length);
  assert.ok(critical.length > 0);
  assert.equal(JSON.stringify(scanner), original, 'Displaying scanner ratings must preserve the original report');
}
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

const reports = await Promise.all(['network_classified', 'code', 'cloud'].map(async name => JSON.parse(await readFile(new URL(`../pipeline/cbom_${name}.json`, import.meta.url), 'utf8'))));
const entries = reportEntries(reports);
assert.equal(entries.length, 88);
assert.deepEqual(riskDistribution(entries, 'findings'), { total: 88, omitted: 0, counts: { CRITICAL: 73, HIGH: 0, MEDIUM: 4, LOW: 0, SAFE: 11, UNKNOWN: 0 } });
assert.deepEqual(riskDistribution(entries, 'files'), { total: 12, omitted: 0, counts: { CRITICAL: 9, HIGH: 0, MEDIUM: 3, LOW: 0, SAFE: 0, UNKNOWN: 0 } });
assert.equal(algorithmCounts(entries, 'encryption').included, 58);
const exchanges = algorithmCounts(entries, 'keyExchange');
assert.equal(exchanges.included, 58);
assert.equal(exchanges.rows.find(([name]) => name.includes('ML-KEM'))[1], 7);
assert.equal(algorithmCounts(entries, 'other').included, 25);
assert.deepEqual(algorithmCounts([], 'encryption'), { included: 0, rows: [] });
assert.equal(riskDistribution([], 'files').total, 0);
const mixed = [
  { component: { risk: 'SAFE' }, source: './input_files/a.py' },
  { component: { risk: 'UNKNOWN' }, source: '../input_files/a.py' },
  { component: { risk: 'MEDIUM' }, source: 'input_files/a.py' },
  { component: { risk: 'SAFE' }, source: null },
];
assert.equal(riskDistribution(mixed, 'files').counts.UNKNOWN, 1);
assert.equal(riskDistribution(mixed, 'files').omitted, 1);
mixed.push({ component: { risk: 'CRITICAL' }, source: 'input_files/a.py' });
assert.equal(riskDistribution(mixed, 'files').counts.CRITICAL, 1);
console.log('Chart checks passed: file deduplication, risk precedence, missing sources, finding totals, algorithm counts, hybrid counting, and empty reports.');
