import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Exercise the real page event handlers with a minimal DOM and an in-memory API.
class Element {
  constructor(text = '', value = '') {
    this.textContent = text;
    this.value = value;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.events = {};
    this.classList = { add() {}, remove() {} };
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this[key] = value; }
  removeAttribute(key) { delete this[key]; }
  addEventListener(key, callback) { this.events[key] = callback; }
  focus() {}
  close() { this.open = false; }
}
const nodes = new Map();
const node = selector => {
  if (!nodes.has(selector)) nodes.set(selector, new Element());
  return nodes.get(selector);
};
node('#chart-scope').value = 'all';
node('#risk-basis').value = 'files';
node('#risk-filter').value = 'ALL';
const storage = new Map();
globalThis.document = {
  querySelector: node, querySelectorAll: () => [],
  createElement: () => new Element(), createElementNS: () => new Element(),
  createTextNode: text => new Element(text), addEventListener() {},
};
globalThis.window = {
  localStorage: { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) },
  addEventListener() {}, scrollTo() {},
};
globalThis.location = { hash: '#/inputs' };
globalThis.history = { replaceState() {} };
globalThis.Option = Element;
const sample = { id: 'sample', name: 'Sample workspace', kind: 'sample', status: 'ready', reports: {} };
const database = new Map([
  ['sample', sample],
  ['old-files', { id: 'old-files', name: 'original.py', kind: 'files', files: [{ name: 'original.py', size: 4 }], status: 'ready', reports: {} }],
  ['old-repo', { id: 'old-repo', name: 'team/original', kind: 'repository', url: 'https://github.com/team/original.git', status: 'ready', reports: {} }],
]);
const calls = [];
let pendingList;
let delayList = false;
let pendingSubmission;
let delaySubmission = false;
let omitSample = false;
let failList = false;
globalThis.fetch = async (url, options = {}) => {
  calls.push({ url, method: options.method || 'GET' });
  assert.notEqual(options.method, 'DELETE', 'Frontend removal must never call the deletion API');
  if (url === '/api/sources' && options.method === 'POST') {
    const body = JSON.parse(options.body);
    const source = { id: body.clientSourceId + '-server', name: 'team/new', kind: 'repository', url: body.repositoryUrl, status: 'ready', reports: {} };
    database.set(source.id, source);
    if (delaySubmission) {
      delaySubmission = false;
      return new Promise(resolve => { pendingSubmission = () => resolve(Response.json(source)); });
    }
    return Response.json(source);
  }
  if (url === '/api/sources') {
    if (failList) throw new Error('Connection unavailable');
    const response = Response.json({ sources: [...database.values()].filter(source => !omitSample || source.kind !== 'sample') });
    if (delayList) {
      delayList = false;
      return new Promise(resolve => { pendingList = () => resolve(response); });
    }
    return response;
  }
  return Response.json(database.get(url.split('/').at(-1)));
};
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };
const rows = () => node('#source-list').children;
async function selectAccount(id) {
  node('#mock-account').value = id;
  node('#mock-account').events.change({ target: node('#mock-account') });
  await settle();
}
async function addRepository(url) {
  node('#repo-url').value = url;
  node('#repo-form').events.submit({ preventDefault() {} });
  await settle();
}

await import('./app.mjs');
await settle();
assert.equal(rows().length, 2, 'Pre-existing sources belong to the first account');
assert.equal(node('#workspace-source').value, 'old-files', 'Select the first real source');
assert.ok(!calls.some(call => call.url === '/api/sources/sample'), 'Never fetch the hidden sample report');
const beforeRemove = calls.length;
rows()[0].children[1].events.click();
assert.equal(rows().length, 1);
assert.equal(calls.length, beforeRemove, 'Individual removal makes no API request');
assert.equal(database.size, 3);

await selectAccount('sam');
assert.equal(rows().length, 0);
assert.equal(node('#remove-all-sources').disabled, true);
assert.equal(node('#workspace-source').disabled, true);
assert.equal(node('#export-report').disabled, true);
assert.equal(node('#chart-content').hidden, true);
assert.match(node('#source-status').textContent, /No sources yet/);
await addRepository('https://github.com/team/new');
assert.equal(rows().length, 1);
assert.equal(database.size, 4);

await selectAccount('alex');
assert.equal(rows().length, 1, 'Sam’s repository never appears for Alex');
const beforeRemoveAll = calls.length;
node('#remove-all-sources').events.click();
assert.equal(rows().length, 0);
assert.equal(calls.length, beforeRemoveAll, 'Remove all makes no API request');
assert.equal(database.size, 4, 'Every database record remains after removing all');
assert.equal(node('#workspace-source').value, '');
assert.equal(node('#remove-source').disabled, true);
assert.equal(node('#export-report').disabled, true);
await selectAccount('sam');
assert.equal(rows().length, 1, 'Removing Alex’s sources leaves Sam’s source visible');

// A stale list response cannot replace the next account’s workspace.
delayList = true;
await selectAccount('alex');
await selectAccount('sam');
pendingList();
await settle();
assert.equal(node('#mock-account').value, 'sam');
assert.equal(rows().length, 1);

// Remove before a submission responds, then switch away and back.
delaySubmission = true;
await addRepository('https://github.com/team/pending');
assert.equal(rows().length, 2);
rows()[1].children[1].events.click();
await selectAccount('alex');
assert.equal(rows().length, 0, 'An unacknowledged new source must not be mistaken for a pre-existing source');
await selectAccount('jordan');
pendingSubmission();
await settle();
assert.equal(rows().length, 0);
await selectAccount('sam');
assert.equal(rows().length, 1, 'Removed pending source stays hidden after the server assigns its ID');
assert.equal(database.size, 5);

// Loading and recovery work even if the backend no longer returns a sample source.
omitSample = true;
await selectAccount('jordan');
assert.equal(rows().length, 0);
assert.equal(node('#file-input').disabled, false);
assert.equal(node('#sources-empty').hidden, false);
failList = true;
await selectAccount('alex');
assert.match(node('#source-status').textContent, /Connection unavailable/);
assert.equal(node('#retry-source').hidden, false);
failList = false;
await node('#retry-source').events.click();
await settle();
assert.match(node('#source-status').textContent, /No sources yet/);
await selectAccount('sam');
assert.equal(rows().length, 1);
assert.equal(node('#export-report').disabled, false);

const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
for (const id of ['mock-account', 'remove-all-sources', 'workspace-owner']) assert.ok(html.includes(`id="${id}"`));
assert.ok(!/Sample workspace|Sample report|sample analysis|sample reports/.test(html));
console.log('Page checks passed: per-source removal, remove all, unchanged database, account switching, stale responses, and pending submissions.');
