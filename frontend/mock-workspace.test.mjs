import assert from 'node:assert/strict';
import { createMockWorkspace } from './mock-workspace.mjs';
import { analyzeSource } from './source-api.mjs';

const data = new Map();
const storage = { getItem: key => data.get(key) ?? null, setItem: (key, value) => data.set(key, value) };
const workspace = createMockWorkspace(storage);
const sample = { id: 'sample', kind: 'sample' };
const existing = { id: 'existing-repo', serverId: 'existing-repo', kind: 'repository' };
assert.deepEqual(workspace.visible([sample, existing]), [existing]);
workspace.select('sam');
assert.deepEqual(workspace.visible([sample, existing]), []);

// A source belongs to its submitting account, even if the server responds after switching accounts.
const pending = { id: 'client-sam', kind: 'repository', url: 'https://github.com/team/repo.git' };
workspace.remember(pending);
const originalFetch = globalThis.fetch;
try {
  let respond;
  let calls = 0;
  globalThis.fetch = async (_, options) => {
    calls++;
    assert.equal(options.method, 'POST');
    return new Promise(resolve => { respond = resolve; });
  };
  const analysis = analyzeSource(pending, () => {
    workspace.remember(pending, 'sam');
    if (pending.serverId) pending.controller.abort();
  });
  workspace.hide(pending);
  workspace.select('jordan');
  respond(Response.json({ id: 'server-sam', status: 'processing' }));
  await analysis;
  assert.equal(calls, 1, 'Removing a submitting source must not send a deletion or start polling');
  const saved = { id: 'server-sam', serverId: 'server-sam', kind: 'repository' };
  assert.deepEqual(workspace.visible([sample, existing, saved]), []);
  const reloaded = createMockWorkspace(storage);
  assert.equal(reloaded.account.id, 'jordan');
  reloaded.select('sam');
  assert.deepEqual(reloaded.visible([sample, existing, saved]), [], 'Removal survives reload');
  reloaded.select('alex');
  assert.deepEqual(reloaded.visible([sample, existing, saved]), [existing], 'Ownership remains after removal');

  const alexSource = { id: 'alex-upload', serverId: 'alex-upload', kind: 'files' };
  reloaded.remember(alexSource);
  const anotherTab = createMockWorkspace(storage);
  anotherTab.hide(alexSource);
  reloaded.remember(alexSource);
  assert.deepEqual(reloaded.visible([sample, alexSource]), [], 'Polling cannot undo removal from another tab');
  reloaded.hide(sample);
  assert.deepEqual(reloaded.visible([sample]), [], 'The backend sample remains hidden');
} finally {
  globalThis.fetch = originalFetch;
}

const blocked = createMockWorkspace({ getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } });
const local = { id: 'local', kind: 'files' };
blocked.remember(local);
blocked.select('sam');
assert.deepEqual(blocked.visible([sample, local]), []);
blocked.select('alex');
assert.deepEqual(blocked.visible([sample, local]), [local]);
blocked.hide(local);
assert.deepEqual(blocked.visible([sample, local]), []);
console.log('Mock workspace checks passed: account ownership, existing-source assignment, reload, pending removal, cross-tab removal, and blocked storage.');
