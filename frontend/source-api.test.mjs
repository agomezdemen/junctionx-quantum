import assert from 'node:assert/strict';
import { analyzeSource, listSources } from './source-api.mjs';

const originalFetch = globalThis.fetch;
try {
  const reports = { code: { components: [{ type: 'application-code', name: 'a.py:1', quantumRiskAssessment: { tier: 'Critical' } }] } };
  const repository = { id: 'client-a', kind: 'repository', url: 'https://github.com/team/project.git' };
  let calls = 0;
  globalThis.fetch = async (url, options) => {
    calls++;
    assert.equal(url, '/api/sources');
    assert.equal(options.method, 'POST');
    assert.deepEqual(JSON.parse(options.body), { clientSourceId: 'client-a', repositoryUrl: repository.url });
    return Response.json({ id: 'server-a', status: 'ready', reports });
  };
  const statuses = [];
  await analyzeSource(repository, () => statuses.push(repository.status));
  assert.equal(calls, 1);
  assert.deepEqual(statuses, ['processing', 'ready']);
  assert.deepEqual(repository.reports, reports);

  const files = { id: 'client-files', kind: 'files', files: [new File(['code'], 'a.py'), new File(['capture'], 'b.pcap')] };
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/sources');
    assert.equal(options.body.get('clientSourceId'), files.id);
    assert.deepEqual(options.body.getAll('files').map(file => file.name), ['a.py', 'b.pcap']);
    return new Response('', { status: 501 });
  };
  await analyzeSource(files, () => {});
  assert.equal(files.status, 'error');
  assert.match(files.message, /backend is not connected/);
  assert.equal(files.reports, undefined);

  globalThis.fetch = async url => {
    assert.equal(url, '/api/sources/server-a');
    return Response.json({ id: 'wrong-source', status: 'ready', reports });
  };
  await analyzeSource(repository, () => {});
  assert.equal(repository.status, 'error');
  assert.match(repository.message, /different source/);

  const pending = { id: 'client-pending', kind: 'repository', url: repository.url };
  let pendingCalls = 0;
  globalThis.fetch = async () => {
    pendingCalls++;
    return Response.json({ id: 'server-pending', status: 'processing' });
  };
  const analysis = analyzeSource(pending, () => {
    if (pending.serverId) setTimeout(() => pending.controller.abort(), 10);
  });
  await analysis;
  assert.equal(pendingCalls, 1, 'Removing a pending source must stop polling');
  assert.equal(pending.reports, undefined);

  globalThis.fetch = async url => {
    assert.equal(url, '/api/sources/server-pending');
    return Response.json({ id: 'server-pending', status: 'ready', reports: { network: { components: [] } } });
  };
  await analyzeSource(pending, () => {});
  assert.equal(pending.status, 'ready');
  assert.equal(repository.reports.code.components.length, 1, 'Other sources retain their own reports');

  // Reload restores server identities; saved file metadata must never be uploaded again.
  const saved = [
    { id: 'sample', name: 'Sample workspace', kind: 'sample', status: 'ready' },
    { id: 'saved-files', name: 'a.py', kind: 'files', files: [{ name: 'a.py', size: 4 }], status: 'ready' },
    { id: 'saved-failed', name: 'team/project', kind: 'repository', status: 'failed', url: repository.url },
  ];
  globalThis.fetch = async url => {
    assert.equal(url, '/api/sources');
    return Response.json({ sources: saved });
  };
  const restored = await listSources();
  assert.deepEqual(restored.map(source => source.serverId), saved.map(source => source.id));
  globalThis.fetch = async (url, options) => {
    assert.equal(options.method, 'GET');
    const id = url.split('/').at(-1);
    return Response.json({ id, status: id === 'saved-failed' ? 'failed' : 'ready', reports, error: 'Scanner interrupted' });
  };
  await Promise.all(restored.map(source => analyzeSource(source, () => {})));
  assert.deepEqual(restored.map(source => source.status), ['ready', 'ready', 'error']);
  assert.deepEqual(restored[1].reports, reports);
  assert.equal(restored[2].message, 'Scanner interrupted');
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/sources/saved-failed/retry');
    assert.equal(options.method, 'POST');
    return Response.json({ id: 'saved-failed', status: 'ready', reports: {} });
  };
  await analyzeSource(restored[2], () => {}, { retry: true });
  assert.equal(restored[2].status, 'ready');
  assert.deepEqual(restored[2].reports, {}, 'Missing categories never fall back to sample results');

  globalThis.fetch = async () => Response.json({ error: 'Upload exceeds the limit.' }, { status: 413 });
  await analyzeSource(files, () => {});
  assert.equal(files.message, 'Upload exceeds the limit.');
  globalThis.fetch = async () => Response.json({ sources: [{ id: 'broken' }] });
  await assert.rejects(listSources(), /invalid source list/);
  globalThis.fetch = async () => new Response('', { status: 501 });
  await assert.rejects(listSources(), /backend is not connected/);
  console.log('Source API checks passed: immediate submission, multipart files, backend errors, source identity, cancellation, and polling recovery.');
} finally {
  globalThis.fetch = originalFetch;
}
