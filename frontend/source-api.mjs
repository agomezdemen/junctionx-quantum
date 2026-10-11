// Backend contract is documented in README.md. No scanner or database runs in the browser.
async function sourceResponse(response) {
  if ([404, 405, 501].includes(response.status)) throw new Error('Analysis backend is not connected or this source no longer exists. Start python3 server.py and reload.');
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.error || `Analysis request failed (${response.status}). Check the connection and try again.`);
  }
  return response.json();
}

export async function listSources() {
  const result = await sourceResponse(await fetch('/api/sources'));
  if (!Array.isArray(result?.sources) || result.sources.some(source =>
    !source || typeof source.id !== 'string' || !source.id || typeof source.name !== 'string' ||
    !['sample', 'repository', 'files', 'database'].includes(source.kind) ||
    !['pending', 'processing', 'ready', 'failed'].includes(source.status))) {
    throw new Error('The analysis service returned an invalid source list.');
  }
  return result.sources.map(source => ({
    ...source, serverId: source.id, status: 'processing', message: 'Loading saved analysis…',
    files: source.files || [],
  }));
}

export async function analyzeSource(source, onUpdate, { retry = false } = {}) {
  source.controller?.abort();
  const controller = new AbortController();
  source.controller = controller;
  source.status = 'processing';
  source.message = source.serverId ? 'Loading saved analysis…' : source.kind === 'repository' ? 'Cloning and analyzing repository…' : 'Uploading and analyzing files…';
  onUpdate();
  try {
    let response;
    if (source.serverId) {
      const restart = retry && source.analysisFailed;
      response = await fetch(`/api/sources/${encodeURIComponent(source.serverId)}${restart ? '/retry' : ''}`, {
        method: restart ? 'POST' : 'GET', signal: controller.signal,
      });
    } else {
      const options = { method: 'POST', signal: controller.signal };
      if (source.kind === 'repository') {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify({ clientSourceId: source.id, repositoryUrl: source.url });
      } else {
        options.body = new FormData();
        options.body.append('clientSourceId', source.id);
        for (const file of source.files) options.body.append('files', file, file.name);
      }
      response = await fetch('/api/sources', options);
    }
    while (!controller.signal.aborted) {
      const result = await sourceResponse(response);
      if (controller.signal.aborted) return;
      if (typeof result.id !== 'string' || !result.id || !['pending', 'processing', 'ready', 'failed'].includes(result.status)) {
        throw new Error('The analysis service returned an invalid source response.');
      }
      if (source.serverId && source.serverId !== result.id) throw new Error('The analysis service returned results for a different source.');
      source.serverId = result.id;
      source.analysisFailed = result.status === 'failed';
      if (result.status === 'failed') throw new Error(result.error || 'Analysis failed. Check the source and try again.');
      if (result.status === 'ready') {
        if (!result.reports || typeof result.reports !== 'object' || Array.isArray(result.reports)) throw new Error('The analysis response is missing its reports.');
        for (const [kind, report] of Object.entries(result.reports)) {
          if (!['network', 'code', 'cloud'].includes(kind) || !Array.isArray(report?.components) || report.components.some(c => !c || typeof c !== 'object' || Array.isArray(c))) {
            throw new Error('The analysis response contains an invalid report.');
          }
        }
        source.reports = result.reports;
        source.status = 'ready';
        source.message = 'Analysis complete. Results are available in the corresponding report views.';
        onUpdate();
        return;
      }
      source.message = 'Analysis in progress. Results will appear automatically.';
      onUpdate();
      await new Promise((resolve, reject) => {
        const abort = () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); };
        const timer = setTimeout(() => { controller.signal.removeEventListener('abort', abort); resolve(); }, 1500);
        controller.signal.addEventListener('abort', abort, { once: true });
      });
      response = await fetch(`/api/sources/${encodeURIComponent(source.serverId)}`, { signal: controller.signal });
    }
  } catch (error) {
    if (controller.signal.aborted) return;
    source.status = 'error';
    source.message = error.message;
    onUpdate();
  }
}
