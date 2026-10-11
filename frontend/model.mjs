export const RISKS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'UNKNOWN'];

export function riskOf(component) {
  const value = component?.risk ?? component?.quantumRiskAssessment?.tier;
  const risk = typeof value === 'string' ? value.toUpperCase() : 'UNKNOWN';
  return RISKS.includes(risk) ? risk : 'UNKNOWN';
}

export function authenticationRecorded(details) {
  return !['', 'Negotiated separately', 'Not recorded', 'Not determined'].includes((details?.algorithm || '').trim());
}

export function algorithmLabel(details) {
  return [details?.algorithm, details?.keySizeBits && `${details.keySizeBits}-bit`, details?.mode, details?.curve, details?.parameterSet].filter(Boolean).join(' · ') || 'Not recorded';
}

export function reportEntries(reports) {
  return reports.flatMap(report => report.components.map(component => ({
    component,
    source: component.source || report.metadata?.sourceFile || null,
  })));
}

export function riskDistribution(entries, basis) {
  let risks;
  let omitted = 0;
  if (basis === 'files') {
    const files = new Map();
    // Unknown evidence prevents a file being marked safe; known critical risk still wins.
    const priority = ['CRITICAL', 'HIGH', 'UNKNOWN', 'MEDIUM', 'LOW', 'SAFE'];
    for (const { component, source } of entries) {
      if (!source) { omitted++; continue; }
      const path = source.replace(/\\/g, '/').replace(/^(?:\.\.?\/)+/, '');
      const risk = riskOf(component);
      if (!files.has(path) || priority.indexOf(risk) < priority.indexOf(files.get(path))) files.set(path, risk);
    }
    risks = [...files.values()];
  } else risks = entries.map(({ component }) => riskOf(component));
  return { total: risks.length, omitted, counts: Object.fromEntries(RISKS.map(risk => [risk, risks.filter(value => value === risk).length])) };
}

export function algorithmCounts(entries, purpose) {
  const counts = new Map();
  let included = 0;
  for (const { component } of entries) {
    const crypto = component.cryptoProperties || {};
    const details = crypto[purpose];
    let label;
    if (purpose === 'other') {
      // Untyped scanner references stay separate: a key's purpose cannot be inferred from its name.
      label = crypto.detectedAlgorithm || crypto.keySpec || crypto.keyAlgorithm;
    } else if (details?.algorithm && details.algorithm !== 'Not recorded') {
      label = details.components?.length ? details.components.map(algorithmLabel).join(' + ') : algorithmLabel(details);
    }
    if (!label) continue;
    counts.set(label, (counts.get(label) || 0) + 1);
    included++;
  }
  return { included, rows: [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])) };
}

export function parseRepository(value) {
  let url;
  try { url = new URL(value.trim()); } catch { throw new Error('Enter a complete HTTPS repository URL.'); }
  if (url.protocol !== 'https:' || !['github.com', 'gitlab.com'].includes(url.hostname) || url.username || url.password || url.port) {
    throw new Error('Use an HTTPS URL on github.com or gitlab.com, without credentials or a custom port.');
  }
  const parts = url.pathname.replace(/\/+$/, '').replace(/\.git$/, '').split('/').filter(Boolean);
  if (parts.length < 2 || (url.hostname === 'github.com' && parts.length !== 2) || parts.some(part => !/^[\w.-]+$/.test(part) || ['-', '.', '..'].includes(part))) {
    throw new Error('Paste the repository root URL, not a file, branch, or project page.');
  }
  if (url.search || url.hash) throw new Error('Remove query parameters and fragments from the repository URL.');
  return { url: `https://${url.hostname}/${parts.join('/')}.git`, name: parts.join('/'), provider: url.hostname === 'github.com' ? 'GitHub' : 'GitLab' };
}

export function filterSessions(components, query, risk) {
  const term = query.trim().toLowerCase();
  return components.filter(component => (risk === 'ALL' || riskOf(component) === risk) && JSON.stringify(component).toLowerCase().includes(term));
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}
