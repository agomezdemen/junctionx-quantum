export const RISKS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'UNKNOWN'];

export function riskOf(component) {
  return RISKS.includes(component.risk) ? component.risk : 'UNKNOWN';
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
