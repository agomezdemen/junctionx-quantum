import { RISKS, riskOf, authenticationRecorded, algorithmLabel, parseRepository, filterSessions, formatBytes } from './model.mjs';

const $ = selector => document.querySelector(selector);
const inputs = [];
let report = null;
let detailTrigger;
const PARTS = [['encryption', 'Encryption'], ['hash', 'Hashing'], ['keyExchange', 'Key exchange'], ['authentication', 'Authentication']];

// Keep the report's shape here when replacing this fixture with an API backed by SQLite.
async function loadReport() {
  $('#report-error').hidden = true;
  $('#dataset-status').textContent = 'Loading classified sample…';
  try {
    const response = await fetch('../pipeline/cbom_network_classified.json');
    if (!response.ok) throw new Error(`Report request failed (${response.status}).`);
    const data = await response.json();
    if (!Array.isArray(data.components) || data.components.some(c => !c || typeof c !== 'object' || Array.isArray(c))) {
      throw new Error('The report does not contain a valid components list.');
    }
    report = data;
    const counts = Object.fromEntries(RISKS.map(risk => [risk, data.components.filter(c => riskOf(c) === risk).length]));
    $('#total-count').textContent = data.components.length;
    $('#critical-count').textContent = counts.CRITICAL;
    $('#safe-count').textContent = counts.SAFE;
    $('#unknown-count').textContent = counts.UNKNOWN;
    $('#dataset-status').textContent = `${data.metadata?.sourceFile?.split('/').pop() || 'Classified report'} · ${data.components.length} sessions`;
    $('#risk-summary').replaceChildren(...RISKS.map(risk => {
      const label = element('span');
      label.append(element('i', '', `risk-dot ${risk.toLowerCase()}`), document.createTextNode(`${title(risk)} ${counts[risk]}`));
      return label;
    }));
    $('#export-report').disabled = false;
    renderSessions();
  } catch (error) {
    $('#dataset-status').textContent = 'Sample report unavailable';
    $('#report-error').hidden = false;
    $('#report-error-message').textContent = `${error.message} Serve the repository root and open /frontend/ to load the sample.`;
    $('#result-count').textContent = 'Report unavailable';
  }
}

function element(tag, text = '', className = '') {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function title(value) { return value[0] + value.slice(1).toLowerCase(); }
function badge(component) { const risk = riskOf(component); return element('span', `● ${title(risk)}`, `risk ${risk.toLowerCase()}`); }

function partEvaluation(purpose, details) {
  const view = element('div', '', 'part-evaluation');
  const missingAuthentication = purpose === 'authentication' && !authenticationRecorded(details);
  view.append(element('span', missingAuthentication ? 'Not recorded' : algorithmLabel(details), 'algorithm-name'), badge(details));
  if (missingAuthentication) view.append(element('small', 'Excluded from overall risk', 'assessment-note'));
  return view;
}

function renderSessions() {
  if (!report) return;
  const sessions = filterSessions(report.components, $('#search').value, $('#risk-filter').value);
  $('#sessions').replaceChildren(...sessions.map(component => {
    const crypto = component.cryptoProperties || {};
    const row = element('tr');
    const nameCell = element('td');
    const name = element('button', component.name || 'Unnamed session', 'session-button');
    name.addEventListener('click', () => showDetails(component, name));
    nameCell.append(name, element('small', `${component.evidence?.client || 'Unknown client'} → ${component.evidence?.server || 'Unknown server'}`));
    nameCell.append(element('span', [crypto.protocol, crypto.negotiatedVersion].filter(Boolean).join(' ') || 'Not recorded', 'protocol'));
    const parts = PARTS.map(([purpose]) => {
      const cell = element('td');
      cell.append(partEvaluation(purpose, crypto[purpose]));
      return cell;
    });
    const risk = element('td', '', 'overall-risk');
    risk.append(badge(component));
    const action = element('td');
    const button = element('button', '↗', 'detail-arrow');
    button.setAttribute('aria-label', `Inspect ${component.name || 'session'}`);
    button.addEventListener('click', () => showDetails(component, button));
    action.append(button);
    row.append(nameCell, ...parts, risk, action);
    return row;
  }));
  $('#no-results').hidden = sessions.length > 0;
  $('#result-count').textContent = `Showing ${sessions.length} of ${report.components.length} sessions`;
}

function showDetails(component, trigger) {
  detailTrigger = trigger;
  $('#detail-title').textContent = component.name || 'Unnamed session';
  const content = $('#session-detail');
  content.replaceChildren();
  const evaluations = element('div', '', 'evaluation-grid');
  for (const [purpose, label] of PARTS) {
    const details = component.cryptoProperties?.[purpose];
    const card = element('section', '', 'evaluation-card');
    card.append(element('h3', label), partEvaluation(purpose, details));
    if (details?.components?.length) {
      const primitives = element('ul', '', 'hybrid-parts');
      for (const part of details.components) {
        const item = element('li');
        item.append(element('span', algorithmLabel(part)), badge(part));
        primitives.append(item);
      }
      card.append(primitives, element('p', 'Primitive ratings shown separately. The key-exchange rating assesses the combined hybrid.', 'assessment-note'));
    }
    // Preserve all recorded parameters without displaying nested components as raw JSON.
    const parameters = element('dl');
    for (const [key, value] of Object.entries(details || {})) {
      if (['algorithm', 'risk', 'components'].includes(key)) continue;
      parameters.append(element('dt', key.replace(/([A-Z])/g, ' $1')), element('dd', String(value ?? 'Not recorded')));
    }
    if (parameters.children.length) card.append(parameters);
    evaluations.append(card);
  }
  const conclusion = element('section', '', 'risk-conclusion');
  const explanation = element('div');
  explanation.append(element('h3', 'Overall TLS risk'), element('p', 'Based on encryption, hashing, and key exchange. Authentication contributes only when recorded.'));
  conclusion.append(explanation, badge(component));
  content.append(evaluations, conclusion);
  for (const [section, data] of Object.entries({ evidence: component.evidence, ...component.cryptoProperties })) {
    if (data === undefined || PARTS.some(([purpose]) => purpose === section)) continue;
    const block = element('section', '', 'detail-block');
    block.append(element('h3', section.replace(/([A-Z])/g, ' $1')));
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const list = element('dl');
      for (const [key, value] of Object.entries(data)) {
        list.append(element('dt', key.replace(/([A-Z])/g, ' $1')), element('dd', typeof value === 'object' && value !== null ? JSON.stringify(value, null, 2) : String(value ?? 'Not recorded')));
      }
      block.append(list);
    } else block.append(element('p', Array.isArray(data) ? data.join(', ') : String(data ?? 'Not recorded')));
    content.append(block);
  }
  $('#session-dialog').showModal();
}

function notice(message) { $('#input-notice').textContent = message; }

function renderInputs() {
  $('#queue-count').textContent = inputs.length;
  $('#queue-empty').hidden = inputs.length > 0;
  $('#reset-inputs').disabled = inputs.length === 0 && !$('#repo-url').value;
  $('#analyze').disabled = inputs.length === 0;
  $('#input-list').replaceChildren(...inputs.map((input, index) => {
    const row = element('li', '', 'input-item');
    const info = element('div', input.name);
    info.append(element('small', input.type === 'file' ? `Local file · ${formatBytes(input.file.size)}` : `${input.provider} · ${input.url}`));
    const remove = element('button', '✕', 'button subtle');
    remove.setAttribute('aria-label', `Remove ${input.name}`);
    remove.addEventListener('click', () => { inputs.splice(index, 1); renderInputs(); notice(`${input.name} removed from the queue.`); $('#reset-inputs').disabled ? $('#repo-url').focus() : $('#reset-inputs').focus(); });
    row.append(element('span', input.type === 'file' ? '▤' : '⌘', 'muted'), info, element('span', 'Staged', 'queued-badge'), remove);
    return row;
  }));
}

function addFiles(files) {
  let added = 0;
  for (const file of files) {
    const id = `${file.name}:${file.size}:${file.lastModified}`;
    if (inputs.some(input => input.id === id)) continue;
    inputs.push({ type: 'file', id, name: file.name, file });
    added++;
  }
  renderInputs();
  notice(added ? `${added} file${added === 1 ? '' : 's'} staged. Files stay in this tab until upload support is connected.` : 'No new files added. These files may already be staged.');
}

$('#file-input').addEventListener('change', event => { addFiles(event.target.files); event.target.value = ''; });
let dragDepth = 0;
$('#drop-zone').addEventListener('dragenter', event => { event.preventDefault(); dragDepth++; $('#drop-zone').classList.add('dragging'); });
$('#drop-zone').addEventListener('dragover', event => { event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; });
$('#drop-zone').addEventListener('dragleave', () => { if (--dragDepth <= 0) $('#drop-zone').classList.remove('dragging'); });
$('#drop-zone').addEventListener('drop', event => {
  event.preventDefault();
  dragDepth = 0;
  $('#drop-zone').classList.remove('dragging');
  const items = [...(event.dataTransfer.items || [])];
  if (items.some(item => item.webkitGetAsEntry?.()?.isDirectory)) { notice('Please select individual files or a project archive; folder drops are not supported.'); return; }
  addFiles(event.dataTransfer.files);
});
// Prevent file drops outside the target from navigating away and losing the queue.
for (const type of ['dragover', 'drop']) document.addEventListener(type, event => {
  if ([...event.dataTransfer.types].includes('Files')) event.preventDefault();
});

$('#repo-form').addEventListener('submit', event => {
  event.preventDefault();
  const field = $('#repo-url');
  try {
    const repo = parseRepository(field.value);
    if (inputs.some(input => input.id === repo.url)) throw new Error('This repository is already in the queue.');
    inputs.push({ ...repo, type: 'repository', id: repo.url });
    field.value = '';
    field.removeAttribute('aria-invalid');
    $('#repo-error').textContent = '';
    renderInputs();
    notice(`${repo.name} staged for cloning into input_files/. No repository has been cloned in this frontend preview.`);
  } catch (error) { $('#repo-error').textContent = error.message; field.setAttribute('aria-invalid', 'true'); field.focus(); }
});
$('#repo-url').addEventListener('input', () => { $('#repo-error').textContent = ''; $('#repo-url').removeAttribute('aria-invalid'); $('#reset-inputs').disabled = inputs.length === 0 && !$('#repo-url').value; });
$('#reset-inputs').addEventListener('click', () => {
  inputs.length = 0;
  $('#repo-form').reset();
  $('#file-input').value = '';
  $('#repo-error').textContent = '';
  $('#repo-url').removeAttribute('aria-invalid');
  renderInputs();
  notice('Input queue reset. Existing files in input_files/ and the sample report are unchanged.');
});
$('#analyze').addEventListener('click', () => notice('Your inputs are staged. Analysis requires the backend connection; the inventory below is still the supplied sample report.'));
$('#search').addEventListener('input', renderSessions);
$('#risk-filter').addEventListener('change', renderSessions);
$('#retry-report').addEventListener('click', loadReport);
$('#close-dialog').addEventListener('click', () => $('#session-dialog').close());
$('#session-dialog').addEventListener('close', () => detailTrigger?.focus());
$('#export-report').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const link = element('a');
  link.href = url;
  link.download = 'cbom_network_classified.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

loadReport();
