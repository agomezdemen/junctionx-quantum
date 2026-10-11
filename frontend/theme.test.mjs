import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const script = readFileSync(new URL('./theme.js', import.meta.url), 'utf8');
function browser({ saved = null, dark = false, blocked = false } = {}) {
  const events = {};
  const button = { setAttribute(key, value) { this[key] = value; }, addEventListener(_, callback) { this.click = callback; } };
  const root = { dataset: {}, style: {} };
  const media = { matches: dark, addEventListener(_, callback) { this.change = callback; } };
  const storage = {
    getItem() { if (blocked) throw new Error('Storage disabled'); return saved; },
    setItem(key, value) { if (blocked) throw new Error('Storage disabled'); saved = value; },
  };
  const meta = {};
  let ready = false;
  const document = {
    documentElement: root,
    querySelector(selector) { return selector === '#theme-toggle' ? ready ? button : null : meta; },
    addEventListener(_, callback) { events.ready = callback; },
  };
  runInNewContext(script, { document, localStorage: storage, matchMedia: () => media, window: { addEventListener(name, fn) { events[name] = fn; } } });
  return { root, media, button, meta, events, ready() { ready = true; events.ready(); }, saved: () => saved };
}

for (const dark of [false, true]) {
  const b = browser({ dark });
  assert.equal(b.root.dataset.theme, dark ? 'dark' : 'light', 'Theme is set before DOMContentLoaded');
  assert.equal(b.root.style.colorScheme, b.root.dataset.theme);
  b.ready();
  b.media.matches = !dark;
  b.media.change();
  assert.equal(b.root.dataset.theme, dark ? 'light' : 'dark', 'Follow system until user chooses');
  b.button.click();
  assert.equal(b.saved(), dark ? 'dark' : 'light');
  assert.equal(b.button['aria-pressed'], String(dark));
  assert.equal(b.button['aria-label'], `Switch to ${dark ? 'light' : 'dark'} mode`);
  b.media.change();
  assert.equal(b.root.dataset.theme, b.saved(), 'System changes cannot override a saved choice');
}
assert.equal(browser({ saved: 'light', dark: true }).root.dataset.theme, 'light');
assert.equal(browser({ saved: 'dark' }).root.dataset.theme, 'dark');
assert.equal(browser({ saved: 'invalid', dark: true }).root.dataset.theme, 'dark');
const blocked = browser({ blocked: true });
blocked.ready();
blocked.button.click();
assert.equal(blocked.root.dataset.theme, 'dark', 'Toggle works with storage disabled');
const tab = browser();
tab.ready();
tab.events.storage({ key: 'quantumtrace-theme', newValue: 'dark' });
assert.equal(tab.root.dataset.theme, 'dark');
tab.events.storage({ key: null, newValue: null });
assert.equal(tab.root.dataset.theme, 'light');
const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
assert.ok(html.indexOf('<script src="theme.js">') < html.indexOf('<link rel="stylesheet"'), 'Theme initialization precedes stylesheet');
console.log('Theme checks passed: early initialization, system preference, saved choice, live switching, cross-tab sync, and blocked storage.');
