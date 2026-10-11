// Browser-local demo ownership. The shared backend does not authenticate users.
export const MOCK_ACCOUNTS = [
  { id: 'alex', name: 'Alex Morgan' },
  { id: 'sam', name: 'Sam Rivera' },
  { id: 'jordan', name: 'Jordan Lee' },
];

const PREFIX = 'quantumtrace-mock:';
const validAccount = id => MOCK_ACCOUNTS.some(account => account.id === id);

export function createMockWorkspace(storage) {
  const memory = new Map();
  function read(key) {
    try {
      const value = storage?.getItem(PREFIX + key);
      if (value != null) memory.set(key, value);
    } catch { /* Keep the demo usable when browser storage is unavailable. */ }
    return memory.get(key);
  }
  function write(key, value) {
    memory.set(key, value);
    try { storage?.setItem(PREFIX + key, value); } catch { /* Session-only fallback. */ }
  }
  function record(id) {
    try {
      const saved = JSON.parse(read(`source:${id}`));
      return validAccount(saved?.owner) && typeof saved.hidden === 'boolean' ? saved : null;
    } catch { return null; }
  }
  let accountId = read('account');
  if (!validAccount(accountId)) accountId = 'alex';

  function remember(source, owner = accountId) {
    if (source.kind === 'sample') return null;
    const client = record(source.id);
    const server = source.serverId ? record(source.serverId) : null;
    const sourceOwner = client?.owner || server?.owner || owner;
    const saved = { owner: sourceOwner, hidden: Boolean(
      client?.owner === sourceOwner && client.hidden || server?.owner === sourceOwner && server.hidden
    ) };
    for (const id of new Set([source.id, source.serverId].filter(Boolean))) {
      write(`source:${id}`, JSON.stringify(saved));
    }
    return saved;
  }

  return {
    get account() { return MOCK_ACCOUNTS.find(account => account.id === accountId); },
    select(id) {
      if (!validAccount(id)) throw new Error('Choose a mock account.');
      accountId = id;
      write('account', id);
    },
    remember,
    visible(saved) {
      if (read('initialized') !== 'true') {
        for (const source of saved) remember(source, MOCK_ACCOUNTS[0].id);
        write('initialized', 'true');
      }
      return saved.filter(source => {
        if (source.kind === 'sample') return true;
        const entry = record(source.serverId || source.id);
        return entry?.owner === accountId && !entry.hidden;
      });
    },
    hide(source) {
      const entry = remember(source);
      if (!entry || entry.owner !== accountId) return;
      for (const id of new Set([source.id, source.serverId].filter(Boolean))) {
        write(`source:${id}`, JSON.stringify({ ...entry, hidden: true }));
      }
    },
  };
}
