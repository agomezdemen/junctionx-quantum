const ignoredDirectories = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__']);
export const uploadPath = file => file.relativePath || file.webkitRelativePath || file.name;

export function prepareFiles(files) {
  const unique = new Map();
  let bytes = 0;
  for (const file of files) {
    const path = uploadPath(file);
    if (path.split('/').slice(0, -1).some(part => ignoredDirectories.has(part))) continue;
    const previous = unique.get(path);
    if (previous) {
      if (previous.size !== file.size || previous.lastModified !== file.lastModified) throw new Error(`Two different files use the same path: ${path}. Drop them separately.`);
      continue;
    }
    unique.set(path, file);
    bytes += file.size;
    if (unique.size > 2000 || bytes > 50 * 1024 * 1024) throw new Error('Select at most 2,000 files and 50 MiB per upload.');
  }
  return [...unique.values()];
}

export async function droppedFiles(transfer) {
  // Capture entries and fallback files before the drop event's data store closes.
  const items = [...(transfer.items || [])].filter(item => item.kind === 'file');
  const roots = items.map(item => ({ entry: item.getAsEntry?.() || item.webkitGetAsEntry?.(), file: item.getAsFile?.() }));
  const fallback = [...transfer.files];
  const files = [];
  let bytes = 0;
  async function visit(entry, parent = '') {
    const path = parent + entry.name;
    if (entry.isDirectory) {
      if (ignoredDirectories.has(entry.name)) return;
      const reader = entry.createReader();
      while (true) {
        const entries = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
        if (!entries.length) break;
        for (const child of entries) await visit(child, path + '/');
      }
    } else if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      Object.defineProperty(file, 'relativePath', { value: path });
      files.push(file);
      bytes += file.size;
      if (files.length > 2000 || bytes > 50 * 1024 * 1024) throw new Error('Select at most 2,000 files and 50 MiB per upload.');
    }
  }
  for (const { entry, file } of roots) {
    if (entry) await visit(entry);
    else if (file) files.push(file);
  }
  return prepareFiles(roots.length ? files : fallback);
}
