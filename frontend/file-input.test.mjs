import assert from 'node:assert/strict';
import { droppedFiles, prepareFiles, uploadPath } from './file-input.mjs';

const fileEntry = (name, content = 'RSA.generate(2048)') => ({ name, isFile: true,
  file: resolve => resolve(new File([content], name, { lastModified: 123 })) });
const directory = (name, batches) => ({ name, isDirectory: true, createReader() {
  let index = 0;
  return { readEntries: resolve => resolve(batches[index++] || []) };
} });
const transfer = entries => ({ files: [], items: entries.map(entry => ({ kind: 'file', webkitGetAsEntry: () => entry })) });

const project = directory('project', [
  [directory('client', [[fileEntry('main.py')]]), directory('server', [[fileEntry('main.py')]])],
  [directory('node_modules', [[fileEntry('ignored.py')]]), directory('empty', [[]])],
  Array.from({ length: 105 }, (_, index) => fileEntry(`extra-${index}.py`)),
]);
const files = await droppedFiles(transfer([project, fileEntry('loose.go')]));
assert.equal(files.length, 108, 'Read every directory batch and include mixed loose files');
assert.deepEqual(files.slice(0, 2).map(uploadPath), ['project/client/main.py', 'project/server/main.py']);
assert.equal(prepareFiles(files).length, 108, 'Equal basenames in distinct folders must survive deduplication');
assert.equal(uploadPath(files.at(-1)), 'loose.go');
assert.deepEqual(await droppedFiles(transfer([directory('empty', [[]])])), []);
const loose = new File(['abc'], 'loose.py');
assert.deepEqual(await droppedFiles({ items: [], files: [loose] }), [loose]);
assert.equal(uploadPath({ name: 'main.py', webkitRelativePath: 'picked/src/main.py' }), 'picked/src/main.py');
assert.deepEqual(prepareFiles([{ name: 'ignored.py', webkitRelativePath: 'project/.git/ignored.py' }]), []);
assert.throws(() => prepareFiles([{ name: 'large.py', size: 51 * 1024 * 1024 }]), /50 MiB/);
assert.throws(() => prepareFiles(Array.from({ length: 2001 }, (_, i) => ({ name: `${i}.py`, size: 1 }))), /2,000/);
assert.throws(() => prepareFiles([{ name: 'same.py', size: 1 }, { name: 'same.py', size: 2 }]), /same path/);
await assert.rejects(droppedFiles(transfer([{ name: 'blocked', isDirectory: true, createReader: () => ({ readEntries: (_, reject) => reject(new Error('Permission denied')) }) }])), /Permission denied/);
console.log('Folder checks passed: nested paths, duplicate basenames, multiple directory batches, mixed drops, empty folders, picker/fallback files, exclusions, limits, and read errors.');
