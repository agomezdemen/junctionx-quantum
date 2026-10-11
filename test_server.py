"""Integration checks use a disposable database and input directory."""
import io
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid
import zipfile

from pipeline.database import init_db, add_code_classification, add_network_session
from pipeline.source_store import SourceStore
from server import ROOT, Application, make_server, repository_url


class PersistenceTest(unittest.TestCase):
    def test_migrate_existing_tables_and_preserve_full_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / 'old.db'
            init_db(db)
            add_code_classification({'file_path': 'old.py', 'language': 'python', 'library': 'example', 'primitive': 'RSA', 'risk': 'Critical'}, db)
            add_network_session({'client_endpoint': 'client', 'server_endpoint': 'server', 'encryption_algorithm': 'AES', 'conclusion': 'MEDIUM'}, db)
            store = SourceStore(db)
            legacy = store.get('legacy')['reports']
            self.assertEqual(legacy['code']['components'][0]['cryptoProperties']['detectedAlgorithm'], 'RSA')
            self.assertEqual(legacy['network']['components'][0]['evidence']['server'], 'server')
            report = json.loads((ROOT / 'pipeline/cbom_network_classified.json').read_text())
            store.create({'id': 'test', 'name': 'test', 'kind': 'files'})
            store.save_reports('test', {'network': report})
            store.save_reports('test', {'network': report})
            self.assertEqual(store.get('test')['reports']['network'], report)
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM network_session WHERE source_id='test'").fetchone()[0], len(report['components']))
            store.delete('test')
            self.assertEqual(store.get('legacy')['reports'], legacy)


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temp.name)
        cls.server = make_server(0, cls.folder / 'test.db', cls.folder / 'inputs')
        cls.quiet = patch('server.Handler.log_message')
        cls.quiet.start()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.app.jobs.shutdown(wait=True)
        cls.thread.join()
        cls.temp.cleanup()
        cls.quiet.stop()

    def request(self, path, data=None, method='GET', content_type='application/json', headers=None):
        request = Request(self.base + path, data=data, method=method, headers={'Content-Type': content_type, **(headers or {})})
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, json.loads(raw) if response.headers.get_content_type() == 'application/json' else raw

    def upload(self, files, client=None, paths=None):
        boundary = 'quantumtrace-test-boundary'
        body = f'--{boundary}\r\nContent-Disposition: form-data; name="clientSourceId"\r\n\r\n{client or uuid.uuid4()}\r\n'.encode()
        if paths is not None:
            body += f'--{boundary}\r\nContent-Disposition: form-data; name="paths"\r\n\r\n{json.dumps(paths)}\r\n'.encode()
        for name, content in files:
            body += f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + content + b'\r\n'
        body += f'--{boundary}--\r\n'.encode()
        status, source = self.request('/api/sources', body, 'POST', f'multipart/form-data; boundary={boundary}')
        return status, source

    def complete(self, source):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status, result = self.request('/api/sources/' + source['id'])
            self.assertEqual(status, 200)
            if result['status'] in {'ready', 'failed'}:
                return result
            time.sleep(.1)
        self.fail('Analysis did not complete')

    def test_sample_is_in_database_and_seed_is_idempotent(self):
        status, source = self.request('/api/sources/sample')
        self.assertEqual(status, 200)
        for kind, file in [('network', 'cbom_network_classified.json'), ('code', 'cbom_code.json'), ('cloud', 'cbom_cloud.json')]:
            self.assertEqual(source['reports'][kind], json.loads((ROOT / 'pipeline' / file).read_text()))
        with closing(sqlite3.connect(self.folder / 'test.db')) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM network_session WHERE source_id='sample'").fetchone()[0], 58)
        second = Application(self.folder / 'test.db', self.folder / 'inputs')
        try:
            self.assertEqual(second.store.get('sample'), source)
        finally:
            second.jobs.shutdown()

    def test_upload_scans_all_three_kinds_and_isolates_sources(self):
        client = str(uuid.uuid4())
        files = [('test.py', b'RSA.generate(2048)\n'), ('network.pcap', (ROOT / 'input_files/network-capture/network.pcap').read_bytes()),
                 ('kms_key_inventory.json', b'{"Keys":[{"KeyId":"test-key","KeySpec":"AES_256"}]}')]
        status, source = self.upload(files, client)
        self.assertEqual(status, 202)
        result = self.complete(source)
        self.assertEqual(result['status'], 'ready', result.get('error'))
        self.assertEqual(set(result['reports']), {'code', 'cloud', 'network'})
        self.assertEqual(result['reports']['code']['components'][0]['source'], 'test.py')
        self.assertEqual(len(result['reports']['code']['components']), 1)
        self.assertEqual(result['reports']['cloud']['components'][0]['name'], 'test-key')
        self.assertGreater(len(result['reports']['network']['components']), 0)
        self.assertEqual(self.upload(files, client)[1]['id'], source['id'])
        _, other = self.upload([('safe.py', b'mlkem\n')])
        other = self.complete(other)
        self.assertEqual(set(other['reports']), {'code'})
        self.assertEqual(other['reports']['code']['components'][0]['quantumRiskAssessment']['tier'], 'Safe')
        with closing(sqlite3.connect(self.folder / 'test.db')) as conn:
            self.assertEqual(conn.execute('SELECT primitive FROM code_classification WHERE source_id=?', (source['id'],)).fetchone()[0], 'RSA-2048')
        self.assertEqual(self.request('/api/sources/' + source['id'], method='DELETE')[0], 200)
        self.assertFalse((self.folder / 'inputs' / source['id']).exists())
        self.assertEqual(self.request('/api/sources/' + source['id'])[0], 404)
        self.assertEqual(self.request('/api/sources/' + other['id'])[1]['reports'], other['reports'])

    def test_cbom_zip_failures_retry_and_safe_extraction(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('project/src/Test.java', 'KeyPairGenerator.getInstance("RSA");')
            zipped.writestr('project/main.go', 'rsa.GenerateKey(')
        _, source = self.upload([('project.zip', archive.getvalue())])
        result = self.complete(source)
        self.assertEqual(result['status'], 'ready', result.get('error'))
        self.assertEqual(len(result['reports']['code']['components']), 2)
        _, imported = self.upload([('cbom.json', (ROOT / 'pipeline/cbom_network_classified.json').read_bytes())])
        self.assertEqual(len(self.complete(imported)['reports']['network']['components']), 58)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('../escape.py', 'RSA.generate(2048)')
        _, bad = self.upload([('unsafe.zip', archive.getvalue())])
        self.assertEqual(self.complete(bad)['status'], 'failed')
        self.assertFalse((self.folder / 'inputs' / bad['id'] / 'input/escape.py').exists())
        _, failed = self.upload([('notes.txt', b'No scanner inputs')])
        self.assertEqual(self.complete(failed)['status'], 'failed')
        retry = self.request('/api/sources/' + failed['id'] + '/retry', method='POST')[1]
        self.assertEqual(retry['id'], failed['id'])
        self.assertEqual(self.complete(retry)['status'], 'failed')

    def test_repository_validation_and_clone_pipeline(self):
        for url in ['file:///tmp/repo', 'https://localhost/team/repo', 'https://github.com@evil.test/a/b', 'https://github.com/a/b/tree/main', 'https://gitlab.com/a/../b']:
            with self.assertRaises(ValueError):
                repository_url(url)
        self.assertEqual(repository_url('https://gitlab.com/team/sub/repo')[0], 'https://gitlab.com/team/sub/repo.git')
        # Exercise the real scanner, replacing only the network-bound git command.
        import subprocess
        original = subprocess.run
        commands = []
        def clone_or_run(command, **kwargs):
            if command[0] == 'git':
                commands.append(command)
                target = Path(command[-1])
                target.mkdir()
                (target / 'test.py').write_text('RSA.generate(2048)')
                return subprocess.CompletedProcess(command, 0, '', '')
            return original(command, **kwargs)
        with patch('server.subprocess.run', side_effect=clone_or_run):
            status, source = self.request('/api/sources', json.dumps({'clientSourceId': str(uuid.uuid4()), 'repositoryUrl': 'https://github.com/team/test'}).encode(), 'POST')
            self.assertEqual(status, 202)
            self.assertEqual(self.complete(source)['status'], 'ready')
        self.assertIn('http.followRedirects=false', commands[0])
        self.assertIn('--', commands[0])
        self.assertEqual(commands[0][-2], 'https://github.com/team/test.git')

    def test_http_boundaries(self):
        self.assertEqual(self.request('/frontend/')[0], 200)
        self.assertEqual(self.request('/frontend/app.mjs')[0], 200)
        for path in ['/quantumtrace.db', '/input_files/sample-repos/python/secure_transfer.py', '/frontend/../server.py']:
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request('/api/sources', b'{}', 'POST', headers={'Origin': 'https://untrusted.test'})[0], 403)
        self.assertEqual(self.request('/api/sources', headers={'Host': 'untrusted.test'})[0], 403)
        self.assertEqual(self.upload([('../bad.py', b'RSA.generate(2048)')])[0], 400)
        self.assertEqual(self.request('/api/sources/sample', method='DELETE')[0], 400)

    def test_running_source_cannot_be_reset(self):
        with patch.object(self.server.app.jobs, 'submit'):
            _, source = self.upload([('pending.py', b'RSA.generate(2048)')])
            self.assertEqual(self.request('/api/sources/' + source['id'], method='DELETE')[0], 400)
            self.assertEqual(self.request('/api/sources', method='DELETE')[0], 400)
            self.assertTrue((self.folder / 'inputs' / source['id']).exists())
        self.server.app.run(source['id'])
        self.assertEqual(self.complete(source)['status'], 'ready')

    def test_folder_paths_and_retry_preserve_original_files(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('main.go', 'rsa.GenerateKey(')
        files = [('main.py', b'RSA.generate(2048)'), ('main.py', b'mlkem'),
                 ('kms_key_inventory.json', b'not json'), ('extra.zip', archive.getvalue())]
        paths = ['project/client/main.py', 'project/server/main.py', 'project/cloud/kms_key_inventory.json', 'project/extra.zip']
        status, source = self.upload(files, paths=paths)
        self.assertEqual(status, 202)
        self.assertEqual(source['name'], 'project')
        self.assertEqual(self.complete(source)['status'], 'failed')
        incoming = self.folder / 'inputs' / source['id'] / 'input'
        self.assertEqual((incoming / paths[0]).read_bytes(), files[0][1])
        (incoming / paths[2]).write_text('{"Keys":[{"KeyId":"nested-key","KeySpec":"AES_256"}]}')
        self.request('/api/sources/' + source['id'] + '/retry', method='POST')
        result = self.complete(source)
        self.assertEqual(result['status'], 'ready', result.get('error'))
        self.assertEqual(len(result['reports']['code']['components']), 3)
        self.assertEqual(len(result['reports']['cloud']['components']), 1)
        self.assertTrue(set(paths[:2]).issubset({c['source'] for c in result['reports']['code']['components']}))
        self.assertEqual((incoming / paths[1]).read_bytes(), files[1][1])
        for path in ['../bad.py', '/bad.py', 'a//bad.py', 'a/./bad.py', 'C:/bad.py', '.quantumtrace-extracted/bad.py']:
            self.assertEqual(self.upload([('bad.py', b'code')], paths=[path])[0], 400, path)
        self.assertEqual(self.upload([('bad.py', b'code')], paths=[])[0], 400)
        self.assertEqual(self.upload([('bad.py', b'code')], paths=['other.py'])[0], 400)

    def test_z_reset_preserves_samples(self):
        self.server.app.jobs.shutdown(wait=True)
        self.assertEqual(self.request('/api/sources', method='DELETE')[0], 200)
        self.assertEqual([s['id'] for s in self.request('/api/sources')[1]['sources']], ['sample'])
        self.assertEqual(list((self.folder / 'inputs').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
