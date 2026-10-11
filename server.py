"""Local QuantumTrace API and frontend server. Run: python server.py"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import threading
from urllib.parse import urlsplit, unquote
import uuid
import zipfile

from pipeline.analyze_source import MAX_BYTES, MAX_FILES, source_files
from pipeline.source_store import SourceStore

ROOT = Path(__file__).resolve().parent
MAX_UPLOAD = 50 * 1024 * 1024
EXTRACTED_DIR = '.quantumtrace-extracted'


def repository_url(value):
    if not isinstance(value, str):
        raise ValueError("Enter a GitHub or GitLab HTTPS repository URL.")
    url = urlsplit(value.strip())
    parts = url.path.rstrip('/').removesuffix('.git').strip('/').split('/')
    if (url.scheme != 'https' or url.netloc not in {'github.com', 'gitlab.com'} or url.query or url.fragment
            or len(parts) < 2 or (url.netloc == 'github.com' and len(parts) != 2)
            or any(not re.fullmatch(r'[\w.-]+', part, re.ASCII) or part in {'.', '..', '-'} for part in parts)):
        raise ValueError("Use a repository-root HTTPS URL on github.com or gitlab.com, without credentials, ports, queries, or fragments.")
    return f"https://{url.netloc}/{'/'.join(parts)}.git", '/'.join(parts)


def extract_zip(archive, target):
    with zipfile.ZipFile(archive) as zipped:
        members = zipped.infolist()
        if len(members) > MAX_FILES or sum(item.file_size for item in members) > MAX_BYTES:
            raise ValueError("ZIP exceeds the 100 MiB / 2,000 entry extraction limit.")
        for item in members:
            path = PurePosixPath(item.filename)
            if (path.is_absolute() or any(p in {'..', '.git'} for p in path.parts) or '\\' in item.filename
                    or stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1):
                raise ValueError("ZIP contains an unsafe path, symbolic link, or encrypted entry.")
            destination = target.joinpath(*path.parts)
            if not destination.resolve().is_relative_to(target.resolve()):
                raise ValueError("ZIP entry escapes its source directory.")
            if item.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with zipped.open(item) as source, destination.open('xb') as output:
                    shutil.copyfileobj(source, output)


class Application:
    def __init__(self, db_path, inputs):
        self.store = SourceStore(db_path)
        self.inputs = Path(inputs).resolve()
        self.inputs.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.jobs = ThreadPoolExecutor(max_workers=2, thread_name_prefix='analysis')
        sample = self.store.get('sample')
        if not sample or sample['status'] != 'ready':
            reports = {kind: json.loads((ROOT / 'pipeline' / file).read_text()) for kind, file in
                       [('network', 'cbom_network_classified.json'), ('code', 'cbom_code.json'), ('cloud', 'cbom_cloud.json')]}
            if not sample:
                self.store.create({'id': 'sample', 'name': 'Sample workspace', 'kind': 'sample'})
            self.store.save_reports('sample', reports)

    def create(self, client_id, repo=None, files=None):
        if not isinstance(client_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', client_id):
            raise ValueError('A valid clientSourceId is required.')
        with self.lock:
            previous = self.store.find_client(client_id)
            if previous:
                return previous
            if len([s for s in self.store.list() if s['status'] in {'pending', 'processing'}]) >= 8:
                raise ValueError('Eight analyses are already queued. Wait for a source to finish.')
            source = {'id': str(uuid.uuid4()), 'clientSourceId': client_id, 'status': 'pending'}
            if repo is not None:
                url, name = repository_url(repo)
                source.update(kind='repository', url=url, name=name)
            else:
                if not files or len(files) > MAX_FILES:
                    raise ValueError('Select between 1 and 2,000 files.')
                names = [name for name, _ in files]
                if any(not isinstance(name, str) or '\\' in name or '\x00' in name or ':' in name
                       or any(part in {'', '.', '..', EXTRACTED_DIR} for part in name.split('/')) for name in names):
                    raise ValueError('Upload paths must be relative, without traversal or reserved directory names.')
                paths = set(names)
                if len(paths) != len(names) or any(str(parent) in paths for name in names for parent in PurePosixPath(name).parents):
                    raise ValueError('Upload paths must be unique and must not conflict with a folder path.')
                folder = names[0].split('/')[0]
                name = folder if all(path.startswith(folder + '/') for path in names) else names[0] if len(names) == 1 else f'{names[0]} + {len(names)-1} files'
                source.update(kind='files', name=name,
                              files=[{'name': name, 'size': len(data)} for name, data in files])
            directory = self.inputs / source['id']
            directory.mkdir()
            try:
                if source['kind'] == 'files':
                    incoming = directory / 'input'
                    incoming.mkdir()
                    for name, data in files:
                        destination = incoming / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(data)
                self.store.create(source)
            except Exception:
                shutil.rmtree(directory)
                raise
            self.jobs.submit(self.run, source['id'])
            return self.store.get(source['id'])

    def run(self, source_id):
        self.store.status(source_id, 'processing')
        source = self.store.get(source_id)
        directory = self.inputs / source_id
        target = directory / 'input'
        try:
            if source['kind'] == 'repository':
                if target.exists():
                    shutil.rmtree(target)
                environment = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
                result = subprocess.run(['git', '-c', f'core.hooksPath={os.devnull}', '-c', 'http.followRedirects=false',
                                         '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                                         'clone', '--depth', '1', '--', source['url'], str(target)],
                                        capture_output=True, text=True, env=environment, timeout=120)
                if result.returncode:
                    raise ValueError('Repository clone failed. Check that the repository is public and its URL is correct. ' + result.stderr[-600:])
            else:
                # Only generated ZIP contents are replaced; uploaded folders survive retries.
                extracted = target / EXTRACTED_DIR
                if extracted.exists():
                    shutil.rmtree(extracted)
                for archive in list(target.rglob('*')):
                    if archive.is_file() and archive.suffix.lower() == '.zip':
                        extract_zip(archive, extracted / archive.relative_to(target))
            source_files(target)
            result = subprocess.run([sys.executable, '-m', 'pipeline.analyze_source', str(target), str(directory / 'reports.json')],
                                    cwd=ROOT, capture_output=True, text=True, timeout=180)
            if result.returncode:
                raise ValueError(result.stderr.strip().splitlines()[-1] if result.stderr.strip() else 'The scanner failed.')
            reports = json.loads((directory / 'reports.json').read_text())
            self.store.save_reports(source_id, reports)
        except subprocess.TimeoutExpired:
            self.store.status(source_id, 'failed', 'Analysis timed out. Try a smaller source or retry the repository connection.')
        except Exception as error:
            self.store.status(source_id, 'failed', str(error))

    def retry(self, source_id):
        with self.lock:
            source = self.store.get(source_id)
            if source and source['status'] == 'failed' and source['kind'] in {'repository', 'files'}:
                self.store.status(source_id, 'pending')
                self.jobs.submit(self.run, source_id)
            return self.store.get(source_id)

    def delete(self, source_id=None):
        with self.lock:
            sources = [s for s in self.store.list() if s['kind'] in {'repository', 'files'} and (source_id is None or s['id'] == source_id)]
            if any(s['status'] in {'pending', 'processing'} for s in sources):
                raise ValueError('Wait for the running analyses to finish before resetting inputs.')
            if source_id and not sources:
                raise ValueError('Only added repositories and uploaded sources can be deleted.')
            for source in sources:
                directory = self.inputs / source['id']
                if directory.exists():
                    shutil.rmtree(directory)
                self.store.delete(source['id'])


class Handler(BaseHTTPRequestHandler):
    server_version = 'QuantumTrace/1.0'

    def json_response(self, data, status=200):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(payload)

    def dispatch(self):
        # This development service is loopback-only and accepts same-origin browser requests.
        host = self.headers.get('Host', '')
        port = self.server.server_port
        if host not in {f'localhost:{port}', f'127.0.0.1:{port}'}:
            return self.json_response({'error': 'Invalid host.'}, 403)
        origin = self.headers.get('Origin')
        if origin and origin != f'http://{host}':
            return self.json_response({'error': 'Cross-origin requests are not allowed.'}, 403)
        path = urlsplit(self.path).path
        app = self.server.app
        if self.command == 'GET' and path == '/api/sources':
            return self.json_response({'sources': app.store.list()})
        match = re.fullmatch(r'/api/sources/([\w-]+)(/retry)?', path)
        if match and self.command == 'GET' and not match[2]:
            source = app.store.get(match[1])
            return self.json_response(source if source else {'error': 'Source not found.'}, 200 if source else 404)
        if match and self.command == 'POST' and match[2]:
            source = app.retry(match[1])
            return self.json_response(source if source else {'error': 'Source not found.'}, 200 if source else 404)
        if self.command == 'DELETE' and (path == '/api/sources' or match and not match[2]):
            app.delete(match[1] if match else None)
            return self.json_response({'deleted': True})
        if self.command == 'POST' and path == '/api/sources':
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_UPLOAD:
                return self.json_response({'error': 'Upload must be between 1 byte and 50 MiB.'}, 413)
            body = self.rfile.read(length)
            content_type = self.headers.get('Content-Type', '')
            if content_type.split(';')[0] == 'application/json':
                data = json.loads(body)
                if not isinstance(data, dict) or 'repositoryUrl' not in data:
                    raise ValueError('repositoryUrl is required.')
                source = app.create(data.get('clientSourceId'), repo=data['repositoryUrl'])
            elif content_type.startswith('multipart/form-data;'):
                message = BytesParser(policy=policy.default).parsebytes(f'Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n'.encode() + body)
                files, client_id, paths = [], None, None
                for part in message.iter_parts():
                    field = part.get_param('name', header='content-disposition')
                    if field == 'clientSourceId':
                        client_id = part.get_payload(decode=True).decode('utf-8')
                    elif field == 'paths':
                        paths = json.loads(part.get_payload(decode=True))
                    elif field == 'files' and part.get_filename():
                        files.append((part.get_filename(), part.get_payload(decode=True)))
                if paths is not None:
                    if not isinstance(paths, list) or len(paths) != len(files) or any(not isinstance(path, str) or PurePosixPath(path).name != file[0] for path, file in zip(paths, files)):
                        raise ValueError('Upload paths must match the submitted files in order.')
                    files = [(path, file[1]) for path, file in zip(paths, files)]
                source = app.create(client_id, files=files)
            else:
                return self.json_response({'error': 'Use JSON for repositories or multipart form data for uploads.'}, 415)
            return self.json_response(source, 202)
        if self.command != 'GET' or path.startswith('/api/'):
            return self.json_response({'error': 'Endpoint not found.'}, 404)
        if path in {'/', '/frontend'}:
            self.send_response(302)
            self.send_header('Location', '/frontend/')
            self.end_headers()
            return
        if path == '/frontend/':
            file = ROOT / 'frontend/index.html'
        elif path.startswith('/frontend/') or path in {'/pdfs/inspiring_solutions.pdf', '/pdfs/nist_standards.pdf'}:
            file = (ROOT / unquote(path).lstrip('/')).resolve()
            if not (file.is_relative_to(ROOT / 'frontend') or file.parent == ROOT / 'pdfs'):
                return self.json_response({'error': 'Not found.'}, 404)
        else:
            return self.json_response({'error': 'Not found.'}, 404)
        if not file.is_file():
            return self.json_response({'error': 'Not found.'}, 404)
        data = file.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'text/javascript' if file.suffix == '.mjs' else mimetypes.guess_type(file)[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def handle_request(self):
        try:
            self.dispatch()
        except (ValueError, UnicodeError, zipfile.BadZipFile) as error:
            self.json_response({'error': str(error)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            import traceback
            traceback.print_exc()
            self.json_response({'error': 'The server could not complete this request. Check the server log.'}, 500)

    do_GET = do_POST = do_DELETE = handle_request


def make_server(port=8000, db_path=ROOT / 'quantumtrace.db', inputs=ROOT / 'input_files/sources'):
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.app = Application(db_path, inputs)
    return server


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--db', type=Path, default=ROOT / 'quantumtrace.db')
    args = parser.parse_args()
    server = make_server(args.port, args.db)
    print(f'QuantumTrace: http://localhost:{server.server_port}/frontend/', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.app.jobs.shutdown(wait=True)
