"""Exercise the README actions through real HAProxy and the vendored Lua.

Run: HAPROXY=/path/to/haproxy python3 -m unittest discover -s tests -v
Requires HAProxy with Lua and OpenSSL, Python 3, and the openssl command.
The local auth stub verifies the integration contract, not an Authentik login.
"""
import http.client
import http.server
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]


class AuthStub(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.requests.put((self.path, dict(self.headers)))
        status = self.server.auth_status
        if status is None:
            self.close_connection = True
            return
        self.send_response(status)
        if status == 200:
            self.send_header('X-authentik-username', 'verified-user')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'outpost')

    def log_message(self, *args):
        pass


class AppStub(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.headers.get('X-authentik-username', 'application').encode())

    def log_message(self, *args):
        pass


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class ForwardAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get('HAPROXY', 'haproxy')
        if not shutil.which(binary):
            raise RuntimeError('Install HAProxy with Lua/OpenSSL or set HAPROXY to its executable')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        directory = Path(cls.temp.name)
        cls.auth = http.server.ThreadingHTTPServer(('127.0.0.1', 0), AuthStub)
        cls.auth.requests = queue.Queue()
        cls.auth.auth_status = 401
        cls.app = http.server.ThreadingHTTPServer(('127.0.0.1', 0), AppStub)
        for server in (cls.auth, cls.app):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)
        cls.http_port, cls.https_port = unused_port(), unused_port()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(directory / 'key.pem'), '-out', str(directory / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost'], check=True, capture_output=True)
        pem = directory / 'combined.pem'
        pem.write_bytes((directory / 'cert.pem').read_bytes() + (directory / 'key.pem').read_bytes())
        # Read production documentation instead of copying the rules into tests.
        blocks = re.findall(r'^```[^\n]*\n(.*?)\n```', (ROOT / 'README.md').read_text(), re.S | re.M)
        actions = [line for block in blocks for line in block.splitlines()
                   if line.startswith('http-request ')]
        outpost = next(line for block in blocks for line in block.splitlines()
                       if line.startswith('use_backend authentik-http_ipvANY '))
        config = '\n'.join([
            'global', f'  lua-prepend-path {ROOT}/?.lua', f'  lua-load {ROOT}/auth-request.lua',
            'defaults', '  mode http', '  timeout connect 2s', '  timeout client 5s',
            '  timeout server 5s', 'frontend test', f'  bind 127.0.0.1:{cls.http_port}',
            f'  bind 127.0.0.1:{cls.https_port} ssl crt {pem}',
            '  acl protected-frontends hdr(host) -m beg service1.yourdomain.com',
            '  acl is_authentikoutpost path_beg /outpost.goauthentik.io/',
            *('  ' + rule for rule in actions), '  ' + outpost, '  default_backend application',
            'backend authentik-http_ipvANY', f'  server auth 127.0.0.1:{cls.auth.server_port}',
            'backend application', f'  server app 127.0.0.1:{cls.app.server_port}', '',
        ])
        config_path = directory / 'haproxy.cfg'
        config_path.write_text(config)
        checked = subprocess.run([binary, '-c', '-f', str(config_path)], capture_output=True, text=True)
        if checked.returncode:
            raise RuntimeError(checked.stdout + checked.stderr)
        cls.logs = (directory / 'haproxy.log').open('w+')
        cls.addClassCleanup(cls.logs.close)
        cls.proxy = subprocess.Popen([binary, '-db', '-f', str(config_path)], stdout=cls.logs, stderr=cls.logs)
        cls.addClassCleanup(cls.stop_proxy)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', cls.http_port), timeout=.2):
                    return
            except OSError:
                if cls.proxy.poll() is not None:
                    break
                time.sleep(.05)
        cls.logs.seek(0)
        raise RuntimeError('HAProxy did not start: ' + cls.logs.read())

    @classmethod
    def stop_proxy(cls):
        cls.proxy.terminate()
        cls.proxy.wait(timeout=5)

    def setUp(self):
        self.auth.auth_status = 401
        while not self.auth.requests.empty():
            self.auth.requests.get_nowait()

    def request(self, path, *, tls=False, host='service1.yourdomain.com', headers=None):
        if tls:
            connection = http.client.HTTPSConnection('127.0.0.1', self.https_port,
                                                    context=ssl._create_unverified_context(), timeout=5)
        else:
            connection = http.client.HTTPConnection('127.0.0.1', self.http_port, timeout=5)
        try:
            connection.request('GET', path, headers={'Host': host, **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_original_url_and_redirect_round_trip(self):
        paths = ['/', '/reports?sort=name&order=asc', '/reports?items=a,b&n=2', '/a%2Fb?q=x%26y&plus=a+b&empty=',
                 '/search?next=https%3A%2F%2Fexample.com%2Fa%3Fx%3D1%26y%3D2', '/empty?']
        for tls in (False, True):
            for path in paths:
                with self.subTest(tls=tls, path=path):
                    host = 'service1.yourdomain.com:8443'
                    expected = ('https' if tls else 'http') + '://' + host + path
                    status, headers, _ = self.request(path, tls=tls, host=host,
                                                     headers={'X-Original-URL': 'https://spoof.invalid/'})
                    self.assertEqual(status, 302)
                    auth_path, forwarded = self.auth.requests.get(timeout=2)
                    self.assertEqual(auth_path, '/outpost.goauthentik.io/auth/nginx')
                    self.assertEqual(forwarded['x-original-url'], expected)
                    self.assertEqual(forwarded['x-forwarded-host'], host)
                    self.assertEqual(forwarded['x-forwarded-proto'], 'https' if tls else 'http')
                    redirect = urlsplit(headers['location'])
                    self.assertEqual(redirect.path, '/outpost.goauthentik.io/start')
                    self.assertEqual(parse_qs(redirect.query), {'rd': [expected]})

    def test_absolute_request_target_has_one_scheme_and_authority(self):
        expected = 'http://service1.yourdomain.com/a?x=1&y=2'
        status, _, _ = self.request(expected)
        self.assertEqual(status, 302)
        _, headers = self.auth.requests.get(timeout=2)
        self.assertEqual(headers['x-original-url'], expected)

    def test_authorized_request_reaches_application(self):
        self.auth.auth_status = 200
        status, _, body = self.request('/')
        self.assertEqual((status, body), (200, b'verified-user'))

    def test_auth_errors_fail_closed(self):
        for code in (403, 500, 503, None):
            with self.subTest(code=code):
                self.auth.auth_status = code
                status, _, body = self.request('/')
                self.assertEqual(status, 401)
                self.assertNotIn(b'application', body)

    def test_outpost_bypasses_auth_and_reaches_auth_backend(self):
        status, _, body = self.request('/outpost.goauthentik.io/start?rd=example')
        self.assertEqual((status, body), (200, b'outpost'))
        self.assertTrue(self.auth.requests.empty())


if __name__ == '__main__':
    unittest.main()
