#!/usr/bin/env python3
"""Isolated regression fixtures for client-identifier gathering triggers.

No existing database is touched. Two backend servers and optional IPv6 fixtures
are provisioned in private temporary folders and stopped on completion.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
PASSWORD = 'regression-password-12345'
PUBLIC = '/api/v1/documents'
LOCAL = '/api/v1/internal/local/documents'


def call(host, port, method, path, token=None, body=b'', headers=None):
    values = dict(headers or {})
    if token:
        values['Authorization'] = 'Bearer ' + token
    connection = http.client.HTTPConnection(host, port, timeout=30)
    try:
        connection.request(method, path, body=body, headers=values)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def free_port(host='127.0.0.1'):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def login(host, port, username):
    basic = base64.b64encode((username + ':' + PASSWORD).encode()).decode()
    status, _, body = call(host, port, 'POST', '/api/v1/login',
                           headers={'Authorization': 'Basic ' + basic})
    if status != 200:
        raise RuntimeError('fixture login failed with status ' + str(status))
    return json.loads(body)['token']


class TriggerRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='docsec-regression-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.processes = []
        cls.addClassCleanup(cls.stop_all)
        cls.directory = Path(cls.temporary.name)
        cls.source_root = cls.directory / 'source'
        cls.front_root = cls.directory / 'front'
        cls.provision(cls.source_root, 'Source')
        cls.provision(cls.front_root, 'Collector')
        cls.provision(cls.front_root, 'Other')
        cls.source_port = free_port()
        cls.start(cls.source_root, cls.source_port)
        cls.source_token = login('127.0.0.1', cls.source_port, 'Source')
        cls.data = {}
        fixtures = [(LOCAL + '/gather', b'Gathering document', 'text/plain'),
                    (LOCAL + '/gather/sections/items', b'Gathering section', 'text/plain')]
        for i in range(6):
            payload = ('Information ' + str(i) + ' Ω 文').encode('utf-8')
            key = '/gather/sections/items/data/r' + str(i)
            cls.data[key] = payload
            fixtures.append((LOCAL + key, payload, 'text/plain; charset=utf-8'))
        fixtures += [(LOCAL + '/gather/notes/document-note', b'Document note', 'text/plain'),
                     (LOCAL + '/gather/sections/items/notes/section-note', b'Section note', 'text/plain')]
        for path, payload, mime in fixtures:
            status, _, _ = call('127.0.0.1', cls.source_port, 'PUT', path, cls.source_token,
                                payload, {'Content-Type': mime})
            if status != 201:
                raise RuntimeError('source fixture creation failed')
        cls.v6_available = False
        try:
            cls.v6_port = free_port('::1')
            cls.v6_root = cls.directory / 'source-v6'
            cls.provision(cls.v6_root, 'SourceIPv6')
            cls.start(cls.v6_root, cls.v6_port, '::1')
            cls.v6_token = login('::1', cls.v6_port, 'SourceIPv6')
            for path, payload in [(LOCAL + '/ipv6', b'IPv6 document'),
                                  (LOCAL + '/ipv6/sections/s', b'IPv6 section'),
                                  (LOCAL + '/ipv6/sections/s/data/blob', b'IPv6 content\x00\xff')]:
                if call('::1', cls.v6_port, 'PUT', path, cls.v6_token, payload)[0] != 201:
                    raise RuntimeError('IPv6 source fixture creation failed')
            cls.v6_available = True
        except OSError:
            pass
        peers = ('ip http://127.0.0.1:' + str(cls.source_port) + ' internal\n'
                 'dns http://localhost:' + str(cls.source_port) + ' internal\n')
        if cls.v6_available:
            peers += 'ipv6 http://[::1]:' + str(cls.v6_port) + ' internal\n'
        (cls.front_root / 'peers.conf').write_text(peers)
        (cls.front_root / 'cors.conf').write_text('https://processor.example\n')
        cls.front_port = free_port()
        cls.start(cls.front_root, cls.front_port)
        cls.local_token = login('127.0.0.1', cls.front_port, 'Collector')
        cls.other_token = login('127.0.0.1', cls.front_port, 'Other')

    @classmethod
    def provision(cls, root, user):
        result = subprocess.run([BINARY, 'add-user', str(root), user],
                                input=PASSWORD + '\n', text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError('fixture user creation failed: ' + result.stderr)

    @classmethod
    def start(cls, root, port, host='127.0.0.1'):
        process = subprocess.Popen([BINARY, 'backend', str(root), str(port), host],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        cls.processes.append(process)
        for _ in range(150):
            if process.poll() is not None:
                raise RuntimeError('fixture server exited: ' + process.stderr.read().decode())
            try:
                if call(host, port, 'GET', '/healthz')[0] == 200:
                    return process
            except OSError:
                time.sleep(.03)
        raise RuntimeError('fixture startup timeout')

    @classmethod
    def stop_all(cls):
        for process in reversed(cls.processes):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
            if process.stderr:
                process.stderr.close()

    def front(self, method, path, token=None, body=b'', headers=None):
        return call('127.0.0.1', self.front_port, method, path,
                    token or self.local_token, body, headers)

    def trigger(self, path, *, target='127.0.0.1', identifier='Client-Identifier',
                token=None, source_token=None, method='GET', body=b'', extra=None):
        headers = {identifier: 'regression-client; pretend-to-be-client:' + target,
                   'X-DocSec-Source-Authorization': 'Bearer ' + (source_token or self.source_token)}
        headers.update(extra or {})
        response = self.front(method, path, token, body, headers)
        self.assertEqual(response[2], b'', 'trigger must never return information or receipts')
        self.assertEqual(response[1].get('Content-Length'), '0')
        return response

    def test_01_ipv4_trigger_creates_missing_parents_and_stores(self):
        key = '/gather/sections/items/data/r0'
        status, headers, content = self.trigger(PUBLIC + key)
        self.assertEqual((status, content), (200, b''))
        self.assertEqual(self.front('GET', LOCAL + key)[2], self.data[key])
        self.assertEqual(self.front('GET', LOCAL + '/gather')[0], 200)
        self.assertEqual(self.front('GET', LOCAL + '/gather/sections/items')[0], 200)
        self.assertEqual(self.front('GET', PUBLIC + key)[0], 404)
        metadata = json.loads(self.front('GET', LOCAL + key + '/metadata')[2])
        self.assertEqual(metadata['attributes']['_docsec_source']['peer'], 'ip')
        user = self.front_root / 'users' / hashlib.sha256(b'Collector').hexdigest()
        self.assertTrue((user / 'documents.zar').is_file())
        self.assertTrue(list((user / 'payloads').glob('*.zar')))

    def test_02_hostname_alias_and_user_agent_marker(self):
        key = '/gather/sections/items/data/r1'
        status, headers, content = self.trigger(PUBLIC + key, target='LOCALHOST.', identifier='X-Client-Identifier')
        self.assertEqual((status, content), (200, b''))
        key = '/gather/sections/items/data/r2'
        self.assertEqual(self.trigger(LOCAL + key, identifier='User-Agent')[2], b'')

    def test_03_unchanged_content_does_not_create_new_revision(self):
        key = '/gather/sections/items/data/r3'
        self.assertEqual(self.trigger(PUBLIC + key)[0], 200)
        before = json.loads(self.front('GET', LOCAL + key + '/metadata')[2])
        status, headers, _ = self.trigger(PUBLIC + key)
        after = json.loads(self.front('GET', LOCAL + key + '/metadata')[2])
        self.assertEqual(status, 200)
        self.assertEqual(after['revision'], before['revision'])
        changed = b'Changed source information\x00'
        self.assertEqual(call('127.0.0.1', self.source_port, 'PUT', LOCAL + key,
                              self.source_token, changed)[0], 200)
        self.assertEqual(self.trigger(PUBLIC + key)[2], b'')
        self.assertEqual(self.front('GET', LOCAL + key)[2], changed)

    def test_04_selected_list_is_persisted_without_leaking_projection(self):
        path = PUBLIC + '/gather/sections/items/data?sort=id&order=desc&limit=2&fields=id'
        status, _, body = self.trigger(path)
        self.assertEqual(status, 200, body)
        self.assertEqual(body, b'')
        # A separate authenticated local query returns stored information.
        local_path = LOCAL + '/gather/sections/items/data?sort=id&order=desc&limit=2&fields=id'
        values = json.loads(self.front('GET', local_path)[2])
        self.assertEqual([item['id'] for item in values['items']], ['r5', 'r4'])
        self.assertEqual(set(values['items'][0]), {'id'})
        for name in ('r5', 'r4'):
            self.assertEqual(self.front('GET', LOCAL + '/gather/sections/items/data/' + name)[0], 200)
        # Source snapshot tokens are deliberately not returned by a gathering trigger.
        source_values = json.loads(call('127.0.0.1', self.source_port, 'GET',
                                       path.replace(PUBLIC, LOCAL, 1), self.source_token)[2])
        follow = path + '&offset=2&snapshot=' + source_values['snapshot']
        self.assertEqual(self.trigger(follow)[0], 200)

    def test_05_post_find_query_trigger(self):
        query = {'selector': {'id': {'$in': ['r0', 'r2']}},
                 'sort': [{'id': 'desc'}], 'fields': ['id', 'url'], 'limit': 10}
        path = PUBLIC + '/gather/sections/items/data/_find'
        status, _, body = self.trigger(path, method='POST', body=json.dumps(query).encode(),
                                       extra={'Content-Type': 'application/json'})
        self.assertEqual(status, 200, body)
        self.assertEqual(body, b'')
        values = json.loads(self.front('POST', path.replace(PUBLIC, LOCAL, 1),
                                             body=json.dumps(query).encode())[2])['items']
        self.assertEqual([item['id'] for item in values], ['r2', 'r0'])
        self.assertTrue(all('/gather/sections/items/data/' in item['url'] for item in values))
        query['fields'] = ['id'] * 64
        status, _, body = self.trigger(path + '?limit=1', method='POST', body=json.dumps(query).encode())
        self.assertEqual(status, 200, body)
        self.assertEqual(body, b'')
        query['fields'] = ['unknown' + str(i) for i in range(64)]
        status, _, body = self.trigger(path, method='POST', body=json.dumps(query).encode())
        self.assertEqual(status, 200, body)
        self.assertEqual(body, b'')

    def test_06_ranges_and_metadata_follow_local_commit(self):
        key = '/gather/sections/items/data/r4'
        payload = self.data[key]
        status, headers, body = self.trigger(PUBLIC + key, extra={'Range': 'bytes=2-8'})
        self.assertEqual((status, body), (200, b''))
        self.assertNotIn('Content-Range', headers)
        self.assertEqual(self.front('GET', LOCAL + key, headers={'Range': 'bytes=2-8'})[2], payload[2:9])
        self.assertEqual(self.front('GET', LOCAL + key)[2], payload)
        status, _, body = self.trigger(PUBLIC + key + '/metadata')
        self.assertEqual(status, 200)
        self.assertEqual(body, b'')
        metadata = self.front('GET', LOCAL + key + '/metadata')[2]
        self.assertEqual(json.loads(metadata)['sha256'], hashlib.sha256(payload).hexdigest())

    def test_07_note_trigger(self):
        for key, expected in [('/gather/notes/document-note', b'Document note'),
                              ('/gather/sections/items/notes/section-note', b'Section note')]:
            self.assertEqual(self.trigger(PUBLIC + key)[2], b'')
            self.assertEqual(self.front('GET', LOCAL + key)[2], expected)

    def test_08_authentication_and_local_user_isolation(self):
        key = '/gather/sections/items/data/r0'
        marker = {'Client-Identifier': 'pretend-to-be-client:127.0.0.1',
                  'X-DocSec-Source-Authorization': 'Bearer ' + self.source_token}
        denied = call('127.0.0.1', self.front_port, 'GET', PUBLIC + key, headers=marker)
        self.assertEqual((denied[0], denied[2]), (401, b''))
        self.assertEqual(call('127.0.0.1', self.front_port, 'GET', LOCAL + key)[0], 401)
        self.assertEqual(self.trigger(PUBLIC + key, source_token='invalid-remote-token')[0], 502)
        self.assertEqual(self.front('GET', LOCAL + key, self.other_token)[0], 404)
        self.assertEqual(self.trigger(PUBLIC + key, token=self.other_token)[0], 200)
        self.assertEqual(self.front('GET', LOCAL + key, self.other_token)[2], self.data[key])
        # Local credentials are never silently forwarded as the peer's credentials.
        self.assertEqual(self.front('GET', PUBLIC + key, headers={'Client-Identifier': 'pretend-to-be-client:127.0.0.1'})[0], 400)
        for token in (self.source_token, self.local_token):
            for file in (self.front_root / 'users').glob('*/documents.zar'):
                self.assertNotIn(token.encode(), file.read_bytes())

    def test_09_invalid_targets_markers_and_mutations(self):
        path = PUBLIC + '/gather'
        for target in ('https://127.0.0.1', '127.0.0.1/admin', '127.0.0.1:0',
                       '127.0.0.1:65536', '[::1', '[localhost]', '127.0.0.1%00'):
            with self.subTest(target=target):
                self.assertEqual(self.trigger(path, target=target)[0], 400)
        self.assertEqual(self.trigger(path, target='unconfigured.example')[0], 403)
        self.assertEqual(self.front('GET', path, headers={'Client-Identifier': 'pretend-to-be-client:'})[0], 400)
        self.assertEqual(self.trigger(path, extra={'X-Client-Identifier': 'pretend-to-be-client:127.0.0.1'})[0], 400)
        self.assertEqual(self.trigger(path, method='DELETE')[0], 405)
        self.assertEqual(self.trigger('/api/v1/internal/peers')[0], 400)
        self.assertEqual(self.trigger(PUBLIC + '/gather/../private')[0], 400)
        self.assertEqual(self.trigger(PUBLIC + '/gather/sections/items/data?selector=%7B%22id%22%3A%22r0%22%7D')[0], 200)

    def test_10_browser_cors_preflight_and_actual_request(self):
        origin = 'https://processor.example'
        headers = {'Origin': origin, 'Access-Control-Request-Method': 'GET',
                   'Access-Control-Request-Headers': 'authorization,client-identifier,x-docsec-source-authorization'}
        status, values, _ = call('127.0.0.1', self.front_port, 'OPTIONS', PUBLIC + '/gather', headers=headers)
        self.assertEqual(status, 204)
        self.assertEqual(values['Access-Control-Allow-Origin'], origin)
        self.assertIn('client-identifier', values['Access-Control-Allow-Headers'])
        status, values, _ = self.trigger(PUBLIC + '/gather', extra={'Origin': origin})
        self.assertEqual(status, 200)
        self.assertEqual(values['Access-Control-Allow-Origin'], origin)
        headers['Origin'] = 'https://unconfigured.example'
        self.assertEqual(call('127.0.0.1', self.front_port, 'OPTIONS', PUBLIC + '/gather', headers=headers)[0], 403)
        status, values, _ = call('127.0.0.1', self.front_port, 'GET', PUBLIC + '/gather', headers={'Origin': origin})
        self.assertEqual(status, 401)
        self.assertEqual(values['Access-Control-Allow-Origin'], origin)

    def test_11_ipv6_literal_and_expanded_equivalent(self):
        if not self.v6_available:
            self.skipTest('IPv6 loopback unavailable on this host')
        path = PUBLIC + '/ipv6/sections/s/data/blob'
        for target in ('::1', '[::1]:' + str(self.v6_port), '0:0:0:0:0:0:0:1'):
            status, values, body = self.trigger(path, target=target, source_token=self.v6_token)
            self.assertEqual((status, body), (200, b''))
            self.assertEqual(self.front('GET', path.replace(PUBLIC, LOCAL, 1))[2], b'IPv6 content\x00\xff')

    def test_12_curl_client(self):
        curl = shutil.which('curl.exe' if os.name == 'nt' else 'curl')
        if not curl:
            self.skipTest('curl is not installed')
        path = '/gather/sections/items/data/r5'
        result = subprocess.run([curl, '--noproxy', '*', '--http1.1', '--fail', '--silent', '--show-error',
                                 '-H', 'Authorization: Bearer ' + self.local_token,
                                 '-H', 'Client-Identifier: curl-client; pretend-to-be-client:localhost:' + str(self.source_port),
                                 '-H', 'X-DocSec-Source-Authorization: Bearer ' + self.source_token,
                                 'http://127.0.0.1:' + str(self.front_port) + PUBLIC + path],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(self.front('GET', LOCAL + path)[2], self.data[path])

    def test_13_restart_persistence_and_ambiguous_target(self):
        root = self.directory / 'ambiguous'
        self.provision(root, 'Ambiguous')
        (root / 'peers.conf').write_text('first http://127.0.0.1:' + str(self.source_port) + ' internal\nsecond http://127.0.0.1:1 internal\n')
        port = free_port()
        process = self.start(root, port)
        token = login('127.0.0.1', port, 'Ambiguous')
        headers = {'Client-Identifier': 'pretend-to-be-client:127.0.0.1',
                   'X-DocSec-Source-Authorization': 'Bearer ' + self.source_token}
        self.assertEqual(call('127.0.0.1', port, 'GET', PUBLIC + '/gather', token, headers=headers)[0], 409)
        headers['Client-Identifier'] += ':' + str(self.source_port)
        self.assertEqual(call('127.0.0.1', port, 'GET', PUBLIC + '/gather', token, headers=headers)[0], 200)
        process.terminate();process.wait(timeout=15)
        restarted = self.start(root, port)
        token = login('127.0.0.1', port, 'Ambiguous')
        self.assertEqual(call('127.0.0.1', port, 'GET', LOCAL + '/gather', token)[0], 200)
        restarted.terminate();restarted.wait(timeout=15)


if __name__ == '__main__':
    unittest.main(verbosity=2)
