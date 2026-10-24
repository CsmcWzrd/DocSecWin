#!/usr/bin/env python3
"""Optional test driver only. The server has no Python runtime dependency."""
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
PASSWORD = 'test-password-12345'
BASE = '/api/v1/documents'

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name) / 'storage'
        for user in ('Alice', 'alice', 'Bob'):
            subprocess.run([BINARY, 'add-user', str(cls.root), user], input=PASSWORD+'\n', text=True, capture_output=True, check=True)
        s = socket.socket(); s.bind(('127.0.0.1', 0)); cls.port = s.getsockname()[1]; s.close()
        cls.start()

    @classmethod
    def start(cls):
        cls.process = subprocess.Popen([BINARY, 'serve', str(cls.root), str(cls.port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if cls.process.poll() is not None:
                raise RuntimeError(cls.process.stderr.read().decode())
            try:
                c = http.client.HTTPConnection('127.0.0.1', cls.port, timeout=.2)
                c.request('GET', '/healthz'); c.getresponse().read(); c.close(); return
            except OSError:
                time.sleep(.05)
        raise RuntimeError('server startup timeout')

    @classmethod
    def stop(cls):
        cls.process.terminate(); cls.process.wait(timeout=10); cls.process.stderr.close()

    @classmethod
    def tearDownClass(cls):
        cls.stop(); cls.temp.cleanup()

    def call(self, method, path, body=b'', token=None, headers=None):
        h = dict(headers or {})
        if token: h['Authorization'] = 'Bearer '+token
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=20)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse(); result=(r.status,dict(r.getheaders()),r.read()); c.close(); return result

    def login(self, user='Alice', password=PASSWORD):
        auth=base64.b64encode((user+':'+password).encode()).decode()
        status,_,body=self.call('POST','/api/v1/login',headers={'Authorization':'Basic '+auth})
        self.assertEqual(status,200,body)
        return json.loads(body)['token']

    def raw(self, wire):
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as s:
            s.sendall(wire); s.shutdown(socket.SHUT_WR)
            data=b''
            while True:
                part=s.recv(65536)
                if not part: break
                data+=part
        return int(data.split(b' ')[1])

    def test_01_authentication(self):
        self.assertEqual(self.call('GET',BASE)[0],401)
        auth=base64.b64encode(b'Alice:wrongpassword').decode()
        self.assertEqual(self.call('POST','/api/v1/login',headers={'Authorization':'Basic '+auth})[0],401)
        self.assertEqual(self.call('POST','/api/v1/login',headers={'Authorization':'Basic ===='})[0],401)
        token=self.login()
        self.assertEqual(self.call('GET',BASE,token=token)[0],200)
        self.assertEqual(self.call('POST','/api/v1/logout',token=token)[0],204)
        self.assertEqual(self.call('GET',BASE,token=token)[0],401)

    def test_02_hierarchy_binary_and_deletion(self):
        token=self.login(); doc=BASE+'/manual'; section=doc+'/sections/intro'; item=section+'/data/example'
        self.assertEqual(self.call('PUT',section,b'Intro',token)[0],404)
        title='Manual – दस्तावेज़'.encode()
        self.assertEqual(self.call('PUT',doc,title,token)[0],201)
        self.assertEqual(json.loads(self.call('GET',doc,token=token)[2])['title'],title.decode())
        self.assertEqual(self.call('PUT',section,b'Intro',token)[0],201)
        binary=bytes(range(256))*100
        self.assertEqual(self.call('PUT',item,binary,token,{'Content-Type':'application/octet-stream'})[0],201)
        self.assertEqual(self.call('GET',item,token=token)[2],binary)
        status,headers,body=self.call('HEAD',item,token=token)
        self.assertEqual((status,body,headers['Content-Length']),(200,b'',str(len(binary))))
        listing=json.loads(self.call('GET',section+'/data',token=token)[2])
        self.assertEqual([i['id'] for i in listing['items']],['example'])
        self.assertEqual(self.call('PUT',item,b'updated',token)[0],200)
        self.assertEqual(self.call('GET',item,token=token)[2],b'updated')
        self.assertEqual(self.call('DELETE',doc,token=token)[0],409)
        self.assertEqual(self.call('DELETE',doc+'?recursive=true',token=token)[0],204)
        self.assertEqual(self.call('GET',item,token=token)[0],404)
        self.assertEqual(self.call('DELETE',doc,token=token)[0],404)

    def test_03_isolation(self):
        alice=self.login(); bob=self.login('Bob'); lower=self.login('alice')
        path=BASE+'/private'
        self.assertEqual(self.call('PUT',path,b'Alice private',alice)[0],201)
        self.assertEqual(self.call('GET',path,token=bob)[0],404)
        self.assertEqual(self.call('GET',path,token=lower)[0],404)
        self.assertEqual(self.call('PUT',path,b'Bob private',bob)[0],201)
        self.assertEqual(self.call('GET',path,token=alice)[2].find(b'Alice private')>=0,True)
        for user in ('Alice','alice','Bob'):
            directory=self.root/'users'/hashlib.sha256(user.encode()).hexdigest()
            self.assertTrue((directory/'documents.zar').is_file())
            self.assertNotIn(PASSWORD,(directory/'account').read_text())
            if os.name!='nt': self.assertEqual(directory.stat().st_mode&0o777,0o700)

    def test_04_validation(self):
        token=self.login()
        for path in (BASE+'/..',BASE+'/%2e%2e',BASE+'/a/sections/x/data/y/extra',BASE+'/a//b',BASE+'/a/sections/'):
            self.assertEqual(self.call('PUT',path,b'x',token)[0],400,path)
        self.assertEqual(self.call('PUT',BASE+'/badutf8',b'\xff',token)[0],400)
        self.assertEqual(self.call('PUT',BASE+'/longtitle',b'x'*4097,token)[0],400)
        self.assertEqual(self.call('POST',BASE,b'x',token)[0],400)
        self.assertEqual(self.call('GET',BASE+'?unsupported=true',token=token)[0],400)
        self.assertEqual(self.call('GET',BASE+'/missing/sections',token=token)[0],404)

    def test_05_framing(self):
        for wire,expected in [
            (b'GET /healthz HTTP/1.1\r\n\r\n',400),
            (b'GET /healthz HTTP/1.0\r\nHost: x\r\n\r\n',400),
            (b'GET /healthz HTTP/1.1\r\nHost: x\r\nHost: x\r\n\r\n',400),
            (b'POST /api/v1/login HTTP/1.1\r\nHost: x\r\n\r\n',411),
            (b'POST /api/v1/login HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n',501),
            (b'POST /api/v1/login HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n',400),
            (b'PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: 9223372036854775808\r\n\r\n',413),
            (b'POST /api/v1/login HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\na',400),
            (b'GET /healthz HTTP/1.1\r\nHost: x\r\nX: '+b'x'*17000+b'\r\n\r\n',431),
        ]:
            with self.subTest(expected=expected,wire=wire[:100]): self.assertEqual(self.raw(wire),expected)

    def test_06_concurrent_and_restart(self):
        token=self.login()
        def put(i): return self.call('PUT',BASE+'/parallel'+str(i),str(i).encode(),token)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            self.assertEqual(list(executor.map(put,range(24))),[201]*24)
        lock=subprocess.run([BINARY,'add-user',str(self.root),'Blocked'],input=PASSWORD+'\n',text=True,capture_output=True)
        self.assertNotEqual(lock.returncode,0)
        self.stop(); self.start()
        self.assertEqual(self.call('GET',BASE,token=token)[0],401)
        token=self.login()
        for i in range(24): self.assertEqual(self.call('GET',BASE+'/parallel'+str(i),token=token)[0],200)

    def test_07_corruption_is_not_repaired(self):
        token=self.login('Bob')
        archive=self.root/'users'/hashlib.sha256(b'Bob').hexdigest()/'documents.zar'
        original=archive.read_bytes()
        broken=bytearray(original); broken[8192+256+30]^=1
        archive.write_bytes(broken)
        try:
            self.assertEqual(self.call('GET',BASE,token=token)[0],500)
            self.assertEqual(archive.read_bytes(),broken)
        finally: archive.write_bytes(original)

    def test_08_symlink_rejection(self):
        if os.name=='nt': self.skipTest('symlink permissions differ on Windows')
        token=self.login('Bob')
        archive=self.root/'users'/hashlib.sha256(b'Bob').hexdigest()/'documents.zar'
        original=archive.read_bytes(); target=self.root/'outside.zar';target.write_bytes(original)
        archive.unlink();archive.symlink_to(target)
        try:
            self.assertEqual(self.call('PUT',BASE+'/x',b'x',token)[0],500)
            self.assertEqual(target.read_bytes(),original)
        finally: archive.unlink();archive.write_bytes(original)

    def test_09_typed_content_notes_large_and_ranges(self):
        token=self.login(); doc=BASE+'/types'; section=doc+'/sections/files'
        body=json.dumps({'id':'types','title':'Typed files','tags':['manual']}).encode()
        self.assertEqual(self.call('POST',BASE,body,token,{'Content-Type':'application/json'})[0],201)
        self.assertEqual(self.call('POST',doc+'/sections',b'{"id":"files","title":"Files"}',token)[0],201)
        self.assertEqual(self.call('POST',doc+'/notes','Document note'.encode(),token)[0],201)
        self.assertEqual(self.call('PUT',section+'/notes/note','Section note'.encode(),token)[0],201)
        samples=[('ascii','ASCII'.encode('ascii'),'text/plain; charset=us-ascii'),
                 ('utf-8','Hello Ω 文'.encode('utf-8'),'text/plain; charset=utf-8'),
                 ('utf-16le','Hello Ω 文'.encode('utf-16le'),'text/plain; charset=utf-16le'),
                 ('utf-16be','Hello Ω 文'.encode('utf-16be'),'text/plain; charset=utf-16be'),
                 ('utf-32le','Hello Ω 文'.encode('utf-32le'),'text/plain; charset=utf-32le'),
                 ('utf-32be','Hello Ω 文'.encode('utf-32be'),'text/plain; charset=utf-32be'),
                 ('json',b'{"value": [1,2,3]}','application/json'),
                 ('xml',b'<xml-like><item>value</item></xml-like>','application/xml'),
                 ('blob',bytes(range(256))*257,'application/octet-stream')]
        for name,payload,mime in samples:
            path=section+'/data/'+name
            self.assertEqual(self.call('PUT',path,payload,token,{'Content-Type':mime})[0],201)
            self.assertEqual(self.call('GET',path,token=token)[2],payload)
            meta=json.loads(self.call('GET',path+'/metadata',token=token)[2])
            self.assertEqual(meta['sha256'],hashlib.sha256(payload).hexdigest())
            self.assertEqual(self.call('GET',path+'/verify',token=token)[0],200)
        large=bytes(range(256))*65537  # 16 MiB+, larger than the former ingress limit.
        path=section+'/data/large'
        self.assertEqual(self.call('PUT',path,large,token)[0],201)
        self.assertEqual(self.call('GET',path,token=token)[2],large)
        for bounds,expected in [('bytes=65530-65550',large[65530:65551]),('bytes=-19',large[-19:]),('bytes=100-',large[100:])]:
            status,headers,data=self.call('GET',path,token=token,headers={'Range':bounds})
            self.assertEqual((status,data),(206,expected));self.assertIn('Content-Range',headers)
        self.assertEqual(self.call('GET',path,token=token,headers={'Range':'bytes=999999999999-'})[0],416)
        self.assertEqual(self.call('PUT',section+'/data/empty',b'',token)[0],201)
        self.assertEqual(self.call('GET',section+'/data/empty/verify',token=token)[0],200)
        self.assertEqual(self.call('HEAD',section+'/data/empty',token=token)[1]['Content-Length'],'0')
        wire=('PUT '+section+'/data/interrupted HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+token+'\r\nContent-Length: 10\r\n\r\nabc').encode()
        self.assertEqual(self.raw(wire),400)
        self.assertEqual(self.call('GET',section+'/data/interrupted',token=token)[0],404)
        self.assertFalse(list((self.root/'users'/hashlib.sha256(b'Alice').hexdigest()/'payloads').glob('*.tmp')))
        # POST data creates an ID and stores its JSON body unchanged.
        status,_,receipt=self.call('POST',section+'/data',b'{"untouched":true}',token,{'Content-Type':'application/json'})
        self.assertEqual(status,201); created=json.loads(receipt)
        self.assertEqual(self.call('GET',created['url'],token=token)[2],b'{"untouched":true}')

    def test_10_find_chronology_metadata_and_concurrency(self):
        token=self.login();doc=BASE+'/queries';section=doc+'/sections/records'
        self.call('PUT',doc,b'Queries',token);self.call('PUT',section,b'Records',token)
        times=[]
        for i in range(5):
            path=section+'/data/r'+str(i);self.assertEqual(self.call('PUT',path,str(i).encode(),token)[0],201)
            patch={'title':'Record '+str(i),'flags':18446744073709551615 if i==4 else i,'extra':i,'tags':['even' if i%2==0 else 'odd'],'timestamp':100+i,
                   'additional':'ff'*16,'counters':[i]+[0]*13,'attributes':{'score':i,'category':'test'}}
            response=self.call('PATCH',path+'/metadata',json.dumps(patch).encode(),token)
            self.assertEqual(response[0],200,response[2]);times.append(json.loads(response[2])['updated_at'])
        self.assertEqual(times,sorted(set(times)))
        listing=json.loads(self.call('GET',section+'/data?sort=timestamp&order=desc&limit=2&fields=id,timestamp',token=token)[2])
        self.assertEqual([x['id'] for x in listing['items']],['r4','r3'])
        self.assertEqual(set(listing['items'][0]),{'id','timestamp'})
        selective=section+'/data?timestamp_min=101&timestamp_max=103&counter0_min=2&extra=2'
        self.assertEqual([x['id'] for x in json.loads(self.call('GET',selective,token=token)[2])['items']],['r2'])
        query={'selector':{'$and':[{'attributes.score':{'$gte':2}},{'tags':{'$contains':'even'}}]},'sort':[{'timestamp':'desc'}],'fields':['id','flags'],'limit':10}
        status,_,body=self.call('POST',section+'/data/_find',json.dumps(query).encode(),token)
        self.assertEqual(status,200,body);self.assertEqual([x['id'] for x in json.loads(body)['items']],['r4','r2'])
        huge=section+'/data?flags=18446744073709551615'
        self.assertEqual(json.loads(self.call('GET',huge,token=token)[2])['items'][0]['id'],'r4')
        self.assertEqual(self.call('POST',section+'/data/_find',b'{"selector":{"flags":{"$unknown":1}}}',token)[0],400)
        self.assertEqual(self.call('POST',section+'/data/_find',b'{"limit":1,"limit":2}',token)[0],400)
        page=json.loads(self.call('GET',section+'/data?limit=1',token=token)[2])
        next_page=section+'/data?limit=1&offset=1&snapshot='+page['snapshot']
        self.assertEqual(self.call('GET',next_page,token=token)[0],200)
        path=section+'/data/r0';etag=self.call('GET',path+'/metadata',token=token)[1]['ETag']
        self.assertEqual(self.call('PUT',path,b'changed',token,{'If-Match':etag})[0],200)
        self.assertEqual(self.call('PUT',path,b'lost update',token,{'If-Match':etag})[0],412)
        self.assertEqual(self.call('GET',next_page,token=token)[0],409)
        latest=self.call('GET',path,token=token)[1]['ETag']
        self.assertEqual(self.call('GET',path,token=token,headers={'If-None-Match':latest})[0],304)
        self.assertEqual(self.call('PATCH',path,b'{"archive_id":8}',token)[0],400)
        # 100-continue is sent after authorization and item validation.
        with socket.create_connection(('127.0.0.1',self.port),timeout=10) as sock:
            request=('PUT '+section+'/data/expect HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+token+'\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n').encode()
            sock.sendall(request);self.assertEqual(sock.recv(4096),b'HTTP/1.1 100 Continue\r\n\r\n');sock.sendall(b'abc');self.assertIn(b'201 Created',sock.recv(4096))

    def test_11_backend_pull_and_tls(self):
        import http.server
        import ssl
        import threading
        token=self.login();doc=BASE+'/upstream';section=doc+'/sections/s';item=section+'/data/file'
        for path,data in [(doc,b'Upstream'),(section,b'Section'),(doc+'/notes/dn',b'doc note'),(section+'/notes/sn',b'section note'),(item,bytes(range(256))*4097)]:
            self.assertEqual(self.call('PUT',path,data,token)[0],201)
        expected=self.call('GET',item,token=token)[2]
        source_meta=json.loads(self.call('GET',item+'/metadata',token=token)[2])
        cert=Path(self.temp.name)/'peer-cert.pem';key=Path(self.temp.name)/'peer-key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],capture_output=True,check=True)
        class PeerHandler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args): pass
            def do_GET(self):
                if self.headers.get('Authorization')!='Bearer fake-source-token':
                    self.send_response(401);self.send_header('Content-Length','0');self.end_headers();return
                data=json.dumps(source_meta).encode() if self.path.endswith('/metadata') else expected
                self.send_response(200);self.send_header('Content-Length',str(len(data)));self.send_header('ETag','"fixture"');self.end_headers();self.wfile.write(data)
        tls=http.server.ThreadingHTTPServer(('127.0.0.1',0),PeerHandler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);tls.socket=context.wrap_socket(tls.socket,server_side=True)
        thread=threading.Thread(target=tls.serve_forever,daemon=True);thread.start()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'backend'
            for user in ('Receiver','Other'):
                subprocess.run([BINARY,'add-user',str(root),user],input=PASSWORD+'\n',text=True,capture_output=True,check=True)
            (root/'peers.conf').write_text('source http://127.0.0.1:'+str(self.port)+'\ntls https://localhost:'+str(tls.server_port)+'\nwronghost https://127.0.0.1:'+str(tls.server_port)+'\n')
            s=socket.socket();s.bind(('127.0.0.1',0));backend_port=s.getsockname()[1];s.close()
            env=dict(os.environ,SSL_CERT_FILE=str(cert));backend=subprocess.Popen([BINARY,'backend',str(root),str(backend_port)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env)
            original=self.port
            try:
                self.port=backend_port
                for _ in range(100):
                    try:
                        if self.call('GET','/healthz')[0]==200:break
                    except OSError:time.sleep(.03)
                local=self.login('Receiver');other=self.login('Other')
                self.assertEqual(self.call('GET',BASE,token=local)[0],404)
                self.assertEqual(len(json.loads(self.call('GET','/api/v1/internal/peers',token=local)[2])['peers']),3)
                pull={'peer':'source','source_path':doc,'destination_path':BASE+'/copy','source_token':token,'recursive':True}
                status,_,body=self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)
                self.assertEqual(status,200,body);self.assertEqual(json.loads(body)['imported_count'],5)
                dest='/api/v1/internal/local/documents/copy/sections/s/data/file'
                self.assertEqual(self.call('GET',dest,token=local)[2],expected)
                self.assertEqual(self.call('GET',dest,token=other)[0],404)
                self.assertEqual(self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)[0],412)
                pull['overwrite']=True
                self.assertEqual(self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)[0],200)
                meta=json.loads(self.call('GET',dest+'/metadata',token=local)[2]);self.assertEqual(meta['attributes']['_docsec_source']['peer'],'source')
                pull.update(peer='unconfigured')
                self.assertEqual(self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)[0],400)
                pull.update(peer='source',source_path='/admin/secrets')
                self.assertEqual(self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)[0],400)
                pull.update(peer='tls',source_path=item,destination_path=BASE+'/copy/sections/s/data/tls',source_token='fake-source-token',recursive=False)
                status,_,body=self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)
                self.assertEqual(status,200,body)
                pull.update(peer='wronghost',destination_path=BASE+'/copy/sections/s/data/untrusted')
                self.assertEqual(self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)[0],502)
                # A peer-supplied digest mismatch must fail before committing payload metadata.
                source_meta['sha256']='0'*64;pull.update(peer='tls',destination_path=BASE+'/copy/sections/s/data/corrupt')
                status,_,body=self.call('POST','/api/v1/internal/pull',json.dumps(pull).encode(),local)
                self.assertEqual(status,502,body)
                self.assertEqual(self.call('GET','/api/v1/internal/local/documents/copy/sections/s/data/corrupt',token=local)[0],404)
                self.assertNotIn(token,(root/'users'/hashlib.sha256(b'Receiver').hexdigest()/'documents.zar').read_bytes().decode('latin1'))
            finally:
                self.port=original;backend.terminate();backend.wait(timeout=10);backend.stderr.close();tls.shutdown();tls.server_close();thread.join(timeout=10)

    def test_12_legacy_migration_and_offline_gc(self):
        import struct
        token=self.login('Bob');archive=self.root/'users'/hashlib.sha256(b'Bob').hexdigest()/'documents.zar'
        original=archive.read_bytes();raw='Legacy Ω'.encode('utf-16le')
        def string(data):
            if isinstance(data,str):data=data.encode()
            return struct.pack('<Q',len(data))+data
        records=[('old','text/plain; charset=utf-8',b'Old document'),('old/sections/s','text/plain; charset=utf-8',b'Old section'),('old/sections/s/data/b','text/plain; charset=utf-16le',raw)]
        payload=string('DocSecWin/1')+struct.pack('<Q',len(records))
        for key,mime,data in records:payload+=string(key)+string(mime)+string(data)+struct.pack('<Q',1)
        data=hashlib.sha256(payload).hexdigest().encode()+payload;title=b'DocSecWin-snapshot-v1';combined=title+data
        checksum=bytearray(struct.pack('<8Q',0x123456789ABCDEF0,0x0FEDCBA987654321,0xA5A5A5A5A5A5A5A5,0x5A5A5A5A5A5A5A5A,0x1122334455667788,0x8877665544332211,0xCAFEBABEDEADBEEF,0x0BADC0DEFEEDFACE))
        for i,value in enumerate(combined):checksum[i%64]^=value
        blocks=(256+len(combined)+8191)//8192
        header=struct.pack('<6Q14Q64s16sQII',16384 if blocks>1 else 0,0,blocks,1,1,0,*([0]*14),bytes(checksum),bytes(16),len(data),len(title),1)
        fixture=struct.pack('<Q',8192)+bytes(8184)+header+combined+bytes(blocks*8192-256-len(combined))
        archive.write_bytes(fixture)
        try:
            self.assertEqual(self.call('GET',BASE+'/old/sections/s/data/b',token=token)[2],raw)
            self.assertEqual(self.call('PATCH',BASE+'/old',b'{"tags":["migrated"]}',token)[0],200)
            self.assertEqual(self.call('GET',BASE+'/old/sections/s/data/b',token=token)[2],raw)
            self.assertEqual(self.call('GET',BASE+'/old/sections/s/data/b/verify',token=token)[0],200)
            self.assertIn(b'DocSecWin-catalog-v2',archive.read_bytes())
        finally:archive.write_bytes(original)
        # GC is an offline administrator command, excluded while a server holds the root.
        blocked=subprocess.run([BINARY,'gc',str(self.root),'Bob'],capture_output=True)
        self.assertNotEqual(blocked.returncode,0)
        self.stop()
        try:
            gc=subprocess.run([BINARY,'gc',str(self.root),'Bob'],capture_output=True,text=True,check=True)
            self.assertIn('unreferenced payload files removed',gc.stdout)
        finally:self.start()
        token=self.login('Bob');self.assertEqual(self.call('GET',BASE+'/private',token=token)[0],200)

if __name__=='__main__': unittest.main(verbosity=2)


