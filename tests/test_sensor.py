import asyncio
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from honeypot import Sensor, Store, signals


class SensorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name, 16*1024*1024)
        self.sensor = Sensor(self.store, max_bytes=8192, timeout=.15)
        self.server = await asyncio.start_server(self.sensor.handle, '127.0.0.1', 0)
        self.sensor.server = self.server
        self.port = self.server.sockets[0].getsockname()[1]
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stdout.__enter__()

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.store.db.close()
        self.stdout.__exit__(None,None,None)
        self.temp.cleanup()

    async def send(self, payload, eof=False):
        r,w = await asyncio.open_connection('127.0.0.1', self.port)
        w.write(payload)
        await w.drain()
        if eof:
            w.write_eof()
        response = await r.read()
        w.close()
        await w.wait_closed()
        row = self.store.db.execute('SELECT metadata,raw_file,raw_sha256 FROM events ORDER BY rowid DESC LIMIT 1').fetchone()
        self.assertIsNotNone(row)
        raw = (Path(self.temp.name)/row[1]).read_bytes()
        self.assertEqual(raw, payload)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), row[2])
        return json.loads(row[0]), response

    async def test_get(self):
        meta, response = await self.send(b'GET /index.php?q=%ff HTTP/1.1\r\nHost: bait\r\n\r\n')
        self.assertTrue(meta['complete'])
        self.assertIn(b'200 OK', response)

    async def test_binary_upload(self):
        body = b'--x\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n\x00\xff<?php\r\n--x--\r\n'
        payload = b'POST /upload.php HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        meta,_ = await self.send(payload)
        self.assertIn('session_upload_progress_marker',meta['signals'])
        self.assertIn('code_or_command_marker',meta['signals'])

    async def test_chunked_trailer(self):
        meta,_ = await self.send(b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: yes\r\n\r\n')
        self.assertTrue(meta['complete'])

    async def test_ambiguous_framing(self):
        meta,_ = await self.send(b'POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n')
        self.assertEqual(meta['error'],'ambiguous_framing')

    async def test_duplicate_headers_preserved(self):
        meta,_ = await self.send(b'GET / HTTP/1.1\r\nX-A: 1\r\nX-A: 2\r\n\r\n')
        self.assertEqual(meta['headers'],[['X-A','1'],['X-A','2']])

    async def test_incomplete_body(self):
        meta,_ = await self.send(b'POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\nabc',True)
        self.assertEqual(meta['error'],'incomplete_body')

    async def test_slow_body_timeout(self):
        meta,_ = await self.send(b'POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\nabc')
        self.assertEqual(meta['error'],'timeout')

    async def test_invalid_chunk(self):
        meta,_ = await self.send(b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n')
        self.assertEqual(meta['error'],'invalid_chunk_size')

    async def test_malformed_request(self):
        meta,_ = await self.send(b'garbage\r\n\r\n')
        self.assertFalse(meta['complete'])
        self.assertEqual(meta['error'],'invalid_request_line')

    async def test_size_limit(self):
        self.sensor.max_bytes = 100
        r,w = await asyncio.open_connection('127.0.0.1',self.port)
        w.write(b'POST / HTTP/1.1\r\nContent-Length: 999\r\n\r\n'+b'A'*200)
        await w.drain()
        await r.read()
        w.close()
        await w.wait_closed()
        meta,n = self.store.db.execute('SELECT metadata,raw_bytes FROM events').fetchone()
        self.assertEqual(n,100)
        self.assertEqual(json.loads(meta)['error'],'capture_limit')

    async def test_quota_stops_listener(self):
        self.store.quota=1
        r,w=await asyncio.open_connection('127.0.0.1', self.port)
        w.write(b'GET / HTTP/1.1\r\n\r\n')
        await w.drain()
        await r.read()
        w.close()
        await w.wait_closed()
        self.assertIn('quota',self.sensor.fatal)
        self.assertFalse(self.server.is_serving())

    async def test_unframed_multipart(self):
        payload = b'POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=x\r\n\r\n--x\r\nabc'
        meta,_ = await self.send(payload,True)
        self.assertEqual(meta['framing'],'unframed_multipart')
        self.assertIn('multipart_without_content_length',meta['signals'])

    async def test_capacity_rejection(self):
        self.sensor.max_connections=0
        r,w=await asyncio.open_connection('127.0.0.1',self.port)
        self.assertEqual(await r.read(),b'')
        w.close()
        await w.wait_closed()
        self.assertEqual(self.sensor.dropped,1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM events').fetchone()[0],0)

    async def test_expect_continue(self):
        r,w=await asyncio.open_connection('127.0.0.1',self.port)
        w.write(b'POST / HTTP/1.1\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n')
        await w.drain()
        self.assertIn(b'100 Continue',await r.readuntil(b'\r\n\r\n'))
        w.write(b'abc')
        await w.drain()
        self.assertIn(b'200 OK',await r.read())
        w.close()
        await w.wait_closed()


if __name__ == '__main__':
    unittest.main()
