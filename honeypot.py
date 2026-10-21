#!/usr/bin/env python3
"""PHP2Shell Honeypot 0.2.0: inert HTTP/1.x evidence collector. No PHP runtime."""
import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import time
import uuid

VERSION = '0.2.0'
HEADER_LIMIT = 65536
RESPONSE = (b'HTTP/1.1 200 OK\r\nServer: Apache\r\nX-Powered-By: PHP/8.5.11\r\n'
            b'Content-Type: text/html; charset=UTF-8\r\nContent-Length: 100\r\nConnection: close\r\n\r\n')
PAGE = b'<!doctype html><title>Upload</title><form method="post" enctype="multipart/form-data"><input type="file" name="file"><input type="submit"></form>'
RESPONSE = RESPONSE.replace(b'Content-Length: 100', b'Content-Length: ' + str(len(PAGE)).encode()) + PAGE


def signals(headers, body):
    """Heuristics only; do not assign CVE confirmation from wire evidence."""
    out = []
    content_type = b' '.join(v for k, v in headers if k.lower() == b'content-type').lower()
    if b'multipart/form-data' in content_type:
        out.append('multipart_upload')
        if not any(k.lower() == b'content-length' for k, _ in headers):
            out.append('multipart_without_content_length')
        if body.lower().count(b'filename=""') >= 16:
            out.append('many_empty_file_controls')
        if body.count(b'[') >= 64:
            out.append('nested_field_or_payload_density')
        if len(re.findall(br'(?m)^[^\r\n:]{1,128}:', body)) >= 128:
            out.append('multipart_header_density')
    if b'PHP_SESSION_UPLOAD_PROGRESS' in body:
        out.append('session_upload_progress_marker')
    if any(x in body.lower() for x in (b'<?php', b'<?=', b'/bin/sh', b'powershell', b'base64_decode(')):
        out.append('code_or_command_marker')
    return out


class Store:
    def __init__(self, path, quota):
        self.path = Path(path)
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path / 'events.sqlite3')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, time TEXT NOT NULL, peer TEXT, local TEXT,
            metadata TEXT NOT NULL, raw_file TEXT, raw_sha256 TEXT, raw_bytes INTEGER NOT NULL)''')
        self.db.commit()
        self.quota = quota
        self.used = sum(p.stat().st_size for p in self.path.iterdir() if p.is_file())

    def save(self, raw, metadata, peer, local):
        # Single event-loop thread: quota reservation and writes cannot race.
        event_id = uuid.uuid4().hex
        stamp = datetime.now(timezone.utc).isoformat()
        metadata['signals'] = signals(metadata.pop('_headers', []), metadata.pop('_body', b''))
        metadata['capture_version'] = VERSION
        # Reserve enough for SQLite row/page overhead. Stop acceptance before quota,
        # never silently delete evidence or silently discard a capture.
        cost = len(raw) + len(json.dumps(metadata)) + 16384
        if self.used + cost > self.quota:
            raise OSError('capture quota reached; collection stopped')
        filename = event_id + '.raw'
        with (self.path / filename).open('xb') as f:
            f.write(raw)
        digest = hashlib.sha256(raw).hexdigest()
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)',
                        (event_id, stamp, json.dumps(peer), json.dumps(local),
                         json.dumps(metadata), filename, digest, len(raw)))
        self.db.commit()
        self.used += cost
        print(json.dumps({'id': event_id, 'time': stamp, 'peer': peer,
                          'bytes': len(raw), **metadata}), flush=True)


class Sensor:
    def __init__(self, store, max_bytes=16*1024*1024, timeout=30, max_connections=4):
        self.store, self.max_bytes, self.timeout = store, max_bytes, timeout
        self.max_connections = max_connections
        self.active = 0
        self.dropped = 0
        self.fatal = None
        self.server = None

    async def handle(self, reader, writer):
        if self.active >= self.max_connections or self.fatal:
            self.dropped += 1
            print(json.dumps({'event': 'connection_rejected', 'peer': writer.get_extra_info('peername'),
                              'reason': 'capacity_or_storage', 'rejected_total': self.dropped}), flush=True)
            writer.close()
            await writer.wait_closed()
            return
        self.active += 1
        raw = bytearray()
        headers = []
        meta = {'complete': False, 'error': None, 'headers': [], 'tls': bool(writer.get_extra_info('ssl_object'))}
        start = time.monotonic()
        async def read(n):
            if len(raw) >= self.max_bytes:
                raise ValueError('capture_limit')
            data = await reader.read(min(n, self.max_bytes - len(raw), 65536))
            raw.extend(data)
            return data
        try:
            async with asyncio.timeout(self.timeout):
                # Headers may be malformed: retain bytes even when parsing fails.
                while b'\r\n\r\n' not in raw:
                    if len(raw) >= HEADER_LIMIT:
                        raise ValueError('header_limit')
                    if not await read(min(4096, HEADER_LIMIT-len(raw))):
                        raise ValueError('incomplete_headers')
                split = raw.index(b'\r\n\r\n') + 4
                lines = bytes(raw[:split-4]).split(b'\r\n')
                request = lines[0].split(b' ')
                if len(request) != 3 or request[2] not in (b'HTTP/1.0', b'HTTP/1.1'):
                    raise ValueError('invalid_request_line')
                meta.update(method=request[0].decode('latin1'), target=request[1].decode('latin1'),
                            http_version=request[2].decode('ascii'))
                for line in lines[1:]:
                    key, sep, value = line.partition(b':')
                    if not sep or not re.fullmatch(br"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                        raise ValueError('invalid_header')
                    headers.append((key, value.strip()))
                meta['headers'] = [[k.decode('latin1'), v.decode('latin1')] for k,v in headers]
                lengths = [v for k,v in headers if k.lower() == b'content-length']
                encodings = [v.lower() for k,v in headers if k.lower() == b'transfer-encoding']
                if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
                    raise ValueError('ambiguous_framing')
                if any(k.lower() == b'expect' and v.lower() == b'100-continue' for k,v in headers):
                    writer.write(b'HTTP/1.1 100 Continue\r\n\r\n')
                    await writer.drain()
                if lengths:
                    if not re.fullmatch(br'[0-9]{1,20}', lengths[0]):
                        raise ValueError('invalid_content_length')
                    expected = int(lengths[0])
                    meta['declared_body_bytes'] = expected
                    while len(raw)-split < expected:
                        if not await read(expected-(len(raw)-split)):
                            raise ValueError('incomplete_body')
                    meta['body_end_offset'] = split + expected
                elif encodings:
                    if encodings != [b'chunked']:
                        raise ValueError('unsupported_transfer_encoding')
                    pos = split
                    while True:
                        while raw.find(b'\r\n', pos) < 0:
                            if not await read(4096):
                                raise ValueError('incomplete_chunk_size')
                        end = raw.index(b'\r\n', pos)
                        value = bytes(raw[pos:end]).split(b';',1)[0]
                        if not re.fullmatch(br'[0-9a-fA-F]{1,16}', value):
                            raise ValueError('invalid_chunk_size')
                        size = int(value,16)
                        pos = end+2
                        if not size:
                            while True:
                                end = raw.find(b'\r\n', pos)
                                if end < 0:
                                    if not await read(4096):
                                        raise ValueError('incomplete_trailer')
                                    continue
                                if end == pos:
                                    pos += 2
                                    break
                                pos = end+2
                            break
                        while len(raw) < pos+size+2:
                            if not await read(pos+size+2-len(raw)):
                                raise ValueError('incomplete_chunk')
                        if raw[pos+size:pos+size+2] != b'\r\n':
                            raise ValueError('invalid_chunk_terminator')
                        pos += size+2
                    meta['body_end_offset'] = pos
                else:
                    if any(k.lower() == b'content-type' and b'multipart/form-data' in v.lower() for k,v in headers):
                        # Framing is absent: capture until EOF or the total deadline.
                        meta['framing'] = 'unframed_multipart'
                        while await read(65536):
                            pass
                    meta['body_end_offset'] = len(raw) if meta.get('framing') else split
                meta['header_end_offset'] = split
                meta['extra_bytes_observed'] = max(0,len(raw)-meta['body_end_offset'])
                meta['complete'] = True
        except TimeoutError:
            meta['error'] = 'timeout'
        except (ValueError, ConnectionError, OSError) as exc:
            meta['error'] = str(exc)[:200]
        finally:
            meta['duration_ms'] = round((time.monotonic()-start)*1000)
            meta['_headers'] = headers
            split = bytes(raw).find(b'\r\n\r\n')
            meta['_body'] = bytes(raw[split+4:]) if split >= 0 else b''
            try:
                self.store.save(bytes(raw), meta, writer.get_extra_info('peername'), writer.get_extra_info('sockname'))
            except (OSError, sqlite3.Error) as exc:
                self.fatal = str(exc)
                print(json.dumps({'event':'storage_failure', 'error':str(exc), 'collection':'stopped'}), flush=True)
                if self.server:
                    self.server.close()
            finally:
                if not self.fatal:
                    try:
                        writer.write(RESPONSE)
                        await asyncio.wait_for(writer.drain(), 2)
                    except (OSError, TimeoutError):
                        pass
                self.active -= 1
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ConnectionError):
                    pass


async def serve(args):
    os.umask(0o077)
    if args.max_bytes <= 0 or args.quota_mib < 1 or args.timeout <= 0 or args.max_connections < 1:
        raise ValueError('limits must be positive')
    ctx = None
    if bool(args.cert) != bool(args.key):
        raise ValueError('--cert and --key must be supplied together')
    if args.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(['http/1.1'])
        ctx.load_cert_chain(args.cert, args.key)
    store = Store(args.data, args.quota_mib*1024*1024)
    sensor = Sensor(store, args.max_bytes, args.timeout, args.max_connections)
    server = await asyncio.start_server(sensor.handle, args.host, args.port, ssl=ctx,
                                        backlog=128, ssl_handshake_timeout=10 if ctx else None)
    sensor.server = server
    print(json.dumps({'event':'listening', 'addresses':[str(s.getsockname()) for s in server.sockets],
                      'tls':bool(ctx), 'version':VERSION}), flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        store.db.close()


def report(args):
    # Read-only URI: a typo must not create an empty database and suggest health.
    path = Path(args.data, 'events.sqlite3').resolve()
    db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)
    rows = db.execute('SELECT time, peer, metadata, raw_bytes FROM events ORDER BY time DESC LIMIT ?', (args.limit,)).fetchall()
    counts = Counter()
    for _, _, metadata, _ in rows:
        counts.update(json.loads(metadata).get('signals', []))
    print(json.dumps({'sample_limit':args.limit, 'events_in_sample':len(rows),
                      'signals':dict(counts), 'recent':[{'time':r[0], 'peer':json.loads(r[1]),
                        'bytes':r[3], **json.loads(r[2])} for r in rows[:args.recent]]}, indent=2))
    db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('serve')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8080)
    p.add_argument('--data', default='data')
    p.add_argument('--max-bytes', type=int, default=16*1024*1024)
    p.add_argument('--quota-mib', type=int, default=4096)
    p.add_argument('--timeout', type=float, default=30)
    p.add_argument('--max-connections', type=int, default=4)
    p.add_argument('--cert')
    p.add_argument('--key')
    p = sub.add_parser('report')
    p.add_argument('--data', default='data')
    p.add_argument('--limit', type=int, default=10000)
    p.add_argument('--recent', type=int, default=20)
    args = parser.parse_args()
    if args.command == 'serve':
        try:
            asyncio.run(serve(args))
        except KeyboardInterrupt:
            pass
    else:
        if args.limit < 1 or args.recent < 0:
            parser.error('report bounds must be positive (recent may be zero)')
        report(args)


if __name__ == '__main__':
    main()
