#!/usr/bin/env python3
"""Synthetic localhost TLS check of the Rust executable. No external target."""
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/php2shell').resolve())
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=localhost'], check=True, capture_output=True)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    data = root / 'evidence'
    # File-backed diagnostics cannot fill a pipe and stall the server.
    with (root / 'output.log').open('wb') as output:
        process = subprocess.Popen([binary, 'serve', '--port', str(port), '--data', str(data),
                                    '--cert', str(cert), '--key', str(key)], stdout=output, stderr=output)
        try:
            context = ssl.create_default_context(cafile=str(cert))
            context.set_alpn_protocols(['http/1.1'])
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise AssertionError('TLS sensor exited: ' + (root / 'output.log').read_text())
                try:
                    raw = socket.create_connection(('127.0.0.1', port), timeout=2)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError('TLS sensor startup timed out')
                    time.sleep(.05)
            request = b'GET /upload.php HTTP/1.1\r\nHost: localhost\r\n\r\n'
            with context.wrap_socket(raw, server_hostname='localhost') as client:
                assert client.selected_alpn_protocol() == 'http/1.1'
                client.sendall(request)
                response = bytearray()
                while chunk := client.recv(4096):
                    response.extend(chunk)
                assert response.startswith(b'HTTP/1.1 200 OK')
            with sqlite3.connect(data / 'events.sqlite3') as db:
                row = db.execute('SELECT metadata,raw_file,raw_sha256 FROM events').fetchone()
            assert json.loads(row[0])['tls'] is True
            assert (data / row[1]).read_bytes() == request
            assert hashlib.sha256(request).hexdigest() == row[2]
            health = subprocess.run([binary, 'health', '--data', str(data)], capture_output=True)
            assert health.returncode == 0, health.stderr
            print('PASS: Rust TLS, ALPN HTTP/1.1, decrypted byte evidence, digest, read-only health')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
