#!/usr/bin/env python3
"""Local synthetic Docker stack check; no exploit or external target."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


def compose(*args):
    return subprocess.run(['docker','compose',*args],check=True,capture_output=True,text=True).stdout


http_port=int(__import__('os').environ.get('HTTP_PORT','8080'))
ssh_port=int(__import__('os').environ.get('SSH_PORT','2222'))
for attempt in range(60):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{http_port}/smoke-test.php',timeout=2) as r:
            assert r.status==200
        with socket.create_connection(('127.0.0.1',ssh_port),timeout=2) as s:
            assert b'SSH-' in s.recv(1024)
        break
    except (OSError,AssertionError):
        if attempt==59:raise
        time.sleep(2)

with tempfile.TemporaryDirectory() as folder:
    # A dedicated synthetic decoy account, never the operator's real SSH login.
    result=subprocess.run(['sshpass','-p','compose-smoke-password','ssh','-tt','-p',str(ssh_port),
        '-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(Path(folder)/'known_hosts'),
        '-o','PubkeyAuthentication=no','-o','PreferredAuthentications=password',
        '-o','ConnectTimeout=10','root@127.0.0.1'],input='id\npwd\nls /\nexit\n',
        text=True,capture_output=True,timeout=30)
    if result.returncode!=0:
        raise RuntimeError(result.stderr+result.stdout)
    assert 'uid=0' in result.stdout,result.stdout

for attempt in range(20):
    report=json.loads(compose('run','--rm','-T','tools','--indicators'))
    if any(e['event']=='cowrie.command.input' and 'id' in e.get('details',{}).get('input','') for e in report['events']):
        assert any(e['protocol']=='http' for e in report['events'])
        assert any(e['event']=='cowrie.login.success' for e in report['events'])
        break
    if attempt==19:raise AssertionError(report)
    time.sleep(1)

# Test the network boundary by attempting a TCP handshake to a listening
# sibling on a separate Docker network. A successful connect is a failure.
# The endpoint is synthetic/local; no internet host is probed.
probe_id=compose('ps','-q','probe').strip()
assert probe_id,'Start the smoke stack with: docker compose --profile test up -d --build'
probe_ip=subprocess.check_output(['docker','inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',probe_id],text=True).strip()
# The probe must itself be listening before checking denial from the decoys.
compose('exec','-T','probe','python','-c',"import socket; socket.create_connection(('127.0.0.1',9090),2).close()")
compose('exec','-T','sensor','python','-c',
    "import socket; s=socket.socket(); s.settimeout(2); "
    f"code=s.connect_ex(({probe_ip!r},9090)); s.close(); "
    "assert code != 0, 'outbound TCP unexpectedly allowed'")
print('PASS: HTTP, SSH login, simulated commands, persisted combined timeline, outbound connection denied')
