#!/usr/bin/env python3
"""Local synthetic Docker stack check; no exploit or external target."""
import json
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time
import urllib.request


def compose(*args):
    return subprocess.run(['docker','compose',*args],check=True,capture_output=True,text=True).stdout


http_port=int(__import__('os').environ.get('HTTP_PORT','8080'))
ssh_port=int(__import__('os').environ.get('SSH_PORT','2222'))
telnet_port=int(__import__('os').environ.get('TELNET_PORT','2323'))
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
    if shutil.which('sshpass'):
        command=['sshpass','-p','compose-smoke-password','ssh','-tt','-p',str(ssh_port),
            '-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(Path(folder)/'known_hosts'),
            '-o','PubkeyAuthentication=no','-o','PreferredAuthentications=password',
            '-o','ConnectTimeout=10','root@127.0.0.1']
    else:
        # Container-only SSH client reaches the synthetic decoy over Compose's
        # private bridge. No host sshpass installation or Docker socket mount.
        command=['docker','compose','run','--rm','-T','--no-deps','ssh-client',
            '-p','compose-smoke-password','ssh','-tt','-p','2222',
            '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null',
            '-o','PubkeyAuthentication=no','-o','PreferredAuthentications=password',
            '-o','ConnectTimeout=10','root@guard']
    result=subprocess.run(command,input='id\npwd\nls /\nexit\n',
        text=True,capture_output=True,timeout=60)
    if result.returncode!=0:
        raise RuntimeError(result.stderr+result.stdout)
    assert 'uid=0' in result.stdout,result.stdout

# Exercise the Telnet login and shell using a bounded byte-level client. No
# telnetlib dependency (removed from newer Python versions).
with socket.create_connection(('127.0.0.1',telnet_port),timeout=10) as session:
    session.settimeout(10)
    def until(marker):
        output=bytearray()
        pending=bytearray()
        deadline=time.monotonic()+15
        while marker not in output:
            if time.monotonic()>deadline or len(output)>131072:
                raise AssertionError('Telnet response deadline/size limit')
            pending.extend(session.recv(4096))
            if not pending:
                raise AssertionError('Telnet disconnected before expected prompt')
            while pending:
                if pending[0]!=255:
                    output.append(pending.pop(0));continue
                if len(pending)<2:break
                verb=pending[1]
                if verb in (251,252,253,254):
                    if len(pending)<3:break
                    option=pending[2]
                    if verb==251:session.sendall(bytes([255,254,option]))
                    elif verb==253:session.sendall(bytes([255,252,option]))
                    del pending[:3]
                elif verb==250:
                    end=pending.find(bytes([255,240]),2)
                    if end<0:break
                    del pending[:end+2]
                else:del pending[:2]
        return bytes(output)
    until(b'login:')
    session.sendall(b'root\r\n')
    until(b'Password:')
    session.sendall(b'compose-telnet-password\r\n')
    until(b'#')
    session.sendall(b'id\r\n')
    until(b'uid=0')
    session.sendall(b'exit\r\n')

for attempt in range(20):
    report=json.loads(compose('run','--rm','-T','tools','--indicators'))
    if all(any(e['event']=='cowrie.command.input' and e['protocol']==protocol and 'id' in e.get('details',{}).get('input','') for e in report['events']) for protocol in ('ssh','telnet')):
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
compose('exec','-T','ssh','/cowrie/cowrie-env/bin/python3','-c',
    "import socket; s=socket.socket(); s.settimeout(2); "
    f"code=s.connect_ex(({probe_ip!r},9090)); s.close(); "
    "assert code != 0, 'outbound TCP unexpectedly allowed'")
print('PASS: Rust HTTP, SSH + Telnet login/commands, persisted combined timeline, outbound connection denied')
