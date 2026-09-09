"""Local SMTP/TLS lab: isolated sockets, ephemeral certificates, no mail delivery."""
import base64
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

binary = str(Path(sys.argv[1]).resolve())

class Server:
    def __init__(self, context=None, reject=False, stall=False, implicit=False, echo_secret=None):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.context, self.reject, self.stall, self.implicit, self.echo_secret = context, reject, stall, implicit, echo_secret
        self.commands = []
        self.message = []
        self.error = None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
    def serve(self):
        try:
            conn, _ = self.listener.accept()
            conn.settimeout(8)
            if self.stall:
                time.sleep(2)
                conn.close()
                return
            if self.implicit: conn = self.context.wrap_socket(conn, server_side=True)
            stream = conn.makefile('rwb', buffering=0)
            stream.write(b'220 localhost ESMTP\r\n')
            while True:
                line = stream.readline()
                if not line: break
                self.commands.append(line)
                if line.startswith(b'EHLO'):
                    stream.write(b'250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n')
                elif line == b'STARTTLS\r\n':
                    stream.write(b'220 begin TLS\r\n')
                    stream.close()
                    conn = self.context.wrap_socket(conn, server_side=True)
                    stream = conn.makefile('rwb', buffering=0)
                elif line.startswith(b'AUTH'):
                    assert base64.b64decode(line.split()[2]) == b'\0tester\0local-test-secret'
                    stream.write(b'235 authenticated local-test-secret\r\n' if self.echo_secret else b'235 authenticated\r\n')
                elif line.startswith(b'MAIL FROM'):
                    stream.write(b'250 sender OK\r\n')
                elif line.startswith(b'RCPT TO'):
                    stream.write(b'550 recipient rejected\r\n' if self.reject else b'250 recipient OK\r\n')
                elif line == b'DATA\r\n':
                    stream.write(b'354 continue\r\n')
                    while True:
                        item = stream.readline()
                        if item == b'.\r\n': break
                        if not item: raise AssertionError('Unexpected EOF in DATA')
                        self.message.append(item)
                    stream.write(b'250 queued\r\n')
                elif line == b'QUIT\r\n':
                    stream.write(b'221 bye\r\n')
                    break
                else: raise AssertionError(line)
            stream.close()
            conn.close()
        except (ssl.SSLError, ConnectionError):
            pass  # Expected for a client rejecting an untrusted certificate.
        except BaseException as e:
            self.error = e
        finally:
            self.listener.close()
    def done(self):
        self.thread.join(10)
        assert not self.thread.is_alive(), 'Server did not finish'
        assert self.error is None, self.error

def run(server, *args, expected=0, password=None):
    result = subprocess.run([binary, *args, '--json', '--timeout', '5'], capture_output=True, text=True, input=password, timeout=10)
    assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    data = json.loads(result.stdout)
    server.done()
    return data, result.stdout

with tempfile.TemporaryDirectory() as directory:
    key, cert = Path(directory) / 'key.pem', Path(directory) / 'cert.pem'
    ca_key, ca = Path(directory) / 'ca-key.pem', Path(directory) / 'ca.pem'
    csr, extensions = Path(directory) / 'server.csr', Path(directory) / 'server.ext'
    ca_config, server_config = Path(directory) / 'ca.cnf', Path(directory) / 'server.cnf'
    ca_config.write_text('[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=ca\n[dn]\nCN=Mailbench Test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
    server_config.write_text('[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=localhost\n')
    extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(ca_key), '-out', str(ca), '-days', '1', '-config', str(ca_config)], check=True, capture_output=True)
    subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(csr), '-config', str(server_config)], check=True, capture_output=True)
    subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key), '-CAcreateserial', '-out', str(cert), '-days', '1', '-sha256', '-extfile', str(extensions)], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    s = Server(context=ctx, echo_secret=True)
    data, text = run(s, 'send', f'localhost:{s.port}', '--ca-file', str(ca), '--from', 'a@example.com', '--to', 'b@example.net', '--username', 'tester', '--password-stdin', password='local-test-secret\n')
    assert data['findings'][0]['status'] == 'PASS'
    assert 'local-test-secret' not in text
    assert base64.b64encode(b'\0tester\0local-test-secret').decode() not in text
    assert any(line.startswith(b'X-Mailbench-ID:') for line in s.message)
    s = Server(context=ctx)
    run(s, 'tls', f'localhost:{s.port}', expected=1)
    s = Server(context=ctx)
    run(s, 'tls', f'localhost:{s.port}', '--ca-file', str(ca), '--sni', 'wrong.example', expected=1)
    s = Server(context=ctx, implicit=True)
    run(s, 'tls', f'localhost:{s.port}', '--tls-mode', 'implicit', '--ca-file', str(ca))
    s = Server(reject=True)
    data, _ = run(s, 'send', f'localhost:{s.port}', '--tls-mode', 'off', '--from', 'a@example.com', '--to', 'b@example.net', expected=1)
    assert not s.message
    s = Server(stall=True)
    result = subprocess.run([binary, 'smtp', 'test', f'localhost:{s.port}', '--tls-mode', 'off', '--timeout', '1', '--json'], capture_output=True, text=True, timeout=5)
    assert result.returncode == 4, result.stdout
    assert json.loads(result.stdout)['findings'][0]['status'] == 'ERROR'
    s.done()
    print('SMTP acceptance, rejection, TLS trust, implicit TLS, timeout, and credential-redaction checks passed')
