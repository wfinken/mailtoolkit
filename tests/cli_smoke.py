"""Offline subprocess tests for the public CLI contract; no external DNS or SMTP."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())

def run(*args, expected=0, stdin=None):
    result = subprocess.run([binary, *args, '--json'], input=stdin, text=True, capture_output=True, timeout=15)
    assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    data = json.loads(result.stdout)
    assert data['schema_version'] == 1
    return data

with tempfile.TemporaryDirectory() as directory:
    os.environ['MAILBENCH_CONFIG_DIR'] = directory
    message = str(Path(directory) / 'test.eml')
    run('message', 'build', '--from', 'a@example.com', '--to', 'b@example.net', '--body', 'Hello 🌍', '--output', message)
    data = run('message', 'inspect', message, '--save')
    assert data['findings'][0]['evidence']['from'] == 'a@example.com'
    session_id = data['id']
    assert len(run('history', 'list')['findings'][0]['evidence']['sessions']) == 1
    report = str(Path(directory) / 'report.html')
    run('report', session_id, '--format', 'html', '--output', report)
    assert Path(report).read_text().startswith('<!doctype html>')
    run('history', 'delete', session_id)
    assert run('history', 'list')['findings'][0]['evidence']['sessions'] == []
    run('profile', 'show', '../escape', expected=3)
    run('send', 'localhost:2525', '--from', 'a@example.com', '--to', 'b@example.net', '--subject', 'bad\r\nBcc: injected', '--dry-run', expected=3)
    dry = run('send', 'localhost:2525', '--from', 'a@example.com', '--to', 'b@example.net', '--dry-run')
    assert 'X-Mailbench-ID:' in dry['findings'][0]['evidence']['message']
    print('CLI contract checks passed')
