import os
import subprocess
import sys
import tempfile
import time
import json
import signal
import platform
import shutil
import pytest

pytestmark = pytest.mark.skipif(platform.system().lower() == 'windows', reason='requires linux for eBPF loader build')


def test_loader_blocks_non_allowlisted_api(monkeypatch):
    # Prepare a temporary allowlist that only allows localhost:8000 and pins file empty
    tmpdir = tempfile.mkdtemp()
    try:
        allow = os.path.join(tmpdir, 'allow.txt')
        with open(allow, 'w') as f:
            f.write('# allow only localhost\nhttps://localhost:8000\n')
        pins = os.path.join(tmpdir, 'pins.txt')
        open(pins, 'w').close()

        # Build loader binary
        subprocess.check_call(['go', 'build', '-o', 'introspection-engine/ebpf-core/go-loader/bin/carnot-ebpf-loader', './introspection-engine/ebpf-core/go-loader'])

        # Start loader targeting disallowed host (example.org)
        env = os.environ.copy()
        p = subprocess.Popen([
            'sudo', './introspection-engine/ebpf-core/go-loader/bin/carnot-ebpf-loader',
            '-obj', 'introspection-engine/ebpf-core/openssl_handshake.bpf.o',
            '-out', os.path.join(tmpdir, 'runtime.jsonl'),
            '-api-url', 'https://example.org/ingest',
            '-hel-allowlist', allow,
            '-spki-pins', pins,
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Let it run briefly to print HEL message
        time.sleep(2)
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()

        out = p.stdout.read()
        assert 'blocked egress' in out
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
