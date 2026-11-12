#!/usr/bin/python3
"""Discard successful replies only in the disposable protocol fixture."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

assert os.environ.get('AMNEZIA_PROTOCOL_LOSS_FIXTURE') == 'disposable'
raw = sys.stdin.buffer.read((12 << 20) + 1)
assert len(raw) <= 12 << 20
request = json.loads(raw)
result = subprocess.run(['/opt/amnezia/config-helper.real', *sys.argv[1:]], input=raw,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
sys.stderr.buffer.write(result.stderr)
discard = None
if result.returncode == 0 and request.get('action') == 'stage-live':
    original = base64.b64decode(request.get('expected', ''))
    candidate = base64.b64decode(request.get('candidate', ''))
    if candidate.count(b'[Peer]') > original.count(b'[Peer]'):
        discard = Path('/opt/amnezia/protocol-loss-stage')
if result.returncode == 0 and request.get('action') == 'apply-commit':
    discard = Path('/opt/amnezia/protocol-loss-commit')
if result.returncode == 0 and request.get('action') == 'replace-client-table':
    discard = Path('/opt/amnezia/protocol-loss-client-table')
if discard is not None and not discard.exists():
    discard.write_text('1')
else:
    sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
