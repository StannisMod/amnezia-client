#!/usr/bin/python3
"""Discard one successful idempotent issue reply in the disposable daemon only."""
import json
import os
from pathlib import Path
import subprocess
import sys

real = '/usr/local/bin/docker.real'
if not sys.argv[1:] or sys.argv[-1] != 'issue' or not Path('/run/amnezia-issue-loss-fixture').exists():
    os.execv(real, [real, *sys.argv[1:]])
labels = json.loads(subprocess.check_output([real, 'info', '--format', '{{json .Labels}}']))
assert 'amnezia.test-environment=disposable' in labels
raw = sys.stdin.buffer.read((16 << 20) + 1)
assert len(raw) <= 16 << 20
request = json.loads(raw)
result = subprocess.run([real, *sys.argv[1:]], input=raw, capture_output=True, check=False)
sys.stderr.buffer.write(result.stderr)
discard = False
container = request.get('container')
operation = request.get('operation')
if result.returncode == 0 and operation and container in ('amnezia-wireguard', 'amnezia-awg2'):
    reply = json.loads(result.stdout)
    marker = Path('/tmp/issue-reply-loss-' + container)
    if not marker.exists():
        marker.write_text(json.dumps(dict(operation=operation, droppedId=reply['id'], calls=1)))
        discard = True
    else:
        saved = json.loads(marker.read_text())
        if saved['operation'] == operation:
            saved.update(replayedId=reply['id'], replayed=reply.get('replayed', False), calls=saved['calls'] + 1)
            marker.write_text(json.dumps(saved))
if not discard:
    sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
