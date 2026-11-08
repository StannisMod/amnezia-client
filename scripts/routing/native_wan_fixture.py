#!/usr/bin/env python3
"""A controlled native-route TCP witness inside a disposable service container."""
import select
import subprocess
import uuid


def start():
    namespace = 'amn-witness-' + uuid.uuid4().hex[:8]
    interface = 'awn' + uuid.uuid4().hex[:8]
    child = None

    def command(*args):
        subprocess.run(list(args), check=True, timeout=15, stdout=subprocess.DEVNULL)

    def close():
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        for args in (('ip', 'link', 'del', interface), ('ip', 'netns', 'del', namespace)):
            subprocess.run(args, check=False, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        command('ip', 'netns', 'add', namespace)
        command('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', namespace)
        command('ip', 'addr', 'add', '10.205.0.1/30', 'dev', interface)
        command('ip', 'link', 'set', interface, 'up')
        prefix = ('ip', 'netns', 'exec', namespace)
        command(*prefix, 'ip', 'link', 'set', 'lo', 'up')
        command(*prefix, 'ip', 'addr', 'add', '10.205.0.2/30', 'dev', 'eth0')
        command(*prefix, 'ip', 'addr', 'add', '198.51.100.254/32', 'dev', 'eth0')
        command(*prefix, 'ip', 'link', 'set', 'eth0', 'up')
        command('ip', 'route', 'add', '198.51.100.254/32', 'via', '10.205.0.2', 'dev', interface)
        program = ('import socket\n'
                   's=socket.socket();s.bind(("198.51.100.254",443));s.listen(16)\n'
                   'print("READY",flush=True)\n'
                   'while True:\n c,_=s.accept();c.close()\n')
        child = subprocess.Popen([*prefix, 'python3', '-u', '-c', program], stdout=subprocess.PIPE, text=True)
        if not select.select([child.stdout], [], [], 5)[0] or child.stdout.readline().strip() != 'READY':
            raise RuntimeError('controlled native-route witness did not start')
        return '198.51.100.254', close
    except BaseException:
        close()
        raise
