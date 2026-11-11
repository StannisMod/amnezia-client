import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mtu_controller', Path(__file__).with_name('controller.py'))
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class RouteOwnershipTest(unittest.TestCase):
    def exercise(self, result, external_change=False):
        original = '10.77.0.1 dev awg0 scope link'
        state = [original]
        commands = []

        def execute(command, **kwargs):
            commands.append(command)
            state[0] = ' '.join(command[4:])

        def discover(*args):
            if external_change:
                state[0] = '10.77.0.1 dev another0 scope link'
            return result

        argv = ['controller.py', '--interface', 'awg0', '--source', '10.77.0.254',
                '--peer', '10.77.0.1', '--once']
        with tempfile.TemporaryFile(mode='w+') as lock:
            with patch.object(sys, 'argv', argv), patch.object(controller, 'open', return_value=lock, create=True), \
                 patch.object(controller.socket, 'if_nametoindex', return_value=1), \
                 patch.object(controller, 'route', side_effect=lambda _: state[0]), \
                 patch.object(controller, 'discover', side_effect=discover), \
                 patch.object(controller.subprocess, 'run', side_effect=execute):
                if external_change:
                    with self.assertRaisesRegex(RuntimeError, "route changed during probing"):
                        controller.main()
                else:
                    controller.main()
        return original, state[0], commands

    def test_reduction_restored_on_exit(self):
        original, final, commands = self.exercise({'state': 'reduced', 'mtu': 1104})
        self.assertEqual(final, original)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][-2:], ['mtu', '1104'])

    def test_outage_does_not_change_route(self):
        original, final, commands = self.exercise({'state': 'inconclusive'})
        self.assertEqual(final, original)
        self.assertEqual(commands, [])

    def test_external_change_is_not_overwritten(self):
        _, final, commands = self.exercise({'state': 'reduced', 'mtu': 1104}, external_change=True)
        self.assertIn('another0', final)
        self.assertEqual(commands, [])


if __name__ == '__main__':
    unittest.main()
