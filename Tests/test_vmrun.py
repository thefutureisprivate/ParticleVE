import os
import signal
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from particleve.common import Error
from particleve.vmrun import supervise

COMMAND = ["/usr/bin/systemd-vmspawn", "--register=yes", "--keep-unit", "--machine=test", "--tpm=no"]


class SupervisorTests(unittest.TestCase):
    def test_inspection_failure_keeps_supervisor_running_after_native_child_exit(self):
        child = Mock()
        child.poll.return_value = 0
        with (
            patch("particleve.vmrun.start_guard"),
            patch(
                "particleve.vmrun.Path.read_text",
                return_value="0::/machine.slice/systemd-vmspawn@test.service",
            ),
            patch("particleve.vmrun.subprocess.Popen", return_value=child),
            patch("particleve.vmrun.cgroup_processes", side_effect=[PermissionError("cannot inspect"), []]),
            patch("particleve.vmrun.time.sleep") as delay,
            patch("builtins.print") as notice,
        ):
            self.assertEqual(supervise("test", COMMAND), 0)
        delay.assert_called_once_with(1)
        self.assertIn("waiting for owner assistance", notice.call_args.args[0])

    def test_interrupted_activation_retries_registration_and_never_signals_the_child(self):
        handlers = {}
        child = Mock()
        child.poll.side_effect = [None, None, None, 0]

        def setup(number, handler):
            previous = handlers.get(number, signal.SIG_DFL)
            handlers[number] = handler
            return previous

        def delay(_seconds):
            handlers[signal.SIGTERM](signal.SIGTERM, None)

        with (
            patch("particleve.vmrun.signal.signal", side_effect=setup),
            patch("particleve.vmrun.start_guard"),
            patch(
                "particleve.vmrun.Path.read_text",
                return_value="0::/machine.slice/systemd-vmspawn@test.service",
            ),
            patch.dict(os.environ, {"WATCHDOG_PID": "123", "NOTIFY_SOCKET": "/run/systemd/notify"}),
            patch("particleve.vmrun.subprocess.Popen", return_value=child) as launch,
            patch("particleve.vmrun.cgroup_processes", return_value=[]),
            patch(
                "particleve.vmrun.run",
                side_effect=[SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)],
            ) as poweroff,
            patch("particleve.vmrun.time.sleep", side_effect=delay),
            patch("builtins.print"),
        ):
            self.assertEqual(supervise("test", COMMAND), 0)
        self.assertEqual(poweroff.call_count, 2)
        self.assertNotIn("WATCHDOG_PID", launch.call_args.kwargs["env"])
        self.assertEqual(launch.call_args.kwargs["env"]["NOTIFY_SOCKET"], "/run/systemd/notify")
        child.terminate.assert_not_called()
        child.kill.assert_not_called()
        child.send_signal.assert_not_called()

    def test_stop_before_native_launch_does_not_create_a_guest(self):
        handlers = {}

        def setup(number, handler):
            handlers[number] = handler
            return signal.SIG_DFL

        with (
            patch("particleve.vmrun.signal.signal", side_effect=setup),
            patch("particleve.vmrun.start_guard", side_effect=lambda _: handlers[signal.SIGTERM](15, None)),
            patch("particleve.vmrun.subprocess.Popen") as launch,
        ):
            self.assertEqual(supervise("test", COMMAND), 0)
        launch.assert_not_called()

    def test_incomplete_native_arguments_fail_before_launch(self):
        for command in (["/bin/true"], COMMAND[:-1], [*COMMAND, "--machine=test"]):
            with (
                self.subTest(command=command),
                patch("particleve.vmrun.subprocess.Popen") as launch,
                self.assertRaises(Error),
            ):
                supervise("test", command)
            launch.assert_not_called()
