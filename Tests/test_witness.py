"""Compiled witness launch authority; sandbox inventory cases live in Rust tests."""

from Tests.runtime import RustDriverTests

VARIABLE = "/sys/firmware/efi/efivars/ParticleVEStorage-59a481c6-fbbc-4d82-8617-37eae6ebdf21"


class WitnessIsolationTests(RustDriverTests):
    def test_launcher_exposes_one_existing_writable_file_and_restricts_capabilities(self):
        arguments = self.evaluate("witness-command", variable=VARIABLE)
        self.assertEqual(arguments.count("--bind"), 1)
        index = arguments.index("--bind")
        self.assertEqual(arguments[index + 1 : index + 3], [VARIABLE, VARIABLE])
        self.assertEqual(arguments[arguments.index("--cap-drop") + 1], "ALL")
        self.assertEqual(arguments[arguments.index("--cap-add") + 1], "CAP_LINUX_IMMUTABLE")
        for flag in (
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--clearenv",
        ):
            self.assertIn(flag, arguments)
        self.assertEqual(arguments[-1], "/usr/libexec/particleve-witness-write")

    def test_writer_rejects_execution_outside_its_isolated_launcher(self):
        self.assertIn("error", self.request("witness-check-sandbox", variable=VARIABLE))
