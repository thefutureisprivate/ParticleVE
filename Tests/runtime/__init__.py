"""Test-only access to the compiled runtime; no Python runtime implementation."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


def native_environment(directory, responses):
    """Provide inert commands to one driver subprocess, without host PATH fallback."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    commands = directory / "native-commands"
    commands.mkdir(mode=0o700)
    records = [
        {"arguments": list(key) if isinstance(key, tuple) else [key], "response": value}
        for key, value in responses.items()
    ]
    payload = commands / "responses.json"
    payload.write_text(json.dumps(records))
    for name in {record["arguments"][0] for record in records}:
        if not name or Path(name).name != name:
            raise ValueError("fixture command must use a plain basename")
        script = commands / name
        script.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "arguments = [Path(sys.argv[0]).name, *sys.argv[1:]]\n"
            "log = os.environ.get('PVE_NATIVE_COMMAND_LOG')\n"
            "if log:\n"
            "    with open(log, 'a') as stream:\n"
            "        stream.write(json.dumps(arguments) + '\\n')\n"
            "records = json.loads(Path(__file__).with_name('responses.json').read_text())\n"
            "matches = [r for r in records if r['arguments'] == arguments]\n"
            "if not matches:\n"
            "    matches = [r for r in records if r['arguments'] == arguments[:1]]\n"
            "if len(matches) != 1:\n"
            "    sys.stderr.write('unexpected fixture command: ' + repr(arguments))\n"
            "    sys.exit(125)\n"
            "response = matches[0]['response']\n"
            "sys.stdout.write(response.get('stdout', ''))\n"
            "sys.stderr.write(response.get('stderr', ''))\n"
            "sys.exit(response.get('code', 0))\n"
        )
        script.chmod(0o700)
    return os.environ | {"PATH": str(commands)}


class RustDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = Path(
            os.environ.get("PVE_RUNTIME_DRIVER", "target/debug/examples/runtime-contract-driver")
        ).resolve()
        if not cls.driver.is_file():
            raise RuntimeError("compile the Rust contract driver before running source checks")

    def request(self, operation, *, environment=None, **fields):
        result = subprocess.run(
            [str(self.driver)],
            input=json.dumps({"operation": operation, **fields}, allow_nan=False) + "\n",
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
            env=environment,
        )
        self.assertEqual(result.stderr, "")
        response = json.loads(result.stdout)
        self.assertIsInstance(response, dict)
        self.assertEqual(len(response), 1)
        self.assertIn(next(iter(response)), ("ok", "error"))
        return response

    def evaluate(self, operation, *, environment=None, **fields):
        result = self.request(operation, environment=environment, **fields)
        self.assertIn("ok", result, result.get("error"))
        return result["ok"]
