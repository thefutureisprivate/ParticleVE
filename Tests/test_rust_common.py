"""Exercise compiled Rust boundaries against the persisted Python JSON contract."""

import hashlib
import json
import math
import os
import random
import struct
import subprocess
import unittest
from pathlib import Path


class RustCommonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = Path(
            os.environ.get("PVE_RUNTIME_DRIVER", "target/debug/examples/runtime-contract-driver")
        )
        if not cls.driver.is_file():
            raise RuntimeError("compile the Rust contract driver before running source checks")

    def requests(self, values):
        data = "".join(json.dumps(value, allow_nan=False) + "\n" for value in values)
        result = subprocess.run(
            [str(self.driver.resolve())], input=data, text=True, capture_output=True, timeout=30, check=True
        )
        self.assertEqual(result.stderr, "")
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_canonical_persistent_bytes_and_hashes(self):
        generator = random.Random(0x505645)
        numbers = [-0.0, 0.0, 1.0, 1e-5, 1e-4, 1e15, 1e16, 1e20, 1e-308, 5e-324]
        for _ in range(10000):
            number = struct.unpack("!d", generator.randbytes(8))[0]
            if math.isfinite(number):
                numbers.append(number)
        values = [
            {},
            [],
            [None, True, False, 0, -1, 2**64 - 1, -(2**63), 2**128, -(2**128)],
            {"$serde_json::private::Number": "123456789012345678901234567890"},
            {"\U0001f510": '\x00\b\f\t\r\n\\"\u007f\u00e4', "a": {"z": [1, {}]}},
            *numbers,
        ]
        observed = self.requests([{"operation": "canonical", "value": value} for value in values])
        self.assertEqual(len(observed), len(values))
        for value, response in zip(values, observed, strict=True):
            expected = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
            with self.subTest(value=value):
                self.assertEqual(response["ok"]["canonical"], expected)
                self.assertEqual(response["ok"]["digest"], hashlib.sha256(expected.encode()).hexdigest())

    def test_json_rejects_duplicates_and_nonfinite_values(self):
        invalid = [
            '{"x":1,"x":2}',
            '{"nested":{"x":1,"x":2}}',
            '[{"x":1,"x":2}]',
            "NaN",
            "Infinity",
            "-Infinity",
            "1e9999",
            "{}{}",
            '"\\ud800"',
        ]
        for source, response in zip(
            invalid, self.requests([{"operation": "parse", "data": value} for value in invalid]), strict=True
        ):
            with self.subTest(source=source):
                self.assertIn("error", response)


if __name__ == "__main__":
    unittest.main()
