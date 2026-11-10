"""Exercise compiled installation radio policy; kernel protocol tests live in Rust."""

from particleve.common import canonical
from Tests.fixtures import host
from Tests.runtime import RustDriverTests

TYPES = ("wlan", "bluetooth", "ultrawideband", "wimax", "wwan", "gps", "fm", "nfc")


class RadioPolicyTests(RustDriverTests):
    def test_explicit_installation_policy_is_validated_and_rendered_without_host_metadata(self):
        candidate = host()
        self.assertEqual(
            self.evaluate("config-validate", config=candidate)["physical"]["radios"], {"allowed_types": []}
        )
        for allowed in (None, True, "wlan", ["wlan", "wlan"], ["all"], ["uwb"], [True], ["wlan\n"]):
            self.assertIn("error", self.request("radio-validate", policy={"allowed_types": allowed}))
        for bad in (None, {}, {"allowed_types": [], "restore": True}):
            self.assertIn("error", self.request("radio-validate", policy=bad))
        policy = {"allowed_types": list(TYPES)}
        candidate["physical"]["radios"] = policy
        self.assertEqual(
            self.evaluate("network-render", config=self.evaluate("config-validate", config=candidate))[
                "etc/particleve/radio-policy.json"
            ],
            canonical(policy).decode(),
        )
        del candidate["physical"]
        self.assertIn("error", self.request("config-validate", config=candidate))
