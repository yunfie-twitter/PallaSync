"""Exercise the real policy signer with generated defaults, without generating production keys."""
import base64
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("docker_config", ROOT / "scripts/docker_config.py")
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
SUFFIX = ".exe" if os.name == "nt" else ""
SIGNER = Path(os.environ.get("PALLASYNC_OPERATOR_BIN", ROOT / f"target/debug/pallasync-operator{SUFFIX}"))
TEST_SEED = base64.urlsafe_b64encode(bytes([37]) * 32).rstrip(b"=")


def profile(quota=None):
    return dict(origin="https://relay.example.com", operator='Test "operator" $name',
                contact="https://relay.example.com/contact", location="Test region/provider role",
                recipients="Test operator and hosting administrator", storage_protection="Test volume encryption and operator-only login",
                delete_ms=60000, quota=quota,
                notice="https://relay.example.com/notice", archive="https://relay.example.com/archive",
                notice_ms=0, proxy=True, host_port=3000, host_bind="127.0.0.1", project="pallasync")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "operator"
        config.prepare(profile(), self.state)

    def invoke(self, *args, seed=TEST_SEED):
        result = subprocess.run([str(SIGNER), *map(str, args)], input=seed, capture_output=True)
        self.assertNotIn(seed, result.stdout + result.stderr)
        return result

    def sign(self, quota="none"):
        return self.invoke("sign", self.state / "draft", self.state / "policy", quota)

    def test_generated_default_is_signed_and_accepted_by_server_validator(self):
        result = self.sign()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        policy = self.state / "policy"
        p = json.loads((policy / "privacy.json").read_bytes())
        self.assertEqual(p["revision"], 1)
        self.assertEqual(p["operator"]["name"], profile()["operator"])
        self.assertEqual(p["copies"]["wal"]["content"], "ciphertext")
        self.assertEqual(p["metadata"]["retention"]["mode"], "indefinite")
        self.assertEqual(self.invoke("verify", policy, "none").returncode, 0)
        self.assertIn(b"Revision: 1", (policy / "privacy.md").read_bytes())

    def test_fixed_and_zero_quota_agree_with_the_runtime(self):
        for quota in [0, 1000000]:
            with self.subTest(quota=quota):
                state = Path(self.temp.name) / str(quota)
                config.prepare(profile(quota), state)
                self.assertEqual(self.invoke("sign", state / "draft", state / "policy", quota).returncode, 0)
                self.assertEqual(self.invoke("verify", state / "policy", quota).returncode, 0)
                self.assertNotEqual(self.invoke("verify", state / "policy", "none").returncode, 0)

    def test_modified_markdown_wrong_key_and_quota_are_rejected(self):
        self.assertEqual(self.sign().returncode, 0)
        policy = self.state / "policy"
        wrong = base64.urlsafe_b64encode(bytes([38]) * 32).rstrip(b"=")
        self.assertNotEqual(self.invoke("verify", policy, "none", seed=wrong).returncode, 0)
        with (policy / "privacy.md").open("ab") as f:
            f.write(b"changed")
        self.assertNotEqual(self.invoke("verify", policy, "none").returncode, 0)

    def test_repeated_sign_does_not_replace_a_published_revision(self):
        self.assertEqual(self.sign().returncode, 0)
        p = self.state / "policy/privacy.json"
        original = p.read_bytes()
        self.assertNotEqual(self.sign().returncode, 0)
        self.assertEqual(p.read_bytes(), original)

    def test_draft_cannot_supply_unknown_or_derived_fields(self):
        for field in ["relay_signature", "revision", "custom_api"]:
            with self.subTest(field=field):
                config.prepare(profile(), self.state)
                p = self.state / "draft/privacy.json"
                draft = json.loads(p.read_bytes())
                draft[field] = "untrusted"
                p.write_text(json.dumps(draft), encoding="utf-8")
                self.assertNotEqual(self.sign().returncode, 0)
                self.assertFalse((self.state / "policy").exists())

    def test_schema_invalid_operator_values_and_noncanonical_seeds_fail_closed(self):
        p = self.state / "draft/privacy.json"
        draft = json.loads(p.read_bytes())
        draft["operator"]["name"] = ""
        p.write_text(json.dumps(draft), encoding="utf-8")
        self.assertNotEqual(self.sign().returncode, 0)
        for seed in [TEST_SEED + b"=", b" " + TEST_SEED, b"x" * 100]:
            self.assertNotEqual(self.invoke("sign", self.state / "draft", self.state / "policy", "none", seed=seed).returncode, 0)
        self.assertFalse((self.state / "policy").exists())

    def test_compose_contains_no_plaintext_key_and_preserves_data(self):
        generated = json.loads((self.state / "compose.generated.json").read_bytes())
        server = generated["services"]["pallasync"]
        self.assertNotIn("PALLASYNC_RELAY_SIGNING_SEED", server["environment"])
        self.assertIn("/run/pallasync:size=1m,mode=0700,uid=10001,gid=10001", server["tmpfs"])
        self.assertIn("pallasync-data:/data", server["volumes"])
        self.assertEqual(server["logging"]["driver"], "none")
        p = profile(123)
        p["proxy"] = False
        generated = config.compose(p, self.state)
        self.assertNotIn("caddy", generated["services"])
        self.assertEqual(generated["services"]["pallasync"]["environment"]["PALLASYNC_QUOTA_BYTES"], "123")

    def test_operator_text_is_not_interpreted_as_template_or_json_code(self):
        p = profile()
        p["location"] = '<provider> | "line" $origin'
        md, disclosure = config.render(p)
        self.assertEqual(disclosure["copies"]["active_store"]["locations"], [p["location"]])
        self.assertIn("&lt;provider&gt; \\| &quot;line&quot; $origin", md)
        self.assertIn('Test &quot;operator&quot; $name', md)

    def test_prompts_collect_real_values_and_require_an_explicit_answer(self):
        answers = ["Test operator", "https://relay.example.com/contact", "Test region/provider",
                   "Test operator role", "Test encrypted disk", "60000", "none",
                   "https://relay.example.com/notice", "https://relay.example.com/archive", "0", "yes"]
        with patch("builtins.input", side_effect=answers):
            p = config.collect("https://relay.example.com", False, 3000)
        self.assertEqual(p["storage_protection"], "Test encrypted disk")
        self.assertIsNone(p["quota"])
        with patch("builtins.input", side_effect=answers[:-1] + [""]):
            with self.assertRaises(ValueError):
                config.collect("https://relay.example.com", False, 3000)

    def test_url_input_rejects_credentials_fragments_and_invalid_ports(self):
        for value in ["http://relay.example.com", "https://user@relay.example.com",
                      "https://relay.example.com/#x", "https://relay.example.com:bad"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                config.url(value)

    def test_cloudflare_processor_is_disclosed_without_creating_a_proxy(self):
        p = config.cloudflare_defaults(profile())
        p["proxy"] = False
        state = Path(self.temp.name) / "cloudflare"
        config.prepare(p, state)
        result = self.invoke("sign", state / "draft", state / "policy", "none")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        disclosure = json.loads((state / "policy/privacy.json").read_bytes())
        self.assertEqual(disclosure["copies"]["operational_log"]["content"], "metadata")
        self.assertIn("Cloudflare, Inc. and its service providers", disclosure["metadata"]["recipients"])
        self.assertNotIn("caddy", config.compose(p, state)["services"])


if __name__ == "__main__":
    if not SIGNER.is_file():
        raise SystemExit("Run cargo build --locked --bin pallasync-operator first")
    unittest.main()
