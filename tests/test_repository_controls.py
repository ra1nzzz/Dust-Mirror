from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryControlTests(unittest.TestCase):
    def test_ledger_gate_is_base_only_read_only_and_action_pinned(self) -> None:
        text = (ROOT / ".github" / "workflows" / "ledger-static.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pull_request_target:", text)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", text)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", text)
        self.assertIn("python control/governance/validate_pr.py", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("secrets.", text)
        for reference in re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", text):
            self.assertRegex(reference, r"^[0-9a-f]{40}$")

    def test_rulesets_have_no_bypass_and_require_static_gate(self) -> None:
        main = json.loads(
            (ROOT / ".github" / "rulesets" / "ledger-main.json").read_text(encoding="utf-8")
        )
        tags = json.loads(
            (ROOT / ".github" / "rulesets" / "immutable-tags.json").read_text(encoding="utf-8")
        )
        self.assertEqual(main["bypass_actors"], [])
        self.assertEqual(tags["bypass_actors"], [])
        checks = [
            check["context"]
            for rule in main["rules"]
            if rule["type"] == "required_status_checks"
            for check in rule["parameters"]["required_status_checks"]
        ]
        self.assertEqual(checks, ["ledger-static"])

    def test_checked_in_trust_root_supports_single_maintainer_activation(self) -> None:
        policy = json.loads((ROOT / "governance" / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(policy["activation_status"], "provisioning_required")
        self.assertEqual(policy["trust_root"]["threshold"], 2)
        self.assertEqual(policy["trust_root"]["keys"], [])

        schema = json.loads(
            (ROOT / "governance" / "schemas" / "policy.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            schema["properties"]["trust_root"]["properties"]["threshold"]["minimum"],
            1,
        )

        main = json.loads(
            (ROOT / ".github" / "rulesets" / "ledger-main.json").read_text(
                encoding="utf-8"
            )
        )
        pull_request = next(rule for rule in main["rules"] if rule["type"] == "pull_request")
        self.assertEqual(pull_request["parameters"]["required_approving_review_count"], 0)


if __name__ == "__main__":
    unittest.main()
