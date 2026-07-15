from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance import ledger


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = copy.deepcopy(ledger.load_json(ROOT / "governance" / "policy.json"))
        self.private_keys = {
            "offline-approver-01": Ed25519PrivateKey.from_private_bytes(b"\x01" * 32),
            "offline-approver-02": Ed25519PrivateKey.from_private_bytes(b"\x02" * 32),
            "offline-approver-03": Ed25519PrivateKey.from_private_bytes(b"\x03" * 32),
        }
        self.policy["activation_status"] = "active"
        self.policy["trust_root"]["keys"] = [
            {
                "key_id": key_id,
                "algorithm": "ed25519",
                "public_key_b64": base64.b64encode(
                    private.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ).decode("ascii"),
                "status": "active",
            }
            for key_id, private in self.private_keys.items()
        ]

    def _statement(self, kind: str = "sync", sequence: int = 1, prev: str = ledger.ZERO_DIGEST) -> dict:
        if kind == "sync":
            source = self.policy["repositories"]["dev"]
            target = self.policy["repositories"]["product"]
            check_names = ["governance"]
            stream = "sync:dustmirror"
            tag = None
            target_ref = "refs/heads/master"
            artifact_name = "sync-plan.json"
            sync_digests = ("c" * 64, "d" * 64, "e" * 64)
        elif kind == "release_free":
            source = self.policy["repositories"]["product"]
            target = self.policy["repositories"]["free_artifact"]
            check_names = ["free-boundary", "lint-and-test"]
            stream = "release:free"
            tag = "v1.2.3"
            target_ref = "refs/tags/v1.2.3"
            artifact_name = "DustMirror-v1.2.3-FREE-win64.zip"
            sync_digests = (None, None, None)
        else:
            source = self.policy["repositories"]["product"]
            target = self.policy["repositories"]["pro_artifact"]
            check_names = ["free-boundary", "lint-and-test"]
            stream = "release:pro"
            tag = "pro-v1.2.3"
            target_ref = "refs/tags/pro-v1.2.3"
            artifact_name = "pro-v1.2.3.module.zip"
            sync_digests = (None, None, None)
        artifact_bytes = b"approved artifact bytes"
        return {
            "ledger_repository": "ra1nzzz/Dust-Mirror",
            "stream": stream,
            "approval_id": f"{kind}-20260715-example-{sequence}",
            "kind": kind,
            "sequence": sequence,
            "prev": prev,
            "nonce": base64.urlsafe_b64encode(bytes([sequence]) * 18).decode().rstrip("="),
            "issued_at": "2026-07-15T00:00:00Z",
            "expires_at": "2026-07-16T00:00:00Z",
            "source_repository": source["repository"],
            "source_repository_id": source["repository_id"],
            "source_revision": "a" * 40,
            "source_tree": "b" * 40,
            "workflow_path": ".github/workflows/governance-ci.yml",
            "workflow_blob_sha": "c" * 40,
            "workflow_run_id": 123456789,
            "workflow_run_attempt": 1,
            "checks": [
                {
                    "name": name,
                    "conclusion": "success",
                    "head_sha": "a" * 40,
                    "app_slug": "github-actions",
                }
                for name in check_names
            ],
            "target_repository": target["repository"],
            "target_repository_id": target["repository_id"],
            "target_ref": target_ref,
            "target_base_revision": "d" * 40,
            "target_base_tree": "e" * 40,
            "sync_manifest_sha256": sync_digests[0],
            "ownership_catalog_sha256": sync_digests[1],
            "operations_sha256": sync_digests[2],
            "version": "1.2.3",
            "tag": tag,
            "artifact": {
                "name": artifact_name,
                "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "size_bytes": len(artifact_bytes),
            },
            "policy_epoch": self.policy["policy_epoch"],
            "policy_sha256": ledger.policy_digest(self.policy),
        }

    def _envelope(self, statement: dict, key_ids: tuple[str, ...] = (
        "offline-approver-01", "offline-approver-02"
    )) -> dict:
        payload = ledger.canonical_json(statement)
        return {
            "schema_version": 1,
            "statement": statement,
            "signatures": [
                {
                    "key_id": key_id,
                    "algorithm": "ed25519",
                    "signature_b64": base64.b64encode(
                        self.private_keys[key_id].sign(payload)
                    ).decode("ascii"),
                }
                for key_id in key_ids
            ],
        }

    def test_pending_policy_is_structurally_valid_but_fails_closed(self) -> None:
        pending = ledger.load_json(ROOT / "governance" / "policy.json")
        ledger.validate_policy(pending)
        self.assertEqual(ledger.validate_tree(ROOT), {"approvals": 0, "receipts": 0})
        with self.assertRaisesRegex(ledger.LedgerError, "REMOTE_ACTIVATION_PENDING"):
            ledger.validate_approval(self._envelope(self._statement()), pending, now=NOW)

    def test_threshold_signed_sync_and_release_approvals_validate(self) -> None:
        for kind in ("sync", "release_free", "release_pro"):
            result = ledger.validate_approval(
                self._envelope(self._statement(kind)), self.policy, now=NOW
            )
            self.assertEqual(result["kind"], kind)
            self.assertEqual(len(result["record_sha256"]), 64)

    def test_tamper_wrong_source_and_asset_replacement_fail(self) -> None:
        valid = self._statement("release_free")
        envelope = self._envelope(valid)
        envelope["statement"]["source_revision"] = "f" * 40
        with self.assertRaisesRegex(ledger.LedgerError, "required check"):
            ledger.validate_approval(envelope, self.policy, now=NOW)

        replacement = self._statement("release_free")
        signed = self._envelope(replacement)
        signed["statement"]["artifact"]["sha256"] = hashlib.sha256(b"replacement").hexdigest()
        with self.assertRaisesRegex(ledger.LedgerError, "signature"):
            ledger.validate_approval(signed, self.policy, now=NOW)

    def test_threshold_duplicate_unknown_and_unsorted_signatures_fail(self) -> None:
        statement = self._statement()
        with self.assertRaisesRegex(ledger.LedgerError, "threshold"):
            ledger.validate_approval(
                self._envelope(statement, ("offline-approver-01",)), self.policy, now=NOW
            )
        with self.assertRaisesRegex(ledger.LedgerError, "unique and sorted"):
            ledger.validate_approval(
                self._envelope(statement, ("offline-approver-02", "offline-approver-01")),
                self.policy,
                now=NOW,
            )

    def test_canonical_profile_rejects_float_and_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(ledger.LedgerError, "floating-point"):
            ledger.canonical_json({"unsafe": 1.0})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaisesRegex(ledger.LedgerError, "duplicate JSON key"):
                ledger.load_json(path)

    def test_tree_rejects_broken_chain_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "governance" / "approvals" / "sync").mkdir(parents=True)
            (root / "governance" / "receipts").mkdir(parents=True)
            (root / "governance" / "policies").mkdir(parents=True)
            (root / "governance" / "policy.json").write_text(
                json.dumps(self.policy, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (root / "governance" / "policies" / "epoch-1.json").write_text(
                json.dumps(self.policy, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            first = self._envelope(self._statement(sequence=1))
            first_path = root / "governance" / "approvals" / "sync" / "sync-20260715-example-1.json"
            first_path.write_text(json.dumps(first), encoding="utf-8")
            second_statement = self._statement(
                sequence=2, prev=ledger.digest(first)
            )
            second = self._envelope(second_statement)
            second_path = root / "governance" / "approvals" / "sync" / "sync-20260715-example-2.json"
            second_path.write_text(json.dumps(second), encoding="utf-8")
            self.assertEqual(ledger.validate_tree(root, now=NOW)["approvals"], 2)
            second["statement"]["prev"] = "f" * 64
            second = self._envelope(second["statement"])
            second_path.write_text(json.dumps(second), encoding="utf-8")
            with self.assertRaisesRegex(ledger.LedgerError, "broken approval chain"):
                ledger.validate_tree(root, now=NOW)


if __name__ == "__main__":
    unittest.main()
