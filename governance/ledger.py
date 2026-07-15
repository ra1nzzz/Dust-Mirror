#!/usr/bin/env python3
"""Validate DustMirror's public GitHub-Free governance ledger.

Only JSON data under ``governance/`` is consumed.  Private repository branches,
tags, releases, and checks are candidate evidence; a valid threshold-signed
approval is the authorization boundary.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata
from typing import Any, Iterable


ZERO_DIGEST = "0" * 64
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
WORKFLOW_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9._/-]+\.ya?ml$")

POLICY_FIELDS = {
    "schema_version", "kind", "canonicalization", "policy_epoch",
    "activation_status", "ledger", "trust_root", "repositories",
    "approval_kinds", "limits", "paths",
}
APPROVAL_FIELDS = {
    "ledger_repository", "stream", "approval_id", "kind", "sequence",
    "prev", "nonce", "issued_at", "expires_at", "source_repository",
    "source_repository_id", "source_revision", "source_tree",
    "workflow_path", "workflow_blob_sha", "workflow_run_id",
    "workflow_run_attempt", "checks", "target_repository",
    "target_repository_id", "target_ref", "target_base_revision",
    "target_base_tree", "sync_manifest_sha256",
    "ownership_catalog_sha256", "operations_sha256", "version", "tag",
    "artifact", "policy_epoch", "policy_sha256",
}
SIGNATURE_FIELDS = {"key_id", "algorithm", "signature_b64"}
CHECK_FIELDS = {"name", "conclusion", "head_sha", "app_slug"}
ARTIFACT_FIELDS = {"name", "sha256", "size_bytes"}
RECEIPT_FIELDS = {
    "ledger_repository", "stream", "receipt_id", "kind", "approval_id",
    "approval_record_sha256", "nonce", "issued_at", "approval_expires_at",
    "action", "status", "source_repository", "source_repository_id",
    "source_revision", "source_tree", "workflow_path", "workflow_blob_sha",
    "workflow_run_id", "workflow_run_attempt", "target_repository",
    "target_repository_id", "target_ref", "target_commit", "target_tree",
    "target_pull_request_number", "target_release_id", "version", "tag",
    "artifact", "policy_epoch", "policy_sha256",
}
POLICY_TRANSITION_FIELDS = {
    "kind", "ledger_repository", "from_epoch", "from_policy_sha256",
    "to_epoch", "to_policy_sha256", "nonce", "issued_at", "reason",
}


class LedgerError(RuntimeError):
    """A governance record is not safe to consume."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LedgerError(f"cannot read {path}: {exc}") from exc
    if raw.startswith(b"\xef\xbb\xbf"):
        raise LedgerError(f"JSON must not contain a BOM: {path}")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                LedgerError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerError(f"invalid JSON in {path}: {exc}") from exc


def _validate_canonical_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise LedgerError(f"floating-point values are forbidden at {path}")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise LedgerError(f"string must be NFC-normalized at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or unicodedata.normalize("NFC", key) != key:
                raise LedgerError(f"object key must be an NFC string at {path}")
            _validate_canonical_value(item, f"{path}.{key}")
        return
    raise LedgerError(f"unsupported JSON value at {path}: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """DustMirror CJSON v1: UTF-8, NFC, sorted keys, integers only."""
    _validate_canonical_value(value)
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _expect_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LedgerError(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        raise LedgerError(
            f"{label} fields differ (missing={sorted(fields - actual)}, "
            f"unexpected={sorted(actual - fields)})"
        )
    return value


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise LedgerError(f"{label} must be a positive integer")
    return value


def _exact_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise LedgerError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _exact_git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA_RE.fullmatch(value) is None:
        raise LedgerError(f"{label} must be a lowercase full Git SHA")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LedgerError(f"{label} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LedgerError(f"{label} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise LedgerError(f"{label} must use UTC")
    return parsed


def _safe_name(value: Any, label: str) -> str:
    if (
        not isinstance(value, str) or not value or len(value) > 255
        or Path(value).name != value or value in {".", ".."}
        or any(ord(char) < 32 for char in value)
    ):
        raise LedgerError(f"{label} is not a safe filename")
    return value


def _validate_artifact(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    artifact = _expect_object(value, ARTIFACT_FIELDS, "artifact")
    _safe_name(artifact["name"], "artifact.name")
    _exact_digest(artifact["sha256"], "artifact.sha256")
    size = _positive_int(artifact["size_bytes"], "artifact.size_bytes")
    if size > policy["limits"]["max_artifact_size_bytes"]:
        raise LedgerError("artifact exceeds policy size limit")
    return artifact


def validate_policy(policy: Any, *, require_active: bool = False) -> dict[str, Any]:
    policy = _expect_object(policy, POLICY_FIELDS, "policy")
    if (
        policy["schema_version"] != 1
        or policy["kind"] != "dustmirror.governance-policy"
        or policy["canonicalization"] != "dustmirror-cjson-v1"
    ):
        raise LedgerError("unsupported governance policy")
    _positive_int(policy["policy_epoch"], "policy_epoch")
    if policy["activation_status"] not in {"provisioning_required", "active"}:
        raise LedgerError("invalid policy activation_status")

    ledger = _expect_object(
        policy["ledger"],
        {"repository", "repository_id", "default_branch", "visibility"},
        "policy.ledger",
    )
    if ledger != {
        "repository": "ra1nzzz/Dust-Mirror",
        "repository_id": 1267655184,
        "default_branch": "main",
        "visibility": "public",
    }:
        raise LedgerError("policy ledger identity is not the public Dust-Mirror repository")

    trust = _expect_object(
        policy["trust_root"], {"algorithm", "threshold", "keys"}, "policy.trust_root"
    )
    if trust["algorithm"] != "ed25519":
        raise LedgerError("only Ed25519 governance keys are supported")
    threshold = _positive_int(trust["threshold"], "policy trust threshold")
    if not isinstance(trust["keys"], list):
        raise LedgerError("policy trust keys must be an array")
    key_ids: set[str] = set()
    active = 0
    for index, key in enumerate(trust["keys"]):
        key = _expect_object(
            key, {"key_id", "algorithm", "public_key_b64", "status"},
            f"policy.trust_root.keys[{index}]",
        )
        key_id = key["key_id"]
        if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
            raise LedgerError("invalid governance key_id")
        if key_id in key_ids:
            raise LedgerError(f"duplicate governance key_id: {key_id}")
        key_ids.add(key_id)
        if key["algorithm"] != "ed25519" or key["status"] not in {"active", "revoked"}:
            raise LedgerError(f"invalid governance key metadata: {key_id}")
        try:
            raw = base64.b64decode(key["public_key_b64"], validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise LedgerError(f"invalid public key encoding: {key_id}") from exc
        if len(raw) != 32:
            raise LedgerError(f"Ed25519 public key must be 32 bytes: {key_id}")
        if key["status"] == "active":
            active += 1
    if policy["activation_status"] == "active" and active < threshold:
        raise LedgerError("active governance policy has fewer active keys than its threshold")
    if policy["activation_status"] == "provisioning_required" and trust["keys"]:
        raise LedgerError("provisioning policy must not contain partially activated keys")
    if require_active and policy["activation_status"] != "active":
        raise LedgerError("REMOTE_ACTIVATION_PENDING: governance trust root is not active")

    if not isinstance(policy["repositories"], dict) or not policy["repositories"]:
        raise LedgerError("policy repositories must be a non-empty object")
    for role, repository in policy["repositories"].items():
        _expect_object(
            repository,
            {"repository", "repository_id", "default_branch", "trust_role"},
            f"policy.repositories.{role}",
        )
        _positive_int(repository["repository_id"], f"repository id for {role}")

    if set(policy["approval_kinds"]) != {"sync", "release_free", "release_pro"}:
        raise LedgerError("policy approval kinds are not exact")
    for kind, rule in policy["approval_kinds"].items():
        _expect_object(
            rule, {"stream", "subject_role", "target_role", "required_checks"},
            f"policy.approval_kinds.{kind}",
        )
        if rule["subject_role"] not in policy["repositories"] or rule["target_role"] not in policy["repositories"]:
            raise LedgerError(f"approval kind {kind} references an unknown repository role")
        if not isinstance(rule["required_checks"], list) or not rule["required_checks"]:
            raise LedgerError(f"approval kind {kind} must require checks")
        if len(rule["required_checks"]) != len(set(rule["required_checks"])):
            raise LedgerError(f"approval kind {kind} repeats a required check")

    limits = _expect_object(
        policy["limits"],
        {"max_approval_ttl_seconds", "max_artifact_size_bytes", "minimum_nonce_bytes"},
        "policy.limits",
    )
    for name, value in limits.items():
        _positive_int(value, f"policy.limits.{name}")
    paths = _expect_object(policy["paths"], {"approvals", "receipts"}, "policy.paths")
    if paths != {"approvals": "governance/approvals", "receipts": "governance/receipts"}:
        raise LedgerError("policy ledger paths are not canonical")
    canonical_json(policy)
    return policy


def policy_digest(policy: dict[str, Any]) -> str:
    validate_policy(policy)
    return digest(policy)


def _validate_nonce(value: Any, policy: dict[str, Any]) -> str:
    if not isinstance(value, str) or NONCE_RE.fullmatch(value) is None:
        raise LedgerError("nonce must be unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise LedgerError("nonce is not valid base64url") from exc
    if len(raw) < policy["limits"]["minimum_nonce_bytes"]:
        raise LedgerError("nonce is shorter than the policy minimum")
    return value


def _verify_signatures(
    envelope: dict[str, Any], policy: dict[str, Any], statement_bytes: bytes
) -> None:
    validate_policy(policy, require_active=True)
    signatures = envelope["signatures"]
    if not isinstance(signatures, list):
        raise LedgerError("signatures must be an array")
    key_map = {
        item["key_id"]: item
        for item in policy["trust_root"]["keys"]
        if item["status"] == "active"
    }
    ids: list[str] = []
    valid = 0
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise LedgerError("cryptography is required for Ed25519 verification") from exc
    for index, signature in enumerate(signatures):
        signature = _expect_object(signature, SIGNATURE_FIELDS, f"signatures[{index}]")
        key_id = signature["key_id"]
        if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
            raise LedgerError("signature key_id is invalid")
        if signature["algorithm"] != "ed25519":
            raise LedgerError("signature algorithm must be ed25519")
        ids.append(key_id)
        key = key_map.get(key_id)
        if key is None:
            raise LedgerError(f"signature uses an unknown or inactive key: {key_id}")
        try:
            raw_signature = base64.b64decode(signature["signature_b64"], validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise LedgerError(f"signature is not canonical base64: {key_id}") from exc
        if len(raw_signature) != 64:
            raise LedgerError(f"Ed25519 signature must be 64 bytes: {key_id}")
        public_raw = base64.b64decode(key["public_key_b64"], validate=True)
        try:
            Ed25519PublicKey.from_public_bytes(public_raw).verify(raw_signature, statement_bytes)
        except InvalidSignature as exc:
            raise LedgerError(f"invalid governance signature: {key_id}") from exc
        valid += 1
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise LedgerError("signatures must be unique and sorted by key_id")
    if valid < policy["trust_root"]["threshold"]:
        raise LedgerError("approval does not meet the governance signature threshold")


def _repository_for(policy: dict[str, Any], role: str) -> dict[str, Any]:
    return policy["repositories"][role]


def validate_approval(
    envelope: Any,
    policy: dict[str, Any],
    *,
    now: datetime | None = None,
    verify_signatures: bool = True,
) -> dict[str, Any]:
    policy = validate_policy(policy, require_active=verify_signatures)
    envelope = _expect_object(envelope, {"schema_version", "statement", "signatures"}, "approval")
    if envelope["schema_version"] != 1:
        raise LedgerError("unsupported approval schema")
    statement = _expect_object(envelope["statement"], APPROVAL_FIELDS, "approval.statement")
    kind = statement["kind"]
    if kind not in policy["approval_kinds"]:
        raise LedgerError("approval kind is not allowed")
    rule = policy["approval_kinds"][kind]
    if statement["ledger_repository"] != policy["ledger"]["repository"]:
        raise LedgerError("approval ledger repository mismatch")
    if statement["stream"] != rule["stream"]:
        raise LedgerError("approval stream does not match its kind")
    approval_id = statement["approval_id"]
    if not isinstance(approval_id, str) or ID_RE.fullmatch(approval_id) is None:
        raise LedgerError("approval_id is invalid")
    sequence = _positive_int(statement["sequence"], "approval sequence")
    prev = _exact_digest(statement["prev"], "approval prev")
    if sequence == 1 and prev != ZERO_DIGEST:
        raise LedgerError("first approval in a stream must use the zero prev digest")
    if sequence > 1 and prev == ZERO_DIGEST:
        raise LedgerError("non-genesis approval cannot use the zero prev digest")
    _validate_nonce(statement["nonce"], policy)
    issued_at = _timestamp(statement["issued_at"], "issued_at")
    expires_at = _timestamp(statement["expires_at"], "expires_at")
    if expires_at <= issued_at:
        raise LedgerError("approval expiry must be later than issuance")
    if (expires_at - issued_at).total_seconds() > policy["limits"]["max_approval_ttl_seconds"]:
        raise LedgerError("approval TTL exceeds policy")
    current = now or datetime.now(timezone.utc)
    if current > expires_at:
        raise LedgerError("approval is expired")
    if issued_at > current and (issued_at - current).total_seconds() > 300:
        raise LedgerError("approval issued_at is unreasonably far in the future")

    source = _repository_for(policy, rule["subject_role"])
    target = _repository_for(policy, rule["target_role"])
    if (statement["source_repository"], statement["source_repository_id"]) != (
        source["repository"], source["repository_id"]
    ):
        raise LedgerError("approval source repository identity mismatch")
    if (statement["target_repository"], statement["target_repository_id"]) != (
        target["repository"], target["repository_id"]
    ):
        raise LedgerError("approval target repository identity mismatch")
    source_sha = _exact_git_sha(statement["source_revision"], "source_revision")
    _exact_git_sha(statement["source_tree"], "source_tree")
    _exact_git_sha(statement["target_base_revision"], "target_base_revision")
    _exact_git_sha(statement["target_base_tree"], "target_base_tree")
    workflow_path = statement["workflow_path"]
    if not isinstance(workflow_path, str) or WORKFLOW_RE.fullmatch(workflow_path) is None or ".." in workflow_path:
        raise LedgerError("workflow_path is invalid")
    _exact_git_sha(statement["workflow_blob_sha"], "workflow_blob_sha")
    _positive_int(statement["workflow_run_id"], "workflow_run_id")
    _positive_int(statement["workflow_run_attempt"], "workflow_run_attempt")

    checks = statement["checks"]
    if not isinstance(checks, list) or not checks:
        raise LedgerError("approval checks must be a non-empty array")
    check_names: list[str] = []
    for index, check in enumerate(checks):
        check = _expect_object(check, CHECK_FIELDS, f"approval.checks[{index}]")
        if not isinstance(check["name"], str) or not check["name"]:
            raise LedgerError("check name is invalid")
        if check["conclusion"] != "success" or check["head_sha"] != source_sha:
            raise LedgerError(f"required check is not successful for exact source: {check['name']}")
        if not isinstance(check["app_slug"], str) or not check["app_slug"]:
            raise LedgerError("check app_slug is invalid")
        check_names.append(check["name"])
    if check_names != sorted(check_names) or len(check_names) != len(set(check_names)):
        raise LedgerError("checks must be unique and sorted by name")
    if set(check_names) != set(rule["required_checks"]):
        raise LedgerError("approval does not contain the exact policy-required checks")

    version = statement["version"]
    if not isinstance(version, str) or SEMVER_RE.fullmatch(version) is None:
        raise LedgerError("approval version must be a stable semantic version")
    _validate_artifact(statement["artifact"], policy)
    if kind == "sync":
        if statement["target_ref"] != f"refs/heads/{target['default_branch']}":
            raise LedgerError("sync target_ref must be the Product default branch")
        if statement["tag"] is not None:
            raise LedgerError("sync approval tag must be null")
        for field in ("sync_manifest_sha256", "ownership_catalog_sha256", "operations_sha256"):
            _exact_digest(statement[field], field)
    else:
        expected_tag = f"v{version}" if kind == "release_free" else f"pro-v{version}"
        if statement["tag"] != expected_tag or statement["target_ref"] != f"refs/tags/{expected_tag}":
            raise LedgerError("release tag/target_ref does not match its version and kind")
        for field in ("sync_manifest_sha256", "ownership_catalog_sha256", "operations_sha256"):
            if statement[field] is not None:
                raise LedgerError(f"release approval {field} must be null")
    if statement["policy_epoch"] != policy["policy_epoch"]:
        raise LedgerError("approval policy epoch mismatch")
    if statement["policy_sha256"] != policy_digest(policy):
        raise LedgerError("approval policy digest mismatch")
    statement_bytes = canonical_json(statement)
    if verify_signatures:
        _verify_signatures(envelope, policy, statement_bytes)
    else:
        if not isinstance(envelope["signatures"], list):
            raise LedgerError("signatures must be an array")
    return {
        "approval_id": approval_id,
        "kind": kind,
        "stream": statement["stream"],
        "sequence": sequence,
        "prev": prev,
        "nonce": statement["nonce"],
        "statement_sha256": hashlib.sha256(statement_bytes).hexdigest(),
        "record_sha256": digest(envelope),
        "statement": statement,
    }


def validate_policy_transition(
    envelope: Any,
    current_policy: dict[str, Any],
    next_policy: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authorize a policy/key rotation with the currently trusted threshold."""
    current_policy = validate_policy(current_policy, require_active=True)
    next_policy = validate_policy(next_policy, require_active=True)
    envelope = _expect_object(
        envelope, {"schema_version", "statement", "signatures"}, "policy transition"
    )
    if envelope["schema_version"] != 1:
        raise LedgerError("unsupported policy transition schema")
    statement = _expect_object(
        envelope["statement"], POLICY_TRANSITION_FIELDS, "policy transition statement"
    )
    if (
        statement["kind"] != "dustmirror.policy-transition"
        or statement["ledger_repository"] != current_policy["ledger"]["repository"]
    ):
        raise LedgerError("policy transition identity is invalid")
    if (
        statement["from_epoch"] != current_policy["policy_epoch"]
        or statement["from_policy_sha256"] != policy_digest(current_policy)
    ):
        raise LedgerError("policy transition does not start at the trusted policy")
    if (
        statement["to_epoch"] != current_policy["policy_epoch"] + 1
        or next_policy["policy_epoch"] != statement["to_epoch"]
        or statement["to_policy_sha256"] != policy_digest(next_policy)
    ):
        raise LedgerError("policy transition does not bind the next policy epoch")
    _validate_nonce(statement["nonce"], current_policy)
    issued_at = _timestamp(statement["issued_at"], "policy transition issued_at")
    current = now or datetime.now(timezone.utc)
    if issued_at > current and (issued_at - current).total_seconds() > 300:
        raise LedgerError("policy transition is unreasonably far in the future")
    if not isinstance(statement["reason"], str) or not 10 <= len(statement["reason"]) <= 500:
        raise LedgerError("policy transition reason must contain 10-500 characters")
    # Repository identities and ledger location cannot be changed by key rotation.
    if (
        next_policy["ledger"] != current_policy["ledger"]
        or next_policy["repositories"] != current_policy["repositories"]
        or next_policy["paths"] != current_policy["paths"]
    ):
        raise LedgerError("policy transition cannot redirect repository identities or ledger paths")
    statement_bytes = canonical_json(statement)
    _verify_signatures(envelope, current_policy, statement_bytes)
    return {
        "from_epoch": statement["from_epoch"],
        "to_epoch": statement["to_epoch"],
        "record_sha256": digest(envelope),
    }


def validate_receipt(
    envelope: Any,
    policy: dict[str, Any],
    approval: dict[str, Any],
    *,
    verify_signatures: bool = True,
) -> dict[str, Any]:
    policy = validate_policy(policy, require_active=verify_signatures)
    envelope = _expect_object(envelope, {"schema_version", "statement", "signatures"}, "receipt")
    if envelope["schema_version"] != 1:
        raise LedgerError("unsupported receipt schema")
    statement = _expect_object(envelope["statement"], RECEIPT_FIELDS, "receipt.statement")
    approval_result = validate_approval(
        approval, policy, now=_timestamp(statement["issued_at"], "receipt issued_at"),
        verify_signatures=verify_signatures,
    )
    approved = approval_result["statement"]
    if not isinstance(statement["receipt_id"], str) or ID_RE.fullmatch(statement["receipt_id"]) is None:
        raise LedgerError("receipt_id is invalid")
    _validate_nonce(statement["nonce"], policy)
    if statement["approval_record_sha256"] != approval_result["record_sha256"]:
        raise LedgerError("receipt approval digest mismatch")
    issued_at = _timestamp(statement["issued_at"], "receipt issued_at")
    approval_expires = _timestamp(statement["approval_expires_at"], "approval_expires_at")
    if statement["approval_expires_at"] != approved["expires_at"] or issued_at > approval_expires:
        raise LedgerError("receipt was issued after approval expiry")
    action_by_kind = {
        "sync": "sync_pr_opened",
        "release_free": "release_free_published",
        "release_pro": "release_pro_published",
    }
    if statement["action"] != action_by_kind[approved["kind"]] or statement["status"] != "succeeded":
        raise LedgerError("receipt action/status does not match approval kind")
    for field in (
        "ledger_repository", "stream", "kind", "approval_id", "source_repository",
        "source_repository_id", "source_revision", "source_tree", "target_repository",
        "target_repository_id", "version", "tag", "artifact", "policy_epoch",
        "policy_sha256",
    ):
        if statement[field] != approved[field]:
            raise LedgerError(f"receipt does not match approval field: {field}")
    if not isinstance(statement["workflow_path"], str) or WORKFLOW_RE.fullmatch(statement["workflow_path"]) is None:
        raise LedgerError("receipt workflow path is invalid")
    _exact_git_sha(statement["workflow_blob_sha"], "receipt workflow blob")
    _positive_int(statement["workflow_run_id"], "receipt workflow_run_id")
    _positive_int(statement["workflow_run_attempt"], "receipt workflow_run_attempt")
    _exact_git_sha(statement["target_commit"], "receipt target_commit")
    _exact_git_sha(statement["target_tree"], "receipt target_tree")
    if approved["kind"] == "sync":
        _positive_int(statement["target_pull_request_number"], "target_pull_request_number")
        if statement["target_release_id"] is not None or not str(statement["target_ref"]).startswith("refs/heads/"):
            raise LedgerError("sync receipt target identity is invalid")
    else:
        _positive_int(statement["target_release_id"], "target_release_id")
        if statement["target_pull_request_number"] is not None or statement["target_ref"] != approved["target_ref"]:
            raise LedgerError("release receipt target identity is invalid")
    statement_bytes = canonical_json(statement)
    if verify_signatures:
        _verify_signatures(envelope, policy, statement_bytes)
    return {
        "receipt_id": statement["receipt_id"],
        "approval_id": statement["approval_id"],
        "nonce": statement["nonce"],
        "record_sha256": digest(envelope),
    }


def _record_paths(root: Path, category: str) -> Iterable[Path]:
    base = root / "governance" / category
    if not base.exists():
        return []
    return sorted(path for path in base.glob("*/*.json") if path.is_file())


def validate_tree(root: Path, *, now: datetime | None = None) -> dict[str, int]:
    policy = validate_policy(load_json(root / "governance" / "policy.json"))
    policies: dict[int, dict[str, Any]] = {}
    policy_dir = root / "governance" / "policies"
    if policy_dir.exists():
        for path in sorted(policy_dir.glob("epoch-*.json")):
            snapshot = validate_policy(load_json(path), require_active=True)
            epoch = snapshot["policy_epoch"]
            if path.name != f"epoch-{epoch}.json" or epoch in policies:
                raise LedgerError(f"policy snapshot path/epoch is invalid: {path}")
            policies[epoch] = snapshot
    if policy["activation_status"] == "active":
        if not policies or max(policies) != policy["policy_epoch"]:
            raise LedgerError("active policy must have an immutable latest epoch snapshot")
        if policies[policy["policy_epoch"]] != policy:
            raise LedgerError("current policy differs from its immutable epoch snapshot")
        expected_epochs = set(range(1, policy["policy_epoch"] + 1))
        if set(policies) != expected_epochs:
            raise LedgerError("policy epoch history is incomplete")
        for epoch in range(2, policy["policy_epoch"] + 1):
            transition_path = root / "governance" / "policy-transitions" / f"epoch-{epoch}.json"
            if not transition_path.is_file():
                raise LedgerError(f"missing signed policy transition for epoch {epoch}")
            validate_policy_transition(
                load_json(transition_path), policies[epoch - 1], policies[epoch], now=now
            )
    elif policies:
        raise LedgerError("provisioning policy cannot have active policy snapshots")
    approvals: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    stream_records: dict[str, list[dict[str, Any]]] = {}
    all_nonces: set[str] = set()
    approval_paths = list(_record_paths(root, "approvals"))
    receipt_paths = list(_record_paths(root, "receipts"))
    if (approval_paths or receipt_paths) and policy["activation_status"] != "active":
        raise LedgerError("REMOTE_ACTIVATION_PENDING: ledger records cannot exist before key provisioning")
    for path in approval_paths:
        envelope = load_json(path)
        statement = envelope.get("statement") if isinstance(envelope, dict) else None
        epoch = statement.get("policy_epoch") if isinstance(statement, dict) else None
        record_policy = policies.get(epoch)
        if record_policy is None:
            raise LedgerError(f"approval references unknown policy epoch: {epoch}")
        # Historical approvals remain auditable after their execution window
        # expires. Freshness is enforced for newly added records by the PR gate
        # and again immediately before execution.
        historical_time = _timestamp(statement.get("issued_at"), "approval issued_at")
        result = validate_approval(envelope, record_policy, now=historical_time)
        expected = root / "governance" / "approvals" / result["kind"] / f"{result['approval_id']}.json"
        if path.resolve() != expected.resolve():
            raise LedgerError(f"approval path does not match record identity: {path}")
        if result["approval_id"] in approvals:
            raise LedgerError(f"duplicate approval_id: {result['approval_id']}")
        if result["nonce"] in all_nonces:
            raise LedgerError(f"duplicate ledger nonce: {result['nonce']}")
        all_nonces.add(result["nonce"])
        approvals[result["approval_id"]] = (envelope, result)
        stream_records.setdefault(result["stream"], []).append(result)
    for stream, records in stream_records.items():
        records.sort(key=lambda value: value["sequence"])
        previous = ZERO_DIGEST
        for expected_sequence, record in enumerate(records, start=1):
            if record["sequence"] != expected_sequence or record["prev"] != previous:
                raise LedgerError(f"broken approval chain in stream {stream}")
            previous = record["record_sha256"]

    receipt_ids: set[str] = set()
    consumed: set[str] = set()
    for path in receipt_paths:
        envelope = load_json(path)
        statement = envelope.get("statement") if isinstance(envelope, dict) else None
        approval_id = statement.get("approval_id") if isinstance(statement, dict) else None
        if approval_id not in approvals:
            raise LedgerError(f"receipt references unknown approval: {approval_id}")
        approval_epoch = approvals[approval_id][1]["statement"]["policy_epoch"]
        result = validate_receipt(
            envelope, policies[approval_epoch], approvals[approval_id][0]
        )
        kind = approvals[approval_id][1]["kind"]
        expected = root / "governance" / "receipts" / kind / f"{result['receipt_id']}.json"
        if path.resolve() != expected.resolve():
            raise LedgerError(f"receipt path does not match record identity: {path}")
        if result["receipt_id"] in receipt_ids or result["nonce"] in all_nonces:
            raise LedgerError("duplicate receipt identity or nonce")
        if result["approval_id"] in consumed:
            raise LedgerError(f"approval has more than one successful receipt: {result['approval_id']}")
        receipt_ids.add(result["receipt_id"])
        all_nonces.add(result["nonce"])
        consumed.add(result["approval_id"])
    return {"approvals": len(approvals), "receipts": len(receipt_ids)}


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest_parser = subparsers.add_parser("policy-digest")
    digest_parser.add_argument("--policy", type=Path, default=Path("governance/policy.json"))
    approval_parser = subparsers.add_parser("validate-approval")
    approval_parser.add_argument("record", type=Path)
    approval_parser.add_argument("--policy", type=Path, default=Path("governance/policy.json"))
    receipt_parser = subparsers.add_parser("validate-receipt")
    receipt_parser.add_argument("record", type=Path)
    receipt_parser.add_argument("--approval", type=Path, required=True)
    receipt_parser.add_argument("--policy", type=Path, default=Path("governance/policy.json"))
    tree_parser = subparsers.add_parser("validate-tree")
    tree_parser.add_argument("root", type=Path, nargs="?", default=Path("."))
    args = parser.parse_args(argv)
    try:
        if args.command == "policy-digest":
            print(policy_digest(load_json(args.policy)))
        elif args.command == "validate-approval":
            result = validate_approval(load_json(args.record), load_json(args.policy))
            print(json.dumps(result, sort_keys=True, default=str))
        elif args.command == "validate-receipt":
            result = validate_receipt(
                load_json(args.record), load_json(args.policy), load_json(args.approval)
            )
            print(json.dumps(result, sort_keys=True))
        else:
            print(json.dumps(validate_tree(args.root), sort_keys=True))
        return 0
    except LedgerError as exc:
        print(f"governance ledger rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
