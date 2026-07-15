#!/usr/bin/env python3
"""Validate a pull-request tree using only trusted base-branch Python code."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import ledger


IMMUTABLE_PREFIXES = (
    "governance/approvals/",
    "governance/receipts/",
    "governance/policies/",
    "governance/policy-transitions/",
)


def _files(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if ".git" in path.relative_to(root).parts or "__pycache__" in path.parts:
            continue
        if path.is_symlink():
            if relative.startswith("governance/"):
                raise ledger.LedgerError(f"governance paths cannot be symlinks: {relative}")
            continue
        if path.is_file():
            result[relative] = path.read_bytes()
    return result


def validate_pr(base: Path, candidate: Path) -> dict[str, int]:
    base_files = _files(base)
    candidate_files = _files(candidate)
    added = sorted(set(candidate_files) - set(base_files))
    deleted = sorted(set(base_files) - set(candidate_files))
    modified = sorted(
        path for path in set(base_files) & set(candidate_files)
        if base_files[path] != candidate_files[path]
    )

    for path in deleted + modified:
        if path.startswith(IMMUTABLE_PREFIXES):
            raise ledger.LedgerError(f"immutable ledger history changed or was deleted: {path}")

    live_added = [
        path for path in added
        if path.startswith(("governance/approvals/", "governance/receipts/"))
    ]
    policy_changed = "governance/policy.json" in modified
    history_added = [
        path for path in added
        if path.startswith(("governance/policies/", "governance/policy-transitions/"))
    ]
    all_changed = set(added + modified + deleted)

    if live_added:
        if any(
            not path.startswith(("governance/approvals/", "governance/receipts/"))
            for path in all_changed
        ):
            raise ledger.LedgerError(
                "live approval/receipt PRs cannot change control-plane code, policy, or docs"
            )
        if any(not path.endswith(".json") for path in live_added):
            raise ledger.LedgerError("live ledger records must be JSON files")

    base_policy = ledger.validate_policy(
        ledger.load_json(base / "governance" / "policy.json")
    )
    candidate_policy = ledger.validate_policy(
        ledger.load_json(candidate / "governance" / "policy.json")
    )
    if policy_changed:
        if live_added:
            raise ledger.LedgerError("policy changes and live records require separate PRs")
        if base_policy["activation_status"] == "provisioning_required":
            expected = {
                "governance/policy.json",
                "governance/policies/epoch-1.json",
            }
            if (
                candidate_policy["activation_status"] != "active"
                or candidate_policy["policy_epoch"] != 1
                or all_changed != expected
            ):
                raise ledger.LedgerError(
                    "bootstrap activation PR must contain only active policy + epoch-1 snapshot"
                )
        else:
            next_epoch = base_policy["policy_epoch"] + 1
            expected = {
                "governance/policy.json",
                f"governance/policies/epoch-{next_epoch}.json",
                f"governance/policy-transitions/epoch-{next_epoch}.json",
            }
            if all_changed != expected:
                raise ledger.LedgerError(
                    "policy rotation PR must contain only policy, snapshot, and signed transition"
                )
            snapshot = ledger.load_json(
                candidate / "governance" / "policies" / f"epoch-{next_epoch}.json"
            )
            if snapshot != candidate_policy:
                raise ledger.LedgerError("next policy snapshot differs from current policy")
            ledger.validate_policy_transition(
                ledger.load_json(
                    candidate / "governance" / "policy-transitions" / f"epoch-{next_epoch}.json"
                ),
                base_policy,
                candidate_policy,
            )
    elif history_added:
        raise ledger.LedgerError("policy history can only be added with a policy change")

    counts = ledger.validate_tree(candidate)
    # A structurally valid historical record may be expired. Newly proposed
    # approvals must be valid now and must use the current policy epoch.
    for path in live_added:
        if not path.startswith("governance/approvals/"):
            continue
        envelope = ledger.load_json(candidate / path)
        statement = envelope.get("statement") if isinstance(envelope, dict) else None
        if not isinstance(statement, dict) or statement.get("policy_epoch") != candidate_policy["policy_epoch"]:
            raise ledger.LedgerError("new approval must use the current policy epoch")
        ledger.validate_approval(envelope, candidate_policy)
    counts.update({"added": len(added), "modified": len(modified), "deleted": len(deleted)})
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_pr(args.base.resolve(), args.candidate.resolve())
        print(result)
        return 0
    except ledger.LedgerError as exc:
        print(f"ledger-static rejected pull request: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
