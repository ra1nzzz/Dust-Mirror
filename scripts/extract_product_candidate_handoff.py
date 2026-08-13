#!/usr/bin/env python3
"""Safely extract the eight public files from Product's closed handoff archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


BUILD_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
MAX_ARCHIVE_BYTES = 3 * 1024 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 6 * 1024 * 1024 * 1024

CONTROL_FILES = (
    "candidate-approved.json", "candidate-version-plan.json", "public-baseline.json",
    "quality-gate-receipt.json", "release-change-impact.json", "signer-request.json",
    "signer-result.json", "signer-result.sig", "release-gate-manifest.json",
    "verifier-evidence-manifest.json",
    "publication-authorization.json", "publication-authorization.sig", "manifest.json",
    "manifest.sig", "trust.json", "trust.sig", "sbom.json",
    "ota-upgrade-evidence.json", "ota-upgrade-evidence.sig",
    "ota-legacy-1.2.14-evidence.json", "ota-legacy-1.2.14-evidence.sig",
    "pro-deployment-receipt.json", "pro-deployment-receipt.sig", "gui-dev-smoke.json",
    "ui-visual-evidence.json", "performance/runtime.json", "performance/complete.json",
)

VERIFICATION_FILES = {
    "candidate-approved.json",
    "signer-request.json",
    "signer-result.json",
    "signer-result.sig",
    "release-gate-manifest.json",
    "verifier-evidence-manifest.json",
}


class HandoffError(RuntimeError):
    pass


def archive_name(build_id: str) -> str:
    if not BUILD_ID.fullmatch(build_id):
        raise HandoffError("product_build_id_invalid")
    return f"DustMirror-candidate-handoff-{build_id}.zip"


def full_inventory(version: str) -> set[str]:
    if not SEMVER.fullmatch(version):
        raise HandoffError("version_invalid")
    return set(CONTROL_FILES) | {
        f"DustMirror-v{version}-FREE-win64.zip",
        f"DustMirror-v{version}-GUI-win64.zip",
    }


def public_inventory(version: str) -> set[str]:
    return {
        f"DustMirror-v{version}-FREE-win64.zip",
        f"DustMirror-v{version}-GUI-win64.zip",
        "manifest.json", "manifest.sig", "trust.json", "trust.sig",
        "publication-authorization.json", "publication-authorization.sig",
    }


def _member(info: zipfile.ZipInfo) -> str:
    name = info.filename
    if "\\" in name or "\x00" in name:
        raise HandoffError("handoff_path_invalid")
    pure = PurePosixPath(name)
    mode = (info.external_attr >> 16) & 0xFFFF
    if (
        pure.is_absolute() or not pure.parts or
        any(part in {"", ".", ".."} for part in pure.parts) or
        info.is_dir() or stat.S_ISLNK(mode)
    ):
        raise HandoffError("handoff_member_invalid")
    return pure.as_posix()


def extract(args: argparse.Namespace) -> dict[str, object]:
    version = args.tag.removeprefix("v")
    if (
        not SEMVER.fullmatch(version)
        or not SHA40.fullmatch(args.product_commit)
        or not SHA40.fullmatch(args.product_tree)
        or not SHA40.fullmatch(args.release_ledger_commit)
        or not SHA40.fullmatch(args.release_ledger_tree)
        or not SHA64.fullmatch(args.request_sha256)
    ):
        raise HandoffError("release_identity_invalid")
    if not BUILD_ID.fullmatch(args.product_build_id):
        raise HandoffError("product_build_id_invalid")
    archive = args.archive.resolve(strict=True)
    if (
        args.handoff_attachment != archive_name(args.product_build_id)
        or archive.name != args.handoff_attachment
        or archive.is_symlink()
        or archive.stat().st_size > MAX_ARCHIVE_BYTES
    ):
        raise HandoffError("handoff_archive_invalid")
    output = args.output_directory.resolve()
    verification = args.verification_directory.resolve()
    if output == verification:
        raise HandoffError("handoff_output_collision")
    output.mkdir(parents=True, exist_ok=True)
    verification.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()) or any(verification.iterdir()):
        raise HandoffError("handoff_output_not_empty")
    staging = Path(tempfile.mkdtemp(prefix=".public-handoff-", dir=output.parent))
    try:
        with zipfile.ZipFile(archive) as zipped:
            infos = zipped.infolist()
            names = [_member(info) for info in infos]
            if len(names) != len(set(names)) or set(names) != full_inventory(version):
                raise HandoffError("handoff_inventory_invalid")
            if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED_BYTES:
                raise HandoffError("handoff_expansion_too_large")
            for info, name in zip(infos, names, strict=True):
                if name not in public_inventory(version) and name not in VERIFICATION_FILES:
                    continue
                target = staging / name
                with zipped.open(info) as source, target.open("xb") as destination:
                    shutil.copyfileobj(source, destination, 1024 * 1024)
        try:
            approval = json.loads((staging / "candidate-approved.json").read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise HandoffError("candidate_approval_invalid") from exc
        if (
            not isinstance(approval, dict) or
            approval.get("schema") != "dustmirror.pre-tag-candidate/v1" or
            approval.get("status") != "passed" or approval.get("version") != version or
            approval.get("build_id") != args.product_build_id or
            approval.get("product_commit") != args.product_commit or
            approval.get("product_tree") != args.product_tree
        ):
            raise HandoffError("candidate_approval_identity_mismatch")
        try:
            request_raw = (staging / "signer-request.json").read_bytes()
            request = json.loads(request_raw.decode("utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise HandoffError("signer_request_invalid") from exc
        if (
            hashlib.sha256(request_raw).hexdigest() != args.request_sha256
            or not isinstance(request, dict)
            or request.get("schema") != "dustmirror.unsigned-release-candidate/v1"
            or request.get("status") != "ready_for_protected_signer"
            or request.get("version") != version
            or request.get("build_id") != args.product_build_id
            or request.get("product")
            != {
                "repository": "yitaocn/dustmirror",
                "branch": "master",
                "commit": args.product_commit,
                "tree": args.product_tree,
            }
            or request.get("release_ledger")
            != {"commit": args.release_ledger_commit, "tree": args.release_ledger_tree}
        ):
            raise HandoffError("signer_request_identity_mismatch")
        try:
            authorization_raw = (staging / "publication-authorization.json").read_bytes()
            authorization = json.loads(authorization_raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise HandoffError("publication_authorization_invalid") from exc
        if (
            not isinstance(authorization, dict)
            or authorization.get("product_commit") != args.product_commit
            or authorization.get("product_tree") != args.product_tree
            or authorization.get("cnb_build_id") != args.product_build_id
            or authorization.get("tag") != args.tag
            or authorization.get("release_commit") != args.release_ledger_commit
            or authorization.get("release_tree") != args.release_ledger_tree
        ):
            raise HandoffError("publication_authorization_identity_mismatch")
        for name in sorted(public_inventory(version)):
            os.replace(staging / name, output / name)
        for name in sorted(VERIFICATION_FILES):
            os.replace(staging / name, verification / name)
        return {
            "status": "extracted",
            "file_count": len(public_inventory(version)),
            "verification_file_count": len(VERIFICATION_FILES),
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--verification-directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--product-build-id", required=True)
    parser.add_argument("--product-commit", required=True)
    parser.add_argument("--product-tree", required=True)
    parser.add_argument("--handoff-attachment", required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--release-ledger-commit", required=True)
    parser.add_argument("--release-ledger-tree", required=True)
    args = parser.parse_args(argv)
    try:
        result = extract(args)
    except (HandoffError, OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
