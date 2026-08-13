"""Independently verify Product's signed verifier-evidence archive.

The archive is downloaded separately from the closed Candidate handoff.  Its
descriptor and member inventory are trusted only after the protected signer's
detached signature over ``signer-result.json`` has been verified.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BUILD_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SEMVER_TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
MAX_ARCHIVE_BYTES = 12 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 24 * 1024 * 1024 * 1024
MAX_MEMBERS = 4096
CHUNK_SIZE = 1024 * 1024
SIGNED_RESPONSE_FILES = {
    "release-gate-manifest.json",
    "manifest.json",
    "manifest.sig",
    "trust.json",
    "trust.sig",
    "sbom.json",
    "ota-upgrade-evidence.json",
    "ota-upgrade-evidence.sig",
    "ota-legacy-1.2.14-evidence.json",
    "ota-legacy-1.2.14-evidence.sig",
    "pro-deployment-receipt.json",
    "pro-deployment-receipt.sig",
    "publication-authorization.json",
    "publication-authorization.sig",
    "gui-dev-smoke.json",
    "ui-visual-evidence.json",
    "performance/runtime.json",
    "performance/complete.json",
    "verifier-evidence-manifest.json",
}
RESULT_FIELDS = {
    "schema",
    "status",
    "version",
    "build_id",
    "product",
    "request_sha256",
    "signer",
    "release_ledger",
    "files",
    "isolation",
}
EXPECTED_ISOLATION = {
    "private_keys_available_to_product": False,
    "private_keys_available_to_evidence_worker": False,
    "product_checkout_present_in_signing_worker": False,
    "product_scripts_executed_in_signing_worker": False,
    "candidate_artifacts_executed_in_signing_worker": False,
}


class VerifierEvidenceError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def file_record(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return {"name": path.name, "size_bytes": size, "sha256": digest.hexdigest()}


def _load_canonical(path: Path, label: str) -> tuple[bytes, dict]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerifierEvidenceError(f"{label}_invalid_json") from exc
    if not isinstance(value, dict) or raw != canonical(value):
        raise VerifierEvidenceError(f"{label}_not_canonical")
    return raw, value


def _member_name(info: zipfile.ZipInfo) -> str:
    if info.flag_bits & 0x1:
        raise VerifierEvidenceError("verifier_archive_encrypted_member")
    name = info.filename
    if "\\" in name or "\x00" in name:
        raise VerifierEvidenceError("verifier_archive_path_invalid")
    pure = PurePosixPath(name)
    mode = (info.external_attr >> 16) & 0xFFFF
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or info.is_dir()
        or stat.S_ISLNK(mode)
    ):
        raise VerifierEvidenceError("verifier_archive_member_invalid")
    return pure.as_posix()


def _manifest_rows(value: object) -> dict[str, dict]:
    if not isinstance(value, list) or not value or len(value) > MAX_MEMBERS:
        raise VerifierEvidenceError("verifier_manifest_inventory_invalid")
    rows: dict[str, dict] = {}
    for row in value:
        if not isinstance(row, dict) or set(row) != {"name", "size_bytes", "sha256"}:
            raise VerifierEvidenceError("verifier_manifest_inventory_invalid")
        name = row.get("name")
        size = row.get("size_bytes")
        digest = row.get("sha256")
        if (
            not isinstance(name, str)
            or name in rows
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or not HEX64.fullmatch(digest)
        ):
            raise VerifierEvidenceError("verifier_manifest_inventory_invalid")
        fake = zipfile.ZipInfo(name)
        fake.external_attr = (stat.S_IFREG | 0o644) << 16
        if _member_name(fake) != name:
            raise VerifierEvidenceError("verifier_manifest_inventory_invalid")
        rows[name] = row
    if sum(row["size_bytes"] for row in rows.values()) > MAX_EXPANDED_BYTES:
        raise VerifierEvidenceError("verifier_manifest_expansion_too_large")
    return rows


def _verify_archive_members(archive: Path, rows: dict[str, dict]) -> None:
    with zipfile.ZipFile(archive) as zipped:
        infos = zipped.infolist()
        names = [_member_name(info) for info in infos]
        if len(names) != len(set(names)) or set(names) != set(rows):
            raise VerifierEvidenceError("verifier_archive_inventory_mismatch")
        if sum(info.file_size for info in infos) > MAX_EXPANDED_BYTES:
            raise VerifierEvidenceError("verifier_archive_expansion_too_large")
        for info, name in zip(infos, names, strict=True):
            wanted = rows[name]
            if info.file_size != wanted["size_bytes"]:
                raise VerifierEvidenceError(f"verifier_archive_size_mismatch:{name}")
            digest = hashlib.sha256()
            size = 0
            with zipped.open(info) as source:
                while chunk := source.read(CHUNK_SIZE):
                    digest.update(chunk)
                    size += len(chunk)
                    if size > wanted["size_bytes"]:
                        raise VerifierEvidenceError(f"verifier_archive_size_mismatch:{name}")
            if size != wanted["size_bytes"] or digest.hexdigest() != wanted["sha256"]:
                raise VerifierEvidenceError(f"verifier_archive_digest_mismatch:{name}")


def verify(args: argparse.Namespace) -> dict[str, object]:
    if (
        not SEMVER_TAG.fullmatch(args.expected_tag)
        or not BUILD_ID.fullmatch(args.expected_product_build_id)
        or not HEX40.fullmatch(args.expected_product_commit)
        or not HEX40.fullmatch(args.expected_product_tree)
        or not HEX40.fullmatch(args.expected_release_ledger_commit)
        or not HEX40.fullmatch(args.expected_release_ledger_tree)
        or not HEX64.fullmatch(args.expected_request_sha256)
    ):
        raise VerifierEvidenceError("expected_identity_invalid")
    expected_name = f"DustMirror-verifier-evidence-{args.expected_request_sha256}.zip"
    if args.expected_verifier_attachment != expected_name:
        raise VerifierEvidenceError("verifier_attachment_name_invalid")
    archive = args.verifier_archive.resolve(strict=True)
    if (
        archive.name != args.expected_verifier_attachment
        or archive.is_symlink()
        or archive.stat().st_size > MAX_ARCHIVE_BYTES
    ):
        raise VerifierEvidenceError("verifier_archive_invalid")

    result_raw, result = _load_canonical(args.signer_result, "signer_result")
    signature = base64.b64decode(
        args.signer_result_signature.read_text(encoding="ascii").strip(), validate=True
    )
    public_key = base64.b64decode(args.publication_public_key_b64, validate=True)
    if len(public_key) != 32 or len(signature) != 64:
        raise VerifierEvidenceError("signer_result_signature_material_invalid")
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, result_raw)

    version = args.expected_tag.removeprefix("v")
    expected_product = {
        "repository": "yitaocn/dustmirror",
        "commit": args.expected_product_commit,
        "tree": args.expected_product_tree,
    }
    expected_ledger = {
        "commit": args.expected_release_ledger_commit,
        "tree": args.expected_release_ledger_tree,
    }
    if (
        set(result) != RESULT_FIELDS
        or not isinstance(result.get("signer"), dict)
        or result.get("isolation") != EXPECTED_ISOLATION
        or result.get("schema") != "dustmirror.protected-signer-result/v1"
        or result.get("status") != "passed"
        or result.get("version") != version
        or result.get("build_id") != args.expected_product_build_id
        or result.get("product") != expected_product
        or result.get("request_sha256") != args.expected_request_sha256
        or result.get("release_ledger") != expected_ledger
    ):
        raise VerifierEvidenceError("signer_result_identity_invalid")
    file_rows = result.get("files")
    if not isinstance(file_rows, list) or len(file_rows) != len(SIGNED_RESPONSE_FILES):
        raise VerifierEvidenceError("signer_result_inventory_invalid")
    indexed = {
        row.get("name"): row for row in file_rows if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    if set(indexed) != SIGNED_RESPONSE_FILES or len(indexed) != len(file_rows):
        raise VerifierEvidenceError("signer_result_inventory_invalid")

    gate_raw, gate = _load_canonical(args.release_gate_manifest, "release_gate_manifest")
    verifier_raw, verifier = _load_canonical(
        args.verifier_evidence_manifest, "verifier_evidence_manifest"
    )
    for name, raw in (
        ("release-gate-manifest.json", gate_raw),
        ("verifier-evidence-manifest.json", verifier_raw),
    ):
        expected_row = {
            "name": name,
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        if indexed[name] != expected_row:
            raise VerifierEvidenceError(f"signer_result_file_digest_invalid:{name}")

    if (
        gate.get("schema") != "dustmirror.release-gate.v1"
        or gate.get("status") != "passed"
        or gate.get("release_ready") is not True
        or gate.get("release_phase") != "prepublish"
        or gate.get("working_tree_clean") is not True
        or gate.get("qa_skipped") is not False
        or gate.get("version") != version
        or gate.get("cnb_build_id") != args.expected_product_build_id
        or gate.get("commit") != args.expected_product_commit
        or gate.get("tree") != args.expected_product_tree
    ):
        raise VerifierEvidenceError("release_gate_identity_or_status_invalid")

    descriptor = file_record(archive)
    if gate.get("verifier_evidence_archive") != descriptor:
        raise VerifierEvidenceError("release_gate_verifier_descriptor_invalid")
    if (
        verifier.get("schema") != "dustmirror.verifier-evidence-archive/v1"
        or verifier.get("status") != "passed"
        or verifier.get("version") != version
        or verifier.get("build_id") != args.expected_product_build_id
        or verifier.get("product_commit") != args.expected_product_commit
        or verifier.get("product_tree") != args.expected_product_tree
        or verifier.get("request_sha256") != args.expected_request_sha256
        or any(verifier.get(key) != value for key, value in descriptor.items())
    ):
        raise VerifierEvidenceError("verifier_manifest_binding_invalid")
    rows = _manifest_rows(verifier.get("files"))
    _verify_archive_members(archive, rows)
    return {
        "schema": "dustmirror.public-verifier-evidence/v1",
        "status": "verified",
        "tag": args.expected_tag,
        "request_sha256": args.expected_request_sha256,
        "archive": descriptor,
        "member_count": len(rows),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signer-result", type=Path, required=True)
    parser.add_argument("--signer-result-signature", type=Path, required=True)
    parser.add_argument("--release-gate-manifest", type=Path, required=True)
    parser.add_argument("--verifier-evidence-manifest", type=Path, required=True)
    parser.add_argument("--verifier-archive", type=Path, required=True)
    parser.add_argument("--publication-public-key-b64", required=True)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--expected-product-build-id", required=True)
    parser.add_argument("--expected-product-commit", required=True)
    parser.add_argument("--expected-product-tree", required=True)
    parser.add_argument("--expected-request-sha256", required=True)
    parser.add_argument("--expected-release-ledger-commit", required=True)
    parser.add_argument("--expected-release-ledger-tree", required=True)
    parser.add_argument("--expected-verifier-attachment", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = verify(args)
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"verified": True, **receipt}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
