from __future__ import annotations

import argparse
import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import verify_product_verifier_evidence as verifier


TAG = "v1.3.27"
VERSION = "1.3.27"
BUILD = "candidate-27"
COMMIT = "a" * 40
TREE = "b" * 40
REQUEST_SHA = "c" * 64
LEDGER_COMMIT = "d" * 40
LEDGER_TREE = "e" * 40


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fixture(tmp_path: Path) -> argparse.Namespace:
    tmp_path.mkdir(parents=True, exist_ok=True)
    members = {"ota-command-trace.jsonl": b"trace\n", "quality-gate-receipt.json": b"quality"}
    archive = tmp_path / f"DustMirror-verifier-evidence-{REQUEST_SHA}.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        for name, raw in members.items():
            zipped.writestr(name, raw)
    rows = [
        {"name": name, "size_bytes": len(raw), "sha256": _sha(raw)}
        for name, raw in sorted(members.items())
    ]
    descriptor = verifier.file_record(archive)
    verifier_manifest = {
        "schema": "dustmirror.verifier-evidence-archive/v1",
        "status": "passed",
        "version": VERSION,
        "build_id": BUILD,
        "product_commit": COMMIT,
        "product_tree": TREE,
        "request_sha256": REQUEST_SHA,
        **descriptor,
        "files": rows,
    }
    verifier_path = tmp_path / "verifier-evidence-manifest.json"
    verifier_path.write_bytes(_canonical(verifier_manifest))
    gate = {
        "schema": "dustmirror.release-gate.v1",
        "status": "passed",
        "release_ready": True,
        "release_phase": "prepublish",
        "working_tree_clean": True,
        "qa_skipped": False,
        "version": VERSION,
        "cnb_build_id": BUILD,
        "commit": COMMIT,
        "tree": TREE,
        "verifier_evidence_archive": descriptor,
    }
    gate_path = tmp_path / "release-gate-manifest.json"
    gate_path.write_bytes(_canonical(gate))
    file_rows = []
    for name in sorted(verifier.SIGNED_RESPONSE_FILES):
        if name == gate_path.name:
            raw = gate_path.read_bytes()
        elif name == verifier_path.name:
            raw = verifier_path.read_bytes()
        else:
            raw = name.encode()
        file_rows.append({"name": name, "size_bytes": len(raw), "sha256": _sha(raw)})
    result = {
        "schema": "dustmirror.protected-signer-result/v1",
        "status": "passed",
        "version": VERSION,
        "build_id": BUILD,
        "product": {"repository": "yitaocn/dustmirror", "commit": COMMIT, "tree": TREE},
        "request_sha256": REQUEST_SHA,
        "release_ledger": {"commit": LEDGER_COMMIT, "tree": LEDGER_TREE},
        "signer": {"repository": "yitaocn/dustmirror-release-signer"},
        "isolation": verifier.EXPECTED_ISOLATION,
        "files": file_rows,
    }
    result_path = tmp_path / "signer-result.json"
    result_raw = _canonical(result)
    result_path.write_bytes(result_raw)
    private = Ed25519PrivateKey.generate()
    signature_path = tmp_path / "signer-result.sig"
    signature_path.write_text(base64.b64encode(private.sign(result_raw)).decode(), encoding="ascii")
    public = base64.b64encode(
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    return argparse.Namespace(
        signer_result=result_path,
        signer_result_signature=signature_path,
        release_gate_manifest=gate_path,
        verifier_evidence_manifest=verifier_path,
        verifier_archive=archive,
        publication_public_key_b64=public,
        expected_tag=TAG,
        expected_product_build_id=BUILD,
        expected_product_commit=COMMIT,
        expected_product_tree=TREE,
        expected_request_sha256=REQUEST_SHA,
        expected_release_ledger_commit=LEDGER_COMMIT,
        expected_release_ledger_tree=LEDGER_TREE,
        expected_verifier_attachment=archive.name,
    )


def test_accepts_only_archive_bound_by_signed_result_and_manifest(tmp_path: Path) -> None:
    result = verifier.verify(_fixture(tmp_path))
    assert result["status"] == "verified"
    assert result["member_count"] == 2
    assert result["archive"]["name"] == f"DustMirror-verifier-evidence-{REQUEST_SHA}.zip"


def test_rejects_archive_name_or_request_identity_drift(tmp_path: Path) -> None:
    args = _fixture(tmp_path)
    args.expected_verifier_attachment = "different.zip"
    with pytest.raises(verifier.VerifierEvidenceError, match="verifier_attachment_name_invalid"):
        verifier.verify(args)
    args = _fixture(tmp_path / "request")
    args.expected_request_sha256 = "f" * 64
    with pytest.raises(verifier.VerifierEvidenceError, match="verifier_attachment_name_invalid"):
        verifier.verify(args)


def test_rejects_tampered_signed_descriptor_or_archive_member(tmp_path: Path) -> None:
    args = _fixture(tmp_path / "descriptor")
    gate = json.loads(args.release_gate_manifest.read_text())
    gate["verifier_evidence_archive"]["sha256"] = "f" * 64
    args.release_gate_manifest.write_bytes(_canonical(gate))
    with pytest.raises(verifier.VerifierEvidenceError, match="signer_result_file_digest_invalid"):
        verifier.verify(args)

    args = _fixture(tmp_path / "archive")
    with zipfile.ZipFile(args.verifier_archive, "a") as zipped:
        zipped.writestr("unexpected.txt", b"no")
    with pytest.raises(verifier.VerifierEvidenceError, match="release_gate_verifier_descriptor_invalid"):
        verifier.verify(args)
