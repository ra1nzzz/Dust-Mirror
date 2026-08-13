from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_publication_authorization.py"
TARGETS = {"cnb": "yitaocn/dust-mirror", "github": "ra1nzzz/Dust-Mirror"}


def _asset(path: Path) -> dict:
    import hashlib

    raw = path.read_bytes()
    return {"name": path.name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _run(
    tmp_path: Path,
    *,
    replace_control: bool = False,
    ttl: timedelta = timedelta(hours=1),
    issued_offset: timedelta = timedelta(0),
    expected_product_commit: str = "a" * 40,
    expected_product_tree: str = "b" * 40,
    resume_grant: bool = False,
    resume_grant_ttl: timedelta = timedelta(hours=1),
    resume_grant_product_tree: str = "b" * 40,
) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    version, tag, build_id = "1.2.22", "v1.2.22", "build-22"
    files = {}
    for name in ("manifest.json", "manifest.sig", "trust.json", "trust.sig"):
        files[name] = tmp_path / name
        files[name].write_bytes(name.encode("ascii"))
    free = tmp_path / f"DustMirror-{tag}-FREE-win64.zip"; free.write_bytes(b"free")
    gui = tmp_path / f"DustMirror-{tag}-GUI-win64.zip"; gui.write_bytes(b"gui")
    now = datetime.now(timezone.utc) + issued_offset
    payload = {
        "schema": "dustmirror.publication-authorization.v1",
        "version": version,
        "tag": tag,
        "product_commit": "a" * 40,
        "product_tree": "b" * 40,
        "release_commit": "e" * 40,
        "release_tree": "f" * 40,
        "cnb_build_id": build_id,
        "authorization_sequence": 1,
        "nonce": "c" * 64,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + ttl).isoformat().replace("+00:00", "Z"),
        "targets": TARGETS,
        "release_gate_manifest_sha256": "d" * 64,
        "controls": {name: _asset(path) for name, path in files.items()},
        "assets": {"FREE": _asset(free), "GUI": _asset(gui)},
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    authorization = tmp_path / "publication-authorization.json"; authorization.write_bytes(raw)
    private = Ed25519PrivateKey.generate()
    signature = tmp_path / "publication-authorization.sig"
    signature.write_text(base64.b64encode(private.sign(raw)).decode("ascii"), encoding="ascii")
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if replace_control:
        files["trust.sig"].write_bytes(b"replaced")
    command = [
        sys.executable, str(SCRIPT), "--authorization", str(authorization),
        "--signature", str(signature), "--publication-public-key-b64", base64.b64encode(public).decode("ascii"),
        "--expected-tag", tag, "--expected-product-build-id", build_id,
        "--expected-product-commit", expected_product_commit,
        "--expected-product-tree", expected_product_tree,
        "--expected-cnb-repo", TARGETS["cnb"], "--expected-release-commit", "e" * 40,
        "--expected-release-tree", "f" * 40, "--manifest", str(files["manifest.json"]),
        "--manifest-signature", str(files["manifest.sig"]), "--trust-metadata", str(files["trust.json"]),
        "--trust-signature", str(files["trust.sig"]), "--free-bundle", str(free), "--gui-bundle", str(gui),
    ]
    if resume_grant:
        grant_issued = datetime.now(timezone.utc)
        grant = {
            "schema": "dustmirror.publication-resume-grant.v1",
            "purpose": "resume-existing-partial-release",
            "tag": tag,
            "product_commit": "a" * 40,
            "product_tree": resume_grant_product_tree,
            "release_commit": "e" * 40,
            "release_tree": "f" * 40,
            "cnb_build_id": build_id,
            "targets": TARGETS,
            "publication_authorization_sha256": hashlib.sha256(raw).hexdigest(),
            "resume_sequence": 1,
            "nonce": "f" * 64,
            "issued_at": grant_issued.isoformat().replace("+00:00", "Z"),
            "expires_at": (grant_issued + resume_grant_ttl).isoformat().replace("+00:00", "Z"),
        }
        grant_raw = json.dumps(
            grant, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        grant_path = tmp_path / "publication-resume-grant.json"
        grant_signature = tmp_path / "publication-resume-grant.sig"
        grant_path.write_bytes(grant_raw)
        grant_signature.write_text(
            base64.b64encode(private.sign(grant_raw)).decode("ascii"), encoding="ascii"
        )
        command.extend(
            [
                "--resume-grant",
                str(grant_path),
                "--resume-grant-signature",
                str(grant_signature),
            ]
        )
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_accepts_signed_target_bound_handoff(tmp_path: Path):
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_rejects_replaced_trust_signature(tmp_path: Path):
    result = _run(tmp_path, replace_control=True)
    assert result.returncode == 2
    assert "control_digest_invalid" in result.stdout


def test_rejects_product_commit_or_tree_trigger_drift(tmp_path: Path):
    wrong_commit = _run(tmp_path / "commit", expected_product_commit="c" * 40)
    assert wrong_commit.returncode == 2
    assert "product_identity_invalid" in wrong_commit.stdout
    wrong_tree = _run(tmp_path / "tree", expected_product_tree="d" * 40)
    assert wrong_tree.returncode == 2
    assert "product_identity_invalid" in wrong_tree.stdout


def test_accepts_product_compatible_seven_day_authorization(tmp_path: Path):
    result = _run(tmp_path, ttl=timedelta(days=7))
    assert result.returncode == 0, result.stdout + result.stderr


def test_rejects_authorization_longer_than_product_seven_day_contract(tmp_path: Path):
    result = _run(tmp_path, ttl=timedelta(days=7, seconds=1))
    assert result.returncode == 2
    assert "authorization_expired" in result.stdout


def test_expired_authorization_accepts_only_a_fresh_signed_resume_grant(tmp_path: Path):
    expired = _run(
        tmp_path / "expired",
        ttl=timedelta(days=7),
        issued_offset=-timedelta(days=8),
    )
    assert expired.returncode == 2
    assert "authorization_expired" in expired.stdout
    resumed = _run(
        tmp_path / "resumed",
        ttl=timedelta(days=7),
        issued_offset=-timedelta(days=8),
        resume_grant=True,
    )
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert '"resume_only": true' in resumed.stdout


def test_resume_grant_is_identity_bound_and_limited_to_24_hours(tmp_path: Path):
    wrong_tree = _run(
        tmp_path / "tree",
        ttl=timedelta(days=7),
        issued_offset=-timedelta(days=8),
        resume_grant=True,
        resume_grant_product_tree="c" * 40,
    )
    assert wrong_tree.returncode == 2
    assert "resume_grant_identity_mismatch:product_tree" in wrong_tree.stdout
    long_lived = _run(
        tmp_path / "ttl",
        ttl=timedelta(days=7),
        issued_offset=-timedelta(days=8),
        resume_grant=True,
        resume_grant_ttl=timedelta(hours=24, seconds=1),
    )
    assert long_lived.returncode == 2
    assert "resume_grant_expired_or_not_fresh" in long_lived.stdout


def test_matches_product_five_minute_clock_skew_contract(tmp_path: Path):
    accepted = _run(tmp_path, issued_offset=timedelta(minutes=4))
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    rejected = _run(tmp_path, issued_offset=timedelta(minutes=6))
    assert rejected.returncode == 2
    assert "authorization_expired" in rejected.stdout
