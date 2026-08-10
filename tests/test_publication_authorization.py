from __future__ import annotations

import base64
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


def _run(tmp_path: Path, *, replace_control: bool = False) -> subprocess.CompletedProcess[str]:
    version, tag, build_id = "1.2.22", "v1.2.22", "build-22"
    files = {}
    for name in ("manifest.json", "manifest.sig", "trust.json", "trust.sig"):
        files[name] = tmp_path / name
        files[name].write_bytes(name.encode("ascii"))
    free = tmp_path / f"DustMirror-{tag}-FREE-win64.zip"; free.write_bytes(b"free")
    gui = tmp_path / f"DustMirror-{tag}-GUI-win64.zip"; gui.write_bytes(b"gui")
    now = datetime.now(timezone.utc)
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
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
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
    return subprocess.run([
        sys.executable, str(SCRIPT), "--authorization", str(authorization),
        "--signature", str(signature), "--publication-public-key-b64", base64.b64encode(public).decode("ascii"),
        "--expected-tag", tag, "--expected-product-build-id", build_id,
        "--expected-cnb-repo", TARGETS["cnb"], "--expected-release-commit", "e" * 40,
        "--expected-release-tree", "f" * 40, "--manifest", str(files["manifest.json"]),
        "--manifest-signature", str(files["manifest.sig"]), "--trust-metadata", str(files["trust.json"]),
        "--trust-signature", str(files["trust.sig"]), "--free-bundle", str(free), "--gui-bundle", str(gui),
    ], capture_output=True, text=True, check=False)


def test_accepts_signed_target_bound_handoff(tmp_path: Path):
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_rejects_replaced_trust_signature(tmp_path: Path):
    result = _run(tmp_path, replace_control=True)
    assert result.returncode == 2
    assert "control_digest_invalid" in result.stdout
