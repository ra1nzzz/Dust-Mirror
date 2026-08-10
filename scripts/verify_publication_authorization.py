from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TARGETS = {"cnb": "yitaocn/dust-mirror", "github": "ra1nzzz/Dust-Mirror"}


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def asset(path: Path) -> dict:
    raw = path.read_bytes()
    return {"name": path.name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--publication-public-key-b64", required=True)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--expected-product-build-id", required=True)
    parser.add_argument("--expected-cnb-repo", required=True)
    parser.add_argument("--expected-release-commit", required=True)
    parser.add_argument("--expected-release-tree", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-signature", type=Path, required=True)
    parser.add_argument("--trust-metadata", type=Path, required=True)
    parser.add_argument("--trust-signature", type=Path, required=True)
    parser.add_argument("--free-bundle", type=Path, required=True)
    parser.add_argument("--gui-bundle", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = args.authorization.read_bytes()
        value = json.loads(raw.decode("utf-8"))
        if raw != canonical(value):
            raise ValueError("authorization_not_canonical")
        if value.get("schema") != "dustmirror.publication-authorization.v1":
            raise ValueError("authorization_schema_invalid")
        if value.get("tag") != args.expected_tag or value.get("version") != args.expected_tag.lstrip("v"):
            raise ValueError("authorization_version_invalid")
        if value.get("cnb_build_id") != args.expected_product_build_id:
            raise ValueError("authorization_build_invalid")
        if args.expected_cnb_repo != TARGETS["cnb"] or value.get("targets") != TARGETS:
            raise ValueError("authorization_target_invalid")
        if not HEX40.fullmatch(str(value.get("product_commit") or "")) or not HEX40.fullmatch(str(value.get("product_tree") or "")):
            raise ValueError("product_identity_invalid")
        if value.get("release_commit") != args.expected_release_commit or value.get("release_tree") != args.expected_release_tree or not HEX40.fullmatch(args.expected_release_commit) or not HEX40.fullmatch(args.expected_release_tree):
            raise ValueError("release_ledger_identity_invalid")
        if not isinstance(value.get("authorization_sequence"), int) or value["authorization_sequence"] < 1:
            raise ValueError("authorization_sequence_invalid")
        if not HEX64.fullmatch(str(value.get("nonce") or "")) or not HEX64.fullmatch(str(value.get("release_gate_manifest_sha256") or "")):
            raise ValueError("authorization_nonce_or_gate_invalid")
        expected_controls = {
            "manifest.json": asset(args.manifest),
            "manifest.sig": asset(args.manifest_signature),
            "trust.json": asset(args.trust_metadata),
            "trust.sig": asset(args.trust_signature),
        }
        if value.get("controls") != expected_controls:
            raise ValueError("control_digest_invalid")
        expected_assets = {"FREE": asset(args.free_bundle), "GUI": asset(args.gui_bundle)}
        if value.get("assets") != expected_assets:
            raise ValueError("asset_digest_invalid")
        issued = datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if issued > now or expires <= now or expires > issued + timedelta(hours=2):
            raise ValueError("authorization_expired")
        public = base64.b64decode(args.publication_public_key_b64, validate=True)
        signature = base64.b64decode(args.signature.read_text(encoding="ascii").strip(), validate=True)
        if len(public) != 32 or len(signature) != 64:
            raise ValueError("signature_material_invalid")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, raw)
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"verified": True, "tag": args.expected_tag, "target": args.expected_cnb_repo}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
