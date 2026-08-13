"""Fresh signed authorization for resuming, never creating, a partial Release.

The original publication authorization remains the byte and identity ledger.
This grant only extends the time window for an already-existing partial release;
the pipeline must consume ``resume_only=True`` and reject a preflight ``create``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "dustmirror.publication-resume-grant.v1"
PURPOSE = "resume-existing-partial-release"
MAX_GRANT_TTL = timedelta(hours=24)
TARGETS = {"cnb": "yitaocn/dust-mirror", "github": "ra1nzzz/Dust-Mirror"}
REQUIRED_FIELDS = {
    "schema",
    "purpose",
    "tag",
    "product_commit",
    "product_tree",
    "release_commit",
    "release_tree",
    "cnb_build_id",
    "targets",
    "publication_authorization_sha256",
    "resume_sequence",
    "nonce",
    "issued_at",
    "expires_at",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def verify_resume_grant(
    *,
    grant_path: Path,
    signature_path: Path,
    authorization_raw: bytes,
    authorization: dict,
    public_key: bytes,
    now: datetime | None = None,
) -> dict:
    raw = grant_path.read_bytes()
    grant = json.loads(raw.decode("utf-8"))
    if not isinstance(grant, dict) or raw != canonical(grant):
        raise ValueError("resume_grant_not_canonical")
    if set(grant) != REQUIRED_FIELDS or grant.get("schema") != SCHEMA:
        raise ValueError("resume_grant_schema_invalid")
    if grant.get("purpose") != PURPOSE or grant.get("targets") != TARGETS:
        raise ValueError("resume_grant_scope_invalid")
    for field in (
        "tag",
        "product_commit",
        "product_tree",
        "release_commit",
        "release_tree",
        "cnb_build_id",
        "targets",
    ):
        if grant.get(field) != authorization.get(field):
            raise ValueError(f"resume_grant_identity_mismatch:{field}")
    for field in ("product_commit", "product_tree", "release_commit", "release_tree"):
        if not HEX40.fullmatch(str(grant.get(field) or "")):
            raise ValueError("resume_grant_identity_invalid")
    if grant.get("publication_authorization_sha256") != hashlib.sha256(
        authorization_raw
    ).hexdigest():
        raise ValueError("resume_grant_authorization_digest_mismatch")
    if not isinstance(grant.get("resume_sequence"), int) or grant["resume_sequence"] < 1:
        raise ValueError("resume_grant_sequence_invalid")
    if not HEX64.fullmatch(str(grant.get("nonce") or "")):
        raise ValueError("resume_grant_nonce_invalid")

    issued = datetime.fromisoformat(str(grant["issued_at"]).replace("Z", "+00:00"))
    expires = datetime.fromisoformat(str(grant["expires_at"]).replace("Z", "+00:00"))
    original_expires = datetime.fromisoformat(
        str(authorization["expires_at"]).replace("Z", "+00:00")
    )
    current = now or datetime.now(timezone.utc)
    if (
        issued > current + timedelta(minutes=5)
        or expires <= current
        or expires <= issued
        or expires > issued + MAX_GRANT_TTL
        or issued < original_expires - timedelta(minutes=5)
    ):
        raise ValueError("resume_grant_expired_or_not_fresh")

    signature = base64.b64decode(signature_path.read_text(encoding="ascii").strip(), validate=True)
    if len(public_key) != 32 or len(signature) != 64:
        raise ValueError("resume_grant_signature_material_invalid")
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, raw)
    return {
        "schema": SCHEMA,
        "resume_only": True,
        "resume_sequence": grant["resume_sequence"],
        "expires_at": grant["expires_at"],
    }
