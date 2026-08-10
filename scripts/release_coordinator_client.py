"""Submit and verify a durable dual-source publication saga."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TARGETS = {"cnb": "yitaocn/dust-mirror", "github": "ra1nzzz/Dust-Mirror"}


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _request(url: str, token: str, *, method: str = "GET", data: bytes | None = None) -> dict:
    req = urllib.request.Request(url, method=method, data=data, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("coordinator_response_invalid")
    return value


def verify_receipt(envelope: dict, public_key_b64: str, authorization_sha256: str) -> dict:
    if set(envelope) != {"payload", "signature_b64"} or not isinstance(envelope["payload"], dict):
        raise ValueError("coordinator_receipt_envelope_invalid")
    payload = envelope["payload"]
    required = {"schema", "saga_id", "authorization_sha256", "state", "targets", "anti_replay", "checked_at"}
    if set(payload) != required or payload["schema"] != "dustmirror.publication-saga-receipt.v1":
        raise ValueError("coordinator_receipt_contract_invalid")
    if payload["authorization_sha256"] != authorization_sha256 or payload["state"] != "committed" or payload["targets"] != TARGETS:
        raise ValueError("coordinator_not_committed")
    anti = payload["anti_replay"]
    if not isinstance(anti, dict) or set(anti) != {"sequence", "nonce", "build_id", "committed"} or anti["committed"] is not True:
        raise ValueError("coordinator_anti_replay_not_committed")
    public = base64.b64decode(public_key_b64, validate=True)
    signature = base64.b64decode(envelope["signature_b64"], validate=True)
    if len(public) != 32 or len(signature) != 64:
        raise ValueError("coordinator_signature_material_invalid")
    Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(payload))
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--authorization-signature", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    try:
        origin = os.environ.get("DUSTMIRROR_RELEASE_COORDINATOR_ORIGIN", "").rstrip("/")
        token = os.environ.get("DUSTMIRROR_RELEASE_COORDINATOR_TOKEN", "")
        public_key = os.environ.get("DUSTMIRROR_RELEASE_COORDINATOR_PUBLIC_KEY_B64", "")
        parsed = urllib.parse.urlparse(origin)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or not token:
            raise ValueError("trusted_coordinator_environment_missing")
        auth_raw = args.authorization.read_bytes()
        auth_sha = hashlib.sha256(auth_raw).hexdigest()
        request_body = canonical({
            "schema": "dustmirror.publication-saga-request.v1",
            "authorization_b64": base64.b64encode(auth_raw).decode(),
            "authorization_signature_b64": args.authorization_signature.read_text(encoding="ascii").strip(),
            "authorization_sha256": auth_sha,
            "targets": TARGETS,
            "policy": {"persist_after_client_exit": True, "rollback_all_on_partial_failure": True, "anti_replay_cas": True},
        })
        accepted = _request(f"{origin}/v1/release-sagas", token, method="POST", data=request_body)
        saga_id = accepted.get("saga_id")
        if not isinstance(saga_id, str) or not saga_id:
            raise ValueError("coordinator_saga_not_accepted")
        deadline = time.monotonic() + min(max(args.timeout_seconds, 60), 3600)
        while time.monotonic() < deadline:
            envelope = _request(f"{origin}/v1/release-sagas/{urllib.parse.quote(saga_id, safe='')}", token)
            state = envelope.get("payload", {}).get("state") if isinstance(envelope.get("payload"), dict) else None
            if state == "committed":
                verify_receipt(envelope, public_key, auth_sha)
                args.output.write_bytes(canonical(envelope))
                return 0
            if state in {"rolled_back", "failed"}:
                raise ValueError(f"coordinator_terminal_failure:{state}")
            time.sleep(5)
        raise ValueError("coordinator_timeout_saga_remains_persistent")
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
