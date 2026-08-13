"""Verify the complete CNB prerelease attachment inventory before promotion."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path


def _request(url: str, token: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("cnb_release_response_invalid")
    return value


CHUNK_SIZE = 1024 * 1024
HEARTBEAT_BYTES = 64 * 1024 * 1024
MAX_DOWNLOAD_ATTEMPTS = 3


def _transient(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or 500 <= exc.code < 600
    return isinstance(exc, (TimeoutError, socket.timeout, ConnectionError, urllib.error.URLError))


def _stream_digest_once(url: str, token: str, *, label: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    digest = hashlib.sha256()
    size = 0
    next_heartbeat = HEARTBEAT_BYTES
    with urllib.request.urlopen(req, timeout=120) as response:
        while True:
            chunk = response.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if size >= next_heartbeat:
                print(json.dumps({"heartbeat": "download", "asset": label, "bytes": size}, sort_keys=True), flush=True)
                next_heartbeat += HEARTBEAT_BYTES
    return size, digest.hexdigest()


def _stream_digest(url: str, token: str, *, label: str) -> tuple[int, str]:
    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        try:
            return _stream_digest_once(url, token, label=label)
        except Exception as exc:
            if attempt >= MAX_DOWNLOAD_ATTEMPTS or not _transient(exc):
                raise
            print(
                json.dumps(
                    {"heartbeat": "download_retry", "asset": label, "attempt": attempt},
                    sort_keys=True,
                ),
                flush=True,
            )
            time.sleep(min(2 ** (attempt - 1), 4))
    raise AssertionError("unreachable")


def _asset_names(value: dict) -> list[str]:
    assets = value.get("assets")
    if not isinstance(assets, list):
        raise ValueError("cnb_release_assets_missing")
    names = []
    for item in assets:
        if not isinstance(item, dict):
            raise ValueError("cnb_release_asset_invalid")
        name = item.get("name") or item.get("filename") or item.get("asset_name") or item.get("file_name")
        if not isinstance(name, str) or not name:
            raise ValueError("cnb_release_asset_name_invalid")
        names.append(name)
    return names


def _release_tag(value: dict) -> str:
    for key in ("tag_name", "tag", "name"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    raise ValueError("cnb_release_tag_missing")


def _expected_records(authorization_path: Path) -> dict[str, dict]:
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    controls = authorization.get("controls")
    assets = authorization.get("assets")
    if not isinstance(controls, dict) or not isinstance(assets, dict):
        raise ValueError("publication_authorization_inventory_invalid")
    records: dict[str, dict] = {}
    for item in (*controls.values(), *assets.values()):
        if not isinstance(item, dict):
            raise ValueError("publication_authorization_inventory_invalid")
        name = item.get("name")
        if not isinstance(name, str) or not name or name in records:
            raise ValueError("publication_authorization_inventory_invalid")
        records[name] = item
    for name in ("publication-authorization.json", "publication-authorization.sig"):
        if name in records:
            raise ValueError("publication_authorization_inventory_invalid")
        path = authorization_path.with_name(name)
        raw = path.read_bytes()
        records[name] = {
            "name": name,
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    return records


def _authorized_release_identity(authorization_path: Path) -> tuple[str, str]:
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    commit = authorization.get("release_commit")
    tree = authorization.get("release_tree")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(char not in "0123456789abcdef" for char in commit)
        or not isinstance(tree, str)
        or len(tree) != 40
        or any(char not in "0123456789abcdef" for char in tree)
    ):
        raise ValueError("publication_authorization_release_identity_invalid")
    return commit, tree


def _release_target(value: dict) -> str:
    for key in ("tag_commitish", "target_commitish", "target"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    raise ValueError("cnb_release_target_missing")


def verify_release_inventory_state(
    *,
    endpoint: str,
    token: str,
    repo: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    allow_partial: bool,
) -> dict:
    """Verify the live release is exactly the signed Product handoff.

    This function is also used by the preflight resume decision.  Reusing the
    same verifier prevents a partially uploaded or byte-drifted prerelease
    from being treated as a resumable release.
    """

    expected_records = _expected_records(authorization_path)
    release_commit, _release_tree = _authorized_release_identity(authorization_path)
    expected = set(expected_records)
    release = _request(f"{endpoint}/{repo}/-/releases/tags/{tag}", token)
    if _release_tag(release) != tag:
        raise ValueError("release_tag_mismatch")
    if _release_target(release) != release_commit:
        raise ValueError("cnb_release_tag_target_mismatch")
    release_id = release.get("id")
    description = str(release.get("description") or release.get("body") or "").rstrip()
    if not release_id or not description.endswith(f"Product build: {product_build_id}"):
        raise ValueError("release_not_owned_by_product_build")
    detail = _request(f"{endpoint}/{repo}/-/releases/{release_id}", token)
    if detail.get("id") != release_id or _release_tag(detail) != tag:
        raise ValueError("cnb_release_detail_identity_mismatch")
    if _release_target(detail) != release_commit:
        raise ValueError("cnb_release_tag_target_mismatch")
    names = _asset_names(detail)
    actual = set(names)
    if len(names) != len(actual) or not actual.issubset(expected):
        raise ValueError(f"release_inventory_mismatch:{sorted(names)}")
    if not allow_partial and actual != expected:
        raise ValueError(f"release_inventory_mismatch:{sorted(names)}")
    for name in sorted(actual):
        record = expected_records[name]
        url = f"{endpoint}/{repo}/-/releases/download/{tag}/{name}"
        first_size, first_digest = _stream_digest(url, token, label=f"{name}:copy1")
        second_size, second_digest = _stream_digest(url, token, label=f"{name}:copy2")
        if (
            first_size != second_size
            or first_digest != second_digest
            or first_size != record["size_bytes"]
            or first_digest != record["sha256"]
        ):
            raise ValueError(f"release_asset_bytes_mismatch:{name}")
    return {"present": sorted(actual), "missing": sorted(expected - actual)}


def verify_release_inventory(
    *,
    endpoint: str,
    token: str,
    repo: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
) -> list[str]:
    state = verify_release_inventory_state(
        endpoint=endpoint,
        token=token,
        repo=repo,
        tag=tag,
        product_build_id=product_build_id,
        authorization_path=authorization_path,
        allow_partial=False,
    )
    return state["present"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--product-build-id", required=True)
    args = parser.parse_args()
    try:
        endpoint = os.environ.get("CNB_API_ENDPOINT", "").rstrip("/")
        token = os.environ.get("CNB_TOKEN", "")
        if endpoint != "https://api.cnb.cool" or not token:
            raise ValueError("trusted_cnb_api_environment_missing")
        expected = verify_release_inventory(
            endpoint=endpoint,
            token=token,
            repo=args.repo,
            tag=args.tag,
            product_build_id=args.product_build_id,
            authorization_path=args.authorization,
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"verified": True, "tag": args.tag, "assets": sorted(expected)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
