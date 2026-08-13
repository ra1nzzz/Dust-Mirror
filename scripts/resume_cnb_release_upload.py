"""Resume only missing CNB release assets without overwrite or deletion."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import mimetypes
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_cnb_release_inventory import (
    CHUNK_SIZE,
    HEARTBEAT_BYTES,
    _asset_names,
    _expected_records,
    _release_tag,
    _release_target,
    _request,
    verify_release_inventory,
    verify_release_inventory_state,
)

MAX_UPLOAD_ATTEMPTS = 3
MAX_CONFIRM_POLLS = 10


def _api_json(url: str, token: str, *, value: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    if not isinstance(result, dict):
        raise ValueError("cnb_upload_response_invalid")
    return result


def _local_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _put_file_once(url: str, path: Path) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("cnb_upload_url_untrusted")
    target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=120)
    content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    try:
        connection.putrequest("PUT", target)
        connection.putheader("Content-Type", content_type)
        connection.putheader("Content-Length", str(path.stat().st_size))
        connection.endheaders()
        sent = 0
        next_heartbeat = HEARTBEAT_BYTES
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                connection.send(chunk)
                sent += len(chunk)
                if sent >= next_heartbeat:
                    print(
                        json.dumps(
                            {"heartbeat": "upload", "asset": path.name, "bytes": sent},
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    next_heartbeat += HEARTBEAT_BYTES
        response = connection.getresponse()
        response.read()
        if response.status < 200 or response.status >= 300:
            raise urllib.error.HTTPError(url, response.status, response.reason, response.headers, None)
    finally:
        connection.close()


def _confirm(url: str, token: str, *, endpoint: str, repo: str, release_id: str) -> None:
    absolute = urllib.parse.urljoin(endpoint + "/", url)
    parsed = urllib.parse.urlsplit(absolute)
    prefix = f"/{repo}/-/releases/{release_id}/asset-upload-confirmation/"
    if parsed.scheme != "https" or parsed.netloc != "api.cnb.cool" or not parsed.path.startswith(prefix):
        raise ValueError("cnb_upload_confirmation_url_untrusted")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != "ttl"] + [("ttl", "0")]
    absolute = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), "")
    )
    request = urllib.request.Request(
        absolute,
        data=b"",
        method="POST",
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        response.read()


def _current_release(endpoint: str, token: str, repo: str, tag: str) -> tuple[dict, dict]:
    release = _request(f"{endpoint}/{repo}/-/releases/tags/{tag}", token)
    release_id = release.get("id")
    if not isinstance(release_id, (str, int)) or not str(release_id):
        raise ValueError("cnb_release_id_invalid")
    detail = _request(f"{endpoint}/{repo}/-/releases/{release_id}", token)
    return release, detail


def _names(detail: dict, expected: set[str]) -> set[str]:
    names = _asset_names(detail)
    actual = set(names)
    if len(names) != len(actual) or not actual.issubset(expected):
        raise ValueError(f"release_inventory_mismatch:{sorted(names)}")
    return actual


def _wait_for_asset(
    endpoint: str, token: str, repo: str, tag: str, name: str, expected: set[str]
) -> bool:
    for poll in range(1, MAX_CONFIRM_POLLS + 1):
        _, detail = _current_release(endpoint, token, repo, tag)
        if name in _names(detail, expected):
            return True
        print(
            json.dumps({"heartbeat": "upload_confirmation", "asset": name, "poll": poll}, sort_keys=True),
            flush=True,
        )
        time.sleep(min(poll, 3))
    return False


def resume_missing(
    *,
    endpoint: str,
    token: str,
    repo: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    expected_missing: set[str],
) -> list[str]:
    records = _expected_records(authorization_path)
    expected = set(records)
    if not expected_missing or not expected_missing.issubset(expected):
        raise ValueError("expected_missing_assets_invalid")
    release, detail = _current_release(endpoint, token, repo, tag)
    if _release_tag(release) != tag or _release_tag(detail) != tag:
        raise ValueError("release_tag_mismatch")
    release_commit = json.loads(authorization_path.read_text(encoding="utf-8"))["release_commit"]
    if _release_target(release) != release_commit or _release_target(detail) != release_commit:
        raise ValueError("cnb_release_tag_target_mismatch")
    description = str(release.get("body") or release.get("description") or "").rstrip()
    if not description.endswith(f"Product build: {product_build_id}"):
        raise ValueError("release_not_owned_by_product_build")
    actual = _names(detail, expected)
    current_missing = expected - actual
    if not current_missing.issubset(expected_missing):
        raise ValueError("resume_missing_set_changed")
    if current_missing != expected_missing:
        # An earlier confirmation may become visible after preflight.  Accept
        # that idempotent progress only after revalidating every now-present
        # byte; disappearance of any formerly verified asset is never allowed.
        observed = verify_release_inventory_state(
            endpoint=endpoint,
            token=token,
            repo=repo,
            tag=tag,
            product_build_id=product_build_id,
            authorization_path=authorization_path,
            allow_partial=True,
        )
        if set(observed["missing"]) != current_missing:
            raise ValueError("resume_missing_set_changed")

    for name in sorted(current_missing):
        path = authorization_path.with_name(name)
        record = records[name]
        if not path.is_file() or _local_digest(path) != (record["size_bytes"], record["sha256"]):
            raise ValueError(f"local_authorized_asset_mismatch:{name}")
        for attempt in range(1, MAX_UPLOAD_ATTEMPTS + 1):
            _, live_detail = _current_release(endpoint, token, repo, tag)
            live_names = _names(live_detail, expected)
            if name in live_names:
                break
            try:
                response = _api_json(
                    f"{endpoint}/{repo}/-/releases/{release['id']}/asset-upload-url",
                    token,
                    value={
                        "asset_name": name,
                        "overwrite": False,
                        "size": record["size_bytes"],
                        "ttl": 0,
                    },
                )
                upload_url = response.get("upload_url")
                verify_url = response.get("verify_url")
                if not isinstance(upload_url, str) or not isinstance(verify_url, str):
                    raise ValueError("cnb_upload_response_invalid")
                _put_file_once(upload_url, path)
                _confirm(
                    verify_url,
                    token,
                    endpoint=endpoint,
                    repo=repo,
                    release_id=str(release["id"]),
                )
                if not _wait_for_asset(endpoint, token, repo, tag, name, expected):
                    raise TimeoutError(f"cnb_upload_confirmation_timeout:{name}")
                break
            except Exception:
                _, observed = _current_release(endpoint, token, repo, tag)
                if name in _names(observed, expected):
                    break
                if attempt >= MAX_UPLOAD_ATTEMPTS:
                    raise
                print(
                    json.dumps(
                        {"heartbeat": "upload_retry", "asset": name, "attempt": attempt},
                        sort_keys=True,
                    ),
                    flush=True,
                )
                time.sleep(min(2 ** (attempt - 1), 4))
        else:  # pragma: no cover - the loop either breaks or raises
            raise AssertionError("unreachable")

    return verify_release_inventory(
        endpoint=endpoint,
        token=token,
        repo=repo,
        tag=tag,
        product_build_id=product_build_id,
        authorization_path=authorization_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--product-build-id", required=True)
    parser.add_argument("--expected-missing", required=True)
    args = parser.parse_args()
    try:
        endpoint = os.environ.get("CNB_API_ENDPOINT", "").rstrip("/")
        token = os.environ.get("CNB_TOKEN", "")
        missing = {name for name in args.expected_missing.split(",") if name}
        if endpoint != "https://api.cnb.cool" or not token:
            raise ValueError("trusted_cnb_api_environment_missing")
        assets = resume_missing(
            endpoint=endpoint,
            token=token,
            repo=args.repo,
            tag=args.tag,
            product_build_id=args.product_build_id,
            authorization_path=args.authorization,
            expected_missing=missing,
        )
        print(json.dumps({"verified": True, "tag": args.tag, "assets": assets}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
