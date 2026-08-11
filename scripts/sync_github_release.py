"""Publish the already-authorized CNB release to the GitHub mirror.

This is deliberately a thin, fail-closed mirror step.  CNB remains the
primary release host and the signed publication authorization is verified by
the preceding CNB stages.  The only extra credential needed here is a
repository-scoped GitHub token; there is no coordinator service, callback URL,
or second signing key involved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


GITHUB_API = "https://api.github.com"
GITHUB_REPOSITORY = "ra1nzzz/Dust-Mirror"
ASSET_NAMES = (
    "DustMirror-{tag}-FREE-win64.zip",
    "DustMirror-{tag}-GUI-win64.zip",
    "manifest.json",
    "manifest.sig",
    "trust.json",
    "trust.sig",
    "publication-authorization.json",
    "publication-authorization.sig",
)


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def local_asset(path: Path) -> dict:
    raw = path.read_bytes()
    return {"name": path.name, "size_bytes": len(raw), "sha256": sha256_bytes(raw)}


def _request(
    url: str,
    token: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str = "application/json",
    accept: str = "application/vnd.github+json",
):
    headers = {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "User-Agent": "DustMirror-CNB-release-mirror/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if body is not None:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def _json(url: str, token: str, *, method: str = "GET", value: dict | None = None) -> dict:
    body = canonical(value) if value is not None else None
    raw = _request(url, token, method=method, body=body)
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("github_response_invalid")
    return parsed


def _get_release(tag: str, token: str) -> dict | None:
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    try:
        return _json(url, token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _asset_url(release: dict, name: str) -> str:
    upload_url = release.get("upload_url")
    if not isinstance(upload_url, str) or "{" not in upload_url:
        raise ValueError("github_upload_url_invalid")
    return upload_url.split("{", 1)[0] + "?name=" + urllib.parse.quote(name, safe="")


def _download_asset(asset: dict, token: str) -> bytes:
    url = asset.get("url")
    if not isinstance(url, str) or not url.startswith(f"{GITHUB_API}/"):
        raise ValueError("github_asset_url_invalid")
    return _request(url, token, method="GET", accept="application/octet-stream")


def _validate_remote_assets(release: dict, expected: dict[str, dict], token: str) -> dict[str, dict]:
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(item, dict) for item in assets):
        raise ValueError("github_release_assets_invalid")
    by_name = {item.get("name"): item for item in assets}
    if set(by_name) != set(expected):
        raise ValueError("github_release_asset_set_mismatch")
    receipt_assets: dict[str, dict] = {}
    for name, wanted in expected.items():
        remote = by_name[name]
        content = _download_asset(remote, token)
        observed = {"name": name, "size_bytes": len(content), "sha256": sha256_bytes(content)}
        if observed["size_bytes"] != wanted["size_bytes"] or observed["sha256"] != wanted["sha256"]:
            raise ValueError(f"github_release_asset_digest_mismatch:{name}")
        receipt_assets[name] = {**wanted, "remote_id": remote.get("id"), "redownloaded_sha256": observed["sha256"]}
    return receipt_assets


def _create_draft(tag: str, token: str) -> dict:
    return _json(
        f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases",
        token,
        method="POST",
        value={
            "tag_name": tag,
            "target_commitish": "main",
            "name": f"DustMirror {tag}",
            "body": "CNB primary release mirror; assets are bound to the signed Product authorization.",
            "draft": True,
            "prerelease": True,
        },
    )


def _publish(release: dict, token: str) -> dict:
    release_id = release.get("id")
    if not isinstance(release_id, int):
        raise ValueError("github_release_id_invalid")
    return _json(
        f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases/{release_id}",
        token,
        method="PATCH",
        value={"draft": False, "prerelease": False, "make_latest": "true"},
    )


def sync(tag: str, asset_dir: Path, token: str) -> dict:
    expected_paths = [asset_dir / template.format(tag=tag) for template in ASSET_NAMES]
    if any(not path.is_file() for path in expected_paths):
        missing = [path.name for path in expected_paths if not path.is_file()]
        raise ValueError("github_mirror_asset_missing:" + ",".join(missing))
    expected = {path.name: local_asset(path) for path in expected_paths}

    release = _get_release(tag, token)
    if release is None:
        release = _create_draft(tag, token)
    if release.get("tag_name") != tag:
        raise ValueError("github_release_tag_mismatch")
    already_published = release.get("draft") is False and release.get("prerelease") is False
    if already_published:
        remote_assets = _validate_remote_assets(release, expected, token)
    else:
        # Never replace an existing same-name asset with different bytes.
        existing = {item.get("name"): item for item in release.get("assets", []) if isinstance(item, dict)}
        for name, wanted in expected.items():
            if name in existing:
                remote_assets = _validate_remote_assets(release, expected, token)
                break
        else:
            remote_assets = {}
        if remote_assets:
            pass
        else:
            if existing and set(existing) != set(expected):
                raise ValueError("github_release_existing_asset_set_mismatch")
            for path in expected_paths:
                _request(
                    _asset_url(release, path.name),
                    token,
                    method="POST",
                    body=path.read_bytes(),
                    content_type="application/octet-stream",
                )
            release = _get_release(tag, token)
            if release is None:
                raise ValueError("github_release_disappeared")
            remote_assets = _validate_remote_assets(release, expected, token)
        if not already_published:
            release = _publish(release, token)
            if release.get("draft") is not False or release.get("prerelease") is not False:
                raise ValueError("github_release_publish_failed")
            remote_assets = _validate_remote_assets(release, expected, token)

    return {
        "schema": "dustmirror.github-mirror-receipt.v1",
        "repository": GITHUB_REPOSITORY,
        "tag": tag,
        "release_id": release.get("id"),
        "state": "published",
        "assets": remote_assets,
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default=os.environ.get("RELEASE_VERSION", ""))
    parser.add_argument("--asset-dir", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("github-mirror-receipt.json"))
    args = parser.parse_args()
    try:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token or not isinstance(args.tag, str) or not args.tag.startswith("v"):
            raise ValueError("github_mirror_environment_missing")
        receipt = sync(args.tag, args.asset_dir, token)
        args.output.write_bytes(canonical(receipt))
        print(json.dumps({"verified": True, "repository": GITHUB_REPOSITORY, "tag": args.tag}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
