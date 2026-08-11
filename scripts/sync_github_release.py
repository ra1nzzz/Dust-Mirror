"""Stage, promote, verify, or roll back the GitHub release mirror.

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


def _patch_release(release: dict, token: str, value: dict) -> dict:
    release_id = release.get("id")
    if not isinstance(release_id, int):
        raise ValueError("github_release_id_invalid")
    return _json(
        f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases/{release_id}",
        token,
        method="PATCH",
        value=value,
    )


def _publish(release: dict, token: str) -> dict:
    return _patch_release(
        release,
        token,
        {"draft": False, "prerelease": False, "make_latest": "true"},
    )


def _unpublish(release: dict, token: str) -> dict:
    return _patch_release(
        release,
        token,
        {"draft": True, "prerelease": True, "make_latest": "false"},
    )


def _expected_assets(tag: str, asset_dir: Path) -> tuple[list[Path], dict[str, dict]]:
    expected_paths = [asset_dir / template.format(tag=tag) for template in ASSET_NAMES]
    if any(not path.is_file() for path in expected_paths):
        missing = [path.name for path in expected_paths if not path.is_file()]
        raise ValueError("github_mirror_asset_missing:" + ",".join(missing))
    return expected_paths, {path.name: local_asset(path) for path in expected_paths}


def _upload_missing_assets(
    release: dict,
    expected_paths: list[Path],
    expected: dict[str, dict],
    token: str,
) -> dict[str, dict]:
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(item, dict) for item in assets):
        raise ValueError("github_release_assets_invalid")
    existing = {item.get("name"): item for item in assets}
    if any(not isinstance(name, str) for name in existing):
        raise ValueError("github_release_asset_name_invalid")
    if not set(existing).issubset(expected):
        raise ValueError("github_release_existing_asset_set_mismatch")
    for name, remote in existing.items():
        content = _download_asset(remote, token)
        wanted = expected[name]
        if len(content) != wanted["size_bytes"] or sha256_bytes(content) != wanted["sha256"]:
            raise ValueError(f"github_release_existing_asset_digest_mismatch:{name}")
    for path in expected_paths:
        if path.name in existing:
            continue
        _request(
            _asset_url(release, path.name),
            token,
            method="POST",
            body=path.read_bytes(),
            content_type="application/octet-stream",
        )
    refreshed = _get_release(str(release.get("tag_name") or ""), token)
    if refreshed is None:
        raise ValueError("github_release_disappeared")
    return _validate_remote_assets(refreshed, expected, token)


def _receipt(tag: str, release: dict, state: str, assets: dict[str, dict]) -> dict:
    return {
        "schema": "dustmirror.github-mirror-receipt.v1",
        "repository": GITHUB_REPOSITORY,
        "tag": tag,
        "release_id": release.get("id"),
        "state": state,
        "assets": assets,
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def stage(tag: str, asset_dir: Path, token: str) -> dict:
    """Upload and re-download exact bytes while keeping GitHub non-public."""
    expected_paths, expected = _expected_assets(tag, asset_dir)

    release = _get_release(tag, token)
    if release is None:
        release = _create_draft(tag, token)
    if release.get("tag_name") != tag:
        raise ValueError("github_release_tag_mismatch")
    if release.get("draft") is not True or release.get("prerelease") is not True:
        raise ValueError("github_stage_requires_draft_prerelease")
    remote_assets = _upload_missing_assets(release, expected_paths, expected, token)
    return _receipt(tag, release, "staged", remote_assets)


def promote(tag: str, asset_dir: Path, token: str) -> dict:
    """Publish a previously byte-verified draft; never upload in this step."""
    _, expected = _expected_assets(tag, asset_dir)
    release = _get_release(tag, token)
    if release is None or release.get("tag_name") != tag:
        raise ValueError("github_staged_release_missing")
    remote_assets = _validate_remote_assets(release, expected, token)
    if release.get("draft") is True and release.get("prerelease") is True:
        release = _publish(release, token)
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise ValueError("github_release_publish_failed")
    remote_assets = _validate_remote_assets(release, expected, token)
    return _receipt(tag, release, "published", remote_assets)


def verify_published(tag: str, asset_dir: Path, token: str) -> dict:
    _, expected = _expected_assets(tag, asset_dir)
    release = _get_release(tag, token)
    if release is None or release.get("tag_name") != tag:
        raise ValueError("github_published_release_missing")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise ValueError("github_release_not_published")
    return _receipt(tag, release, "published", _validate_remote_assets(release, expected, token))


def rollback(tag: str, token: str) -> dict:
    """Make a partially promoted mirror non-public without deleting its tag."""
    release = _get_release(tag, token)
    if release is None:
        return _receipt(tag, {}, "absent", {})
    if release.get("tag_name") != tag:
        raise ValueError("github_release_tag_mismatch")
    if release.get("draft") is not True or release.get("prerelease") is not True:
        release = _unpublish(release, token)
    if release.get("draft") is not True or release.get("prerelease") is not True:
        raise ValueError("github_release_rollback_failed")
    return _receipt(tag, release, "rolled_back", {})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("stage", "promote", "verify", "rollback"), required=True)
    parser.add_argument("--tag", default=os.environ.get("RELEASE_VERSION", ""))
    parser.add_argument("--asset-dir", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("github-mirror-receipt.json"))
    args = parser.parse_args()
    try:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token or not isinstance(args.tag, str) or not args.tag.startswith("v"):
            raise ValueError("github_mirror_environment_missing")
        if args.mode == "stage":
            receipt = stage(args.tag, args.asset_dir, token)
        elif args.mode == "promote":
            receipt = promote(args.tag, args.asset_dir, token)
        elif args.mode == "verify":
            receipt = verify_published(args.tag, args.asset_dir, token)
        else:
            receipt = rollback(args.tag, token)
        args.output.write_bytes(canonical(receipt))
        print(json.dumps({"verified": True, "repository": GITHUB_REPOSITORY, "tag": args.tag, "state": receipt["state"]}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
