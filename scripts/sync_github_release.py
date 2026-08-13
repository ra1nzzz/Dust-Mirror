"""Prepare and verify the GitHub half of a public DustMirror release.

The public pipeline deliberately creates a GitHub draft and verifies every
byte before either host is promoted.  Reruns may fill *missing* assets, but
they never delete, replace, or overwrite an existing asset.  A same-name
asset with different bytes is therefore a permanent, fail-closed conflict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


GITHUB_API = "https://api.github.com"
GITHUB_REPOSITORY = "ra1nzzz/Dust-Mirror"
BUILD_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
CHUNK_SIZE = 1024 * 1024
HEARTBEAT_BYTES = 64 * 1024 * 1024
HEARTBEAT_SECONDS = 30
MAX_DOWNLOAD_ATTEMPTS = 3
MAX_UPLOAD_ATTEMPTS = 3
UPLOAD_READBACK_ATTEMPTS = 5
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
    digest = hashlib.sha256()
    size = 0
    next_heartbeat = HEARTBEAT_BYTES
    last_heartbeat = time.monotonic()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
            now = time.monotonic()
            if size >= next_heartbeat or now - last_heartbeat >= HEARTBEAT_SECONDS:
                print(
                    json.dumps(
                        {"heartbeat": "local_hash", "asset": path.name, "bytes": size},
                        sort_keys=True,
                    ),
                    flush=True,
                )
                next_heartbeat = size + HEARTBEAT_BYTES
                last_heartbeat = now
    return {"name": path.name, "size_bytes": size, "sha256": digest.hexdigest()}


def _release_body(product_build_id: str) -> str:
    if not BUILD_ID.fullmatch(product_build_id):
        raise ValueError("product_build_id_invalid")
    return (
        "CNB primary release mirror; assets are bound to the signed Product authorization. "
        f"Product build: {product_build_id}"
    )


def _authorized_release_identity(authorization_path: Path) -> tuple[str, str]:
    raw = authorization_path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if raw != canonical(value):
        raise ValueError("authorization_not_canonical")
    commit = value.get("release_commit")
    tree = value.get("release_tree")
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise ValueError("authorized_release_commit_invalid")
    if not isinstance(tree, str) or not HEX40.fullmatch(tree):
        raise ValueError("authorized_release_tree_invalid")
    return commit, tree


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
    with urllib.request.urlopen(request, timeout=120) as response:
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


def _get_latest(token: str) -> dict | None:
    try:
        return _json(f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases/latest", token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _asset_url(release: dict, name: str) -> str:
    upload_url = release.get("upload_url")
    if not isinstance(upload_url, str) or "{" not in upload_url:
        raise ValueError("github_upload_url_invalid")
    return upload_url.split("{", 1)[0] + "?name=" + urllib.parse.quote(name, safe="")


def _asset_download_url(asset: dict) -> str:
    url = asset.get("url")
    if not isinstance(url, str) or not url.startswith(f"{GITHUB_API}/"):
        raise ValueError("github_asset_url_invalid")
    return url


def _transient(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or 500 <= exc.code < 600
    return isinstance(exc, (TimeoutError, socket.timeout, ConnectionError, urllib.error.URLError))


def _upload_chunks(path: Path):
    sent = 0
    next_heartbeat = HEARTBEAT_BYTES
    last_heartbeat = time.monotonic()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            yield chunk
            sent += len(chunk)
            now = time.monotonic()
            if sent >= next_heartbeat or now - last_heartbeat >= HEARTBEAT_SECONDS:
                print(
                    json.dumps(
                        {"heartbeat": "upload", "asset": path.name, "bytes": sent},
                        sort_keys=True,
                    ),
                    flush=True,
                )
                next_heartbeat = sent + HEARTBEAT_BYTES
                last_heartbeat = now


def _upload_asset_once(url: str, token: str, path: Path) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "uploads.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
    ):
        raise ValueError("github_upload_url_untrusted")
    request = urllib.request.Request(
        url,
        data=_upload_chunks(path),
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Length": str(path.stat().st_size),
            "Content-Type": "application/octet-stream",
            "User-Agent": "DustMirror-CNB-release-mirror/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _uploaded_asset(release: dict, name: str) -> dict | None:
    return _assets_by_name(release).get(name)


def _readback_release_asset(tag: str, name: str, token: str) -> tuple[dict, dict] | None:
    release = _get_release(tag, token)
    if release is None:
        raise ValueError("github_release_disappeared")
    remote = _uploaded_asset(release, name)
    return (release, remote) if remote is not None else None


def _upload_asset_idempotent(
    *,
    tag: str,
    release: dict,
    path: Path,
    wanted: dict,
    token: str,
) -> None:
    """Upload without buffering and resolve ambiguous POSTs by exact readback."""

    for attempt in range(1, MAX_UPLOAD_ATTEMPTS + 1):
        existing = _uploaded_asset(release, path.name)
        if existing is not None:
            _validate_asset(path.name, existing, wanted, token)
            return
        try:
            _upload_asset_once(_asset_url(release, path.name), token, path)
        except Exception as exc:
            observed = _readback_release_asset(tag, path.name, token)
            if observed is not None:
                release, remote = observed
                _validate_asset(path.name, remote, wanted, token)
                return
            if attempt >= MAX_UPLOAD_ATTEMPTS or not _transient(exc):
                raise
            print(
                json.dumps(
                    {"heartbeat": "upload_retry", "asset": path.name, "attempt": attempt},
                    sort_keys=True,
                ),
                flush=True,
            )
            time.sleep(min(2 ** (attempt - 1), 4))
            refreshed = _get_release(tag, token)
            if refreshed is None:
                raise ValueError("github_release_disappeared")
            release = refreshed
            continue

        for readback_attempt in range(1, UPLOAD_READBACK_ATTEMPTS + 1):
            observed = _readback_release_asset(tag, path.name, token)
            if observed is not None:
                return
            print(
                json.dumps(
                    {
                        "heartbeat": "upload_readback",
                        "asset": path.name,
                        "attempt": readback_attempt,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            time.sleep(min(readback_attempt, 3))
        if attempt >= MAX_UPLOAD_ATTEMPTS:
            raise TimeoutError(f"github_upload_readback_timeout:{path.name}")
        refreshed = _get_release(tag, token)
        if refreshed is None:
            raise ValueError("github_release_disappeared")
        release = refreshed
    raise AssertionError("unreachable")


def _stream_asset_digest_once(asset: dict, token: str, *, label: str) -> tuple[int, str]:
    request = urllib.request.Request(
        _asset_download_url(asset),
        method="GET",
        headers={
            "Accept": "application/octet-stream",
            "Authorization": f"Bearer {token}",
            "User-Agent": "DustMirror-CNB-release-mirror/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    digest = hashlib.sha256()
    size = 0
    next_heartbeat = HEARTBEAT_BYTES
    with urllib.request.urlopen(request, timeout=120) as response:
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


def _stream_asset_digest(asset: dict, token: str, *, label: str) -> tuple[int, str]:
    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        try:
            return _stream_asset_digest_once(asset, token, label=label)
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


def _assets_by_name(release: dict) -> dict[str, dict]:
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(item, dict) for item in assets):
        raise ValueError("github_release_assets_invalid")
    names = [item.get("name") for item in assets]
    if any(not isinstance(name, str) or not name for name in names) or len(names) != len(set(names)):
        raise ValueError("github_release_asset_names_invalid")
    return dict(zip(names, assets, strict=True))


def _validate_asset(name: str, remote: dict, wanted: dict, token: str) -> dict:
    first_size, first_digest = _stream_asset_digest(remote, token, label=f"{name}:copy1")
    second_size, second_digest = _stream_asset_digest(remote, token, label=f"{name}:copy2")
    observed = {"name": name, "size_bytes": first_size, "sha256": first_digest}
    if (
        first_size != second_size
        or first_digest != second_digest
        or observed["size_bytes"] != wanted["size_bytes"]
        or observed["sha256"] != wanted["sha256"]
    ):
        raise ValueError(f"github_release_asset_digest_mismatch:{name}")
    return {**wanted, "remote_id": remote.get("id"), "redownloaded_sha256": observed["sha256"]}


def _validate_remote_assets(
    release: dict,
    expected: dict[str, dict],
    token: str,
    *,
    allow_partial: bool = False,
) -> dict[str, dict]:
    by_name = _assets_by_name(release)
    if not set(by_name).issubset(expected):
        raise ValueError("github_release_asset_set_mismatch")
    if not allow_partial and set(by_name) != set(expected):
        raise ValueError("github_release_asset_set_mismatch")
    return {
        name: _validate_asset(name, remote, expected[name], token)
        for name, remote in by_name.items()
    }


def _create_draft(tag: str, product_build_id: str, release_commit: str, token: str) -> dict:
    return _json(
        f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases",
        token,
        method="POST",
        value={
            "tag_name": tag,
            "target_commitish": release_commit,
            "name": f"DustMirror {tag}",
            "body": _release_body(product_build_id),
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


def _state(release: dict) -> str:
    draft = release.get("draft")
    prerelease = release.get("prerelease")
    if draft is True and prerelease is True:
        return "draft"
    if draft is False and prerelease is True:
        return "nonlatest"
    if draft is False and prerelease is False:
        return "published"
    raise ValueError("github_release_state_invalid")


def _tag_commit_and_tree(tag: str, token: str) -> tuple[str, str]:
    encoded = urllib.parse.quote(tag, safe="")
    ref = _json(f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/git/ref/tags/{encoded}", token)
    target = ref.get("object")
    if not isinstance(target, dict):
        raise ValueError("github_tag_target_invalid")
    for _ in range(5):
        kind = target.get("type")
        sha = target.get("sha")
        if not isinstance(sha, str) or not HEX40.fullmatch(sha):
            raise ValueError("github_tag_target_invalid")
        if kind == "commit":
            commit = _json(
                f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/git/commits/{sha}", token
            )
            tree = commit.get("tree")
            tree_sha = tree.get("sha") if isinstance(tree, dict) else None
            if not isinstance(tree_sha, str) or not HEX40.fullmatch(tree_sha):
                raise ValueError("github_tag_tree_invalid")
            return sha, tree_sha
        if kind != "tag":
            raise ValueError("github_tag_target_invalid")
        annotated = _json(
            f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/git/tags/{sha}", token
        )
        target = annotated.get("object")
        if not isinstance(target, dict):
            raise ValueError("github_tag_target_invalid")
    raise ValueError("github_tag_target_depth_exceeded")


def _validate_identity(
    release: dict,
    tag: str,
    product_build_id: str,
    release_commit: str,
    release_tree: str,
    token: str,
    *,
    verify_tag_target: bool = True,
) -> None:
    if release.get("tag_name") != tag:
        raise ValueError("github_release_tag_mismatch")
    body = str(release.get("body") or "").rstrip()
    if not body.endswith(f"Product build: {product_build_id}"):
        raise ValueError("github_release_not_owned_by_product_build")
    if release.get("target_commitish") != release_commit:
        raise ValueError("github_release_target_commitish_mismatch")
    if verify_tag_target:
        tag_commit, tag_tree = _tag_commit_and_tree(tag, token)
        if tag_commit != release_commit or tag_tree != release_tree:
            raise ValueError("github_release_tag_target_mismatch")


def _expected_assets(tag: str, asset_dir: Path) -> tuple[list[Path], dict[str, dict]]:
    paths = [asset_dir / template.format(tag=tag) for template in ASSET_NAMES]
    missing = [path.name for path in paths if not path.is_file()]
    if missing:
        raise ValueError("github_mirror_asset_missing:" + ",".join(missing))
    return paths, {path.name: local_asset(path) for path in paths}


def prepare(
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    asset_dir: Path,
    token: str,
) -> dict:
    """Create/resume a draft, fill only missing assets, and read back twice."""

    paths, expected = _expected_assets(tag, asset_dir)
    release_commit, release_tree = _authorized_release_identity(authorization_path)
    release = _get_release(tag, token)
    if release is None:
        release = _create_draft(tag, product_build_id, release_commit, token)
    release_state = _state(release)
    _validate_identity(
        release,
        tag,
        product_build_id,
        release_commit,
        release_tree,
        token,
        verify_tag_target=release_state != "draft",
    )
    existing = _validate_remote_assets(release, expected, token, allow_partial=True)
    missing = [path for path in paths if path.name not in existing]
    if missing and release_state != "draft":
        raise ValueError("github_published_release_inventory_incomplete")
    if not missing:
        return {"release": release, "state": release_state, "assets": existing}
    for path in missing:
        _upload_asset_idempotent(
            tag=tag,
            release=release,
            path=path,
            wanted=expected[path.name],
            token=token,
        )
    release = _get_release(tag, token)
    if release is None:
        raise ValueError("github_release_disappeared")
    release_state = _state(release)
    _validate_identity(
        release,
        tag,
        product_build_id,
        release_commit,
        release_tree,
        token,
        verify_tag_target=release_state != "draft",
    )
    remote_assets = _validate_remote_assets(release, expected, token)
    return {"release": release, "state": release_state, "assets": remote_assets}


def arm_nonlatest(
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    asset_dir: Path,
    token: str,
) -> dict:
    """Publish the verified draft only as a non-latest prerelease."""

    prepared = prepare(tag, product_build_id, authorization_path, asset_dir, token)
    release_commit, release_tree = _authorized_release_identity(authorization_path)
    release = prepared["release"]
    if prepared["state"] == "draft":
        _patch_release(
            release,
            token,
            {"draft": False, "prerelease": True, "make_latest": "false"},
        )
        release = _get_release(tag, token)
        if release is None:
            raise ValueError("github_release_disappeared")
    _validate_identity(
        release, tag, product_build_id, release_commit, release_tree, token
    )
    state = _state(release)
    latest = _get_latest(token)
    is_latest = isinstance(latest, dict) and latest.get("id") == release.get("id")
    if state == "nonlatest" and is_latest:
        raise ValueError("github_prerelease_is_unexpectedly_latest")
    if state not in {"nonlatest", "published"}:
        raise ValueError("github_release_arm_failed")
    _, expected = _expected_assets(tag, asset_dir)
    if set(_assets_by_name(release)) != set(expected):
        raise ValueError("github_release_asset_set_mismatch")
    return {
        "release": release,
        "state": state,
        "is_latest": is_latest,
        "assets": prepared["assets"],
    }


def promote_latest(
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    asset_dir: Path,
    token: str,
) -> dict:
    """Idempotently promote an already armed GitHub prerelease to latest."""

    armed = arm_nonlatest(tag, product_build_id, authorization_path, asset_dir, token)
    return promote_armed(
        tag,
        product_build_id,
        authorization_path,
        asset_dir,
        token,
        armed,
    )


def promote_armed(
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    asset_dir: Path,
    token: str,
    armed: dict,
) -> dict:
    """Promote a byte-verified armed result without redownloading large assets.

    ``arm_nonlatest`` is the phase-1 byte receipt.  This phase only mutates and
    reads release metadata; the pipeline's final ``verify`` performs the second
    full byte readback.  This fixes the download budget at two independent
    copies per phase rather than repeatedly downloading multi-gigabyte ZIPs.
    """

    release_commit, release_tree = _authorized_release_identity(authorization_path)
    release = armed["release"]
    if not armed["is_latest"]:
        _patch_release(
            release,
            token,
            {"draft": False, "prerelease": False, "make_latest": "true"},
        )
    release = _get_release(tag, token)
    latest = _get_latest(token)
    if release is None or latest is None:
        raise ValueError("github_release_publish_readback_missing")
    _validate_identity(
        release, tag, product_build_id, release_commit, release_tree, token
    )
    if (
        _state(release) != "published"
        or release.get("id") != latest.get("id")
        or latest.get("tag_name") != tag
    ):
        raise ValueError("github_release_publish_failed")
    _, expected = _expected_assets(tag, asset_dir)
    if set(_assets_by_name(release)) != set(expected):
        raise ValueError("github_release_asset_set_mismatch")
    return {
        "release": release,
        "state": "published",
        "is_latest": True,
        "assets": armed["assets"],
    }


def sync(
    mode: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    asset_dir: Path,
    token: str,
) -> dict:
    if mode == "prepare":
        result = prepare(tag, product_build_id, authorization_path, asset_dir, token)
    elif mode == "verify":
        result = prepare(tag, product_build_id, authorization_path, asset_dir, token)
        latest = _get_latest(token)
        result["is_latest"] = isinstance(latest, dict) and (
            latest.get("id") == result["release"].get("id")
        )
        if result["state"] != "published" or not result["is_latest"]:
            raise ValueError("github_release_postflight_failed")
    elif mode == "arm":
        result = arm_nonlatest(tag, product_build_id, authorization_path, asset_dir, token)
    elif mode == "promote":
        result = promote_latest(tag, product_build_id, authorization_path, asset_dir, token)
    else:  # pragma: no cover - argparse protects the CLI path
        raise ValueError("github_mirror_mode_invalid")
    return {
        "schema": "dustmirror.github-mirror-receipt.v2",
        "repository": GITHUB_REPOSITORY,
        "tag": tag,
        "product_build_id": product_build_id,
        "release_id": result["release"].get("id"),
        "state": result["state"],
        "is_latest": bool(result.get("is_latest", False)),
        "assets": result["assets"],
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("prepare", "arm", "promote", "verify"), default="prepare")
    parser.add_argument("--tag", default=os.environ.get("RELEASE_VERSION", ""))
    parser.add_argument("--product-build-id", default=os.environ.get("PRODUCT_BUILD_ID", ""))
    parser.add_argument(
        "--authorization", type=Path, default=Path("publication-authorization.json")
    )
    parser.add_argument("--asset-dir", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("github-mirror-receipt.json"))
    args = parser.parse_args()
    try:
        token = os.environ.get("GITHUB_TOKEN", "")
        if (
            not token
            or not isinstance(args.tag, str)
            or not args.tag.startswith("v")
            or not BUILD_ID.fullmatch(args.product_build_id)
        ):
            raise ValueError("github_mirror_environment_missing")
        receipt = sync(
            args.mode,
            args.tag,
            args.product_build_id,
            args.authorization,
            args.asset_dir,
            token,
        )
        args.output.write_bytes(canonical(receipt))
        print(
            json.dumps(
                {
                    "verified": True,
                    "repository": GITHUB_REPOSITORY,
                    "tag": args.tag,
                    "state": receipt["state"],
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
