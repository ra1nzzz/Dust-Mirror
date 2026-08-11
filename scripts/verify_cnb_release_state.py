"""Fail-closed pre/post publication checks against the live CNB Release API."""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _get(url: str, token: str, *, allow_missing: bool = False):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": f"token {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if allow_missing and exc.code == 404:
            return None
        raise


def _version(tag: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(tag)
    if not match:
        raise ValueError("release_tag_invalid")
    return tuple(map(int, match.groups()))


def _tag(value: dict) -> str:
    for key in ("tag_name", "tag", "name"):
        candidate = value.get(key)
        if isinstance(candidate, str) and SEMVER.fullmatch(candidate):
            return candidate
    raise ValueError("release_response_tag_missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("preflight", "postflight"), required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        endpoint = os.environ.get("CNB_API_ENDPOINT", "").rstrip("/")
        token = os.environ.get("CNB_TOKEN", "")
        if endpoint != "https://api.cnb.cool" or not token:
            raise ValueError("trusted_cnb_api_environment_missing")
        target_url = f"{endpoint}/{args.repo}/-/releases/tags/{args.tag}"
        latest_url = f"{endpoint}/{args.repo}/-/releases/latest"
        target = _get(target_url, token, allow_missing=True)
        latest = _get(latest_url, token, allow_missing=True)
        if args.mode == "preflight":
            if target is not None:
                raise ValueError("release_tag_already_exists")
            if latest is not None and _version(args.tag) <= _version(_tag(latest)):
                raise ValueError("release_version_not_newer_than_latest")
            state = {
                "schema": "dustmirror.cnb-release-preflight.v1",
                "tag": args.tag,
                "previous_latest_tag": _tag(latest) if isinstance(latest, dict) else None,
                "previous_latest_id": latest.get("id") if isinstance(latest, dict) else None,
            }
        else:
            if not isinstance(target, dict) or not isinstance(latest, dict):
                raise ValueError("published_release_missing")
            if target.get("id") != latest.get("id") or _tag(target) != args.tag or _tag(latest) != args.tag:
                raise ValueError("published_release_is_not_latest")
            state = {
                "schema": "dustmirror.cnb-release-postflight.v1",
                "tag": args.tag,
                "release_id": target.get("id"),
            }
        if args.output:
            args.output.write_text(
                json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"verified": True, "mode": args.mode, "tag": args.tag}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
