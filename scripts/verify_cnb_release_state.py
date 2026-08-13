"""Fail-closed pre/post publication checks against the live CNB Release API."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_cnb_release_inventory import (
    verify_release_inventory,
    verify_release_inventory_state,
)

SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
BUILD_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _get(url: str, token: str, *, allow_missing: bool = False):
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )
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


def _is_prerelease(value: dict) -> bool:
    return any(
        value.get(key) is True for key in ("prerelease", "pre_release", "preRelease")
    )


def preflight_decision(
    *,
    endpoint: str,
    token: str,
    repo: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
) -> dict:
    """Return a fail-closed create/resume/resume-upload decision."""

    if not BUILD_ID.fullmatch(product_build_id):
        raise ValueError("product_build_id_invalid")
    target_url = f"{endpoint}/{repo}/-/releases/tags/{tag}"
    latest_url = f"{endpoint}/{repo}/-/releases/latest"
    target = _get(target_url, token, allow_missing=True)
    latest = _get(latest_url, token, allow_missing=True)
    if target is None:
        if latest is not None and _version(tag) <= _version(_tag(latest)):
            raise ValueError("release_version_not_newer_than_latest")
        return {"action": "create", "missing": []}
    if not isinstance(target, dict) or _tag(target) != tag:
        raise ValueError("existing_release_identity_invalid")
    description = str(target.get("description") or target.get("body") or "").rstrip()
    if not description.endswith(f"Product build: {product_build_id}"):
        raise ValueError("release_not_owned_by_product_build")
    target_is_latest = isinstance(latest, dict) and (
        target.get("id") == latest.get("id") or _tag(latest) == tag
    )
    if target_is_latest:
        if target.get("draft") is True or _is_prerelease(target):
            raise ValueError("existing_latest_release_state_invalid")
        verify_release_inventory(
            endpoint=endpoint,
            token=token,
            repo=repo,
            tag=tag,
            product_build_id=product_build_id,
            authorization_path=authorization_path,
        )
        # A hard interruption may occur after CNB promotion and before the
        # GitHub commit/readback.  The dual promoter will validate, repair or
        # finish that exact same-build split state; never create/overwrite.
        return {"action": "resume", "missing": []}
    if latest is not None and _version(tag) <= _version(_tag(latest)):
        raise ValueError("release_version_not_newer_than_latest")
    if target.get("draft") is True or not _is_prerelease(target):
        raise ValueError("existing_release_is_not_resumable_prerelease")
    inventory = verify_release_inventory_state(
        endpoint=endpoint,
        token=token,
        repo=repo,
        tag=tag,
        product_build_id=product_build_id,
        authorization_path=authorization_path,
        allow_partial=True,
    )
    return {
        "action": "resume_upload" if inventory["missing"] else "resume",
        "missing": inventory["missing"],
    }


def preflight_action(**kwargs) -> str:
    """Compatibility wrapper used by unit tests and external callers."""

    return str(preflight_decision(**kwargs)["action"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("preflight", "postflight"), required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--product-build-id", default="")
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--set-output", action="store_true")
    args = parser.parse_args()
    try:
        endpoint = os.environ.get("CNB_API_ENDPOINT", "").rstrip("/")
        token = os.environ.get("CNB_TOKEN", "")
        if endpoint != "https://api.cnb.cool" or not token:
            raise ValueError("trusted_cnb_api_environment_missing")
        action = ""
        if args.mode == "preflight":
            if args.authorization is None:
                raise ValueError("publication_authorization_required")
            decision = preflight_decision(
                endpoint=endpoint,
                token=token,
                repo=args.repo,
                tag=args.tag,
                product_build_id=args.product_build_id,
                authorization_path=args.authorization,
            )
            action = str(decision["action"])
        else:
            target_url = f"{endpoint}/{args.repo}/-/releases/tags/{args.tag}"
            latest_url = f"{endpoint}/{args.repo}/-/releases/latest"
            target = _get(target_url, token, allow_missing=True)
            latest = _get(latest_url, token, allow_missing=True)
            if not isinstance(target, dict) or not isinstance(latest, dict):
                raise ValueError("published_release_missing")
            if target.get("id") != latest.get("id") or _tag(target) != args.tag or _tag(latest) != args.tag:
                raise ValueError("published_release_is_not_latest")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2
    result = {"verified": True, "mode": args.mode, "tag": args.tag}
    if action:
        result["action"] = action
    print(json.dumps(result, sort_keys=True))
    if args.set_output and action:
        print(f"##[set-output release_action={action}]")
        print(f"##[set-output missing_assets={','.join(decision.get('missing', []))}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
