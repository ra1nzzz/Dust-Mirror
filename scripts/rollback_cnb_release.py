"""Compensate a partially promoted CNB release without deleting its tag."""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def _request(url: str, token: str, *, method: str = "GET", value: dict | None = None, allow_missing: bool = False):
    body = None if value is None else json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.cnb.api+json",
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if allow_missing and exc.code == 404:
            return None
        raise
    return json.loads(raw.decode("utf-8")) if raw else {}


def rollback(
    *, endpoint: str, repo: str, tag: str, product_build_id: str,
    state_path: Path, token: str,
) -> dict:
    target_url = f"{endpoint}/{repo}/-/releases/tags/{tag}"
    target = _request(target_url, token, allow_missing=True)
    if target is None:
        return {"status": "absent", "tag": tag}
    description = str(target.get("description") or target.get("body") or "")
    if f"Product build: {product_build_id}" not in description:
        raise ValueError("release_not_owned_by_product_build")
    if not state_path.is_file():
        raise ValueError("release_preflight_state_missing")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("schema") != "dustmirror.cnb-release-preflight.v1" or state.get("tag") != tag:
        raise ValueError("release_preflight_state_invalid")
    release_id = target.get("id")
    if not release_id:
        raise ValueError("release_id_missing")
    _request(
        f"{endpoint}/{repo}/-/releases/{release_id}", token, method="PATCH",
        value={"draft": False, "prerelease": True, "make_latest": "false"},
    )
    previous_id = state.get("previous_latest_id")
    previous_tag = state.get("previous_latest_tag")
    if previous_id and previous_tag:
        _request(
            f"{endpoint}/{repo}/-/releases/{previous_id}", token, method="PATCH",
            value={"make_latest": "true"},
        )
    latest = _request(f"{endpoint}/{repo}/-/releases/latest", token, allow_missing=True)
    if isinstance(latest, dict):
        observed = latest.get("tag_name") or latest.get("tag") or latest.get("name")
        if observed == tag:
            raise ValueError("candidate_remains_latest_after_rollback")
        if previous_tag and observed != previous_tag:
            raise ValueError("previous_latest_not_restored")
    return {"status": "rolled_back", "tag": tag, "previous_latest_tag": previous_tag}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--product-build-id", required=True)
    parser.add_argument("--preflight-state", type=Path, required=True)
    args = parser.parse_args()
    try:
        endpoint = os.environ.get("CNB_API_ENDPOINT", "").rstrip("/")
        token = os.environ.get("CNB_TOKEN", "")
        if endpoint != "https://api.cnb.cool" or not token:
            raise ValueError("trusted_cnb_api_environment_missing")
        result = rollback(
            endpoint=endpoint, repo=args.repo, tag=args.tag,
            product_build_id=args.product_build_id,
            state_path=args.preflight_state, token=token,
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"rolled_back": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"rolled_back": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
