"""Verify the complete CNB prerelease attachment inventory before promotion."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def _request(url: str, token: str, auth: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": f"{auth} {token}"})
    with urllib.request.urlopen(req, timeout=30) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("cnb_release_response_invalid")
    return value


def _download(url: str, token: str) -> bytes:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read()


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
        authorization = json.loads(args.authorization.read_text(encoding="utf-8"))
        expected_records = {item["name"]: item for item in (*authorization["controls"].values(), *authorization["assets"].values())}
        for extra in ("publication-authorization.json", "publication-authorization.sig"):
            path = Path(extra)
            raw = path.read_bytes()
            expected_records[extra] = {"name": extra, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        expected = set(expected_records)
        release = _request(f"{endpoint}/{args.repo}/-/releases/tags/{args.tag}", token, "token")
        release_id = release.get("id")
        description = str(release.get("description") or release.get("body") or "")
        if not release_id or f"Product build: {args.product_build_id}" not in description:
            raise ValueError("release_not_owned_by_product_build")
        detail = _request(f"{endpoint}/{args.repo}/-/releases/{release_id}", token, "Bearer")
        names = _asset_names(detail)
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError(f"release_inventory_mismatch:{sorted(names)}")
        for name, record in expected_records.items():
            url = f"{endpoint}/{args.repo}/-/releases/download/{args.tag}/{name}"
            first = _download(url, token)
            second = _download(url, token)
            if first != second or len(first) != record["size_bytes"] or hashlib.sha256(first).hexdigest() != record["sha256"]:
                raise ValueError(f"release_asset_bytes_mismatch:{name}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"verified": True, "tag": args.tag, "assets": sorted(expected)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
