"""Recoverable two-host promotion for a prepared DustMirror release.

CNB and GitHub are independent services, so there is no native atomic commit.
This coordinator minimizes and repairs the only possible split state:

1. both hosts are verified non-latest (CNB prerelease, GitHub prerelease);
2. CNB is promoted;
3. GitHub is promoted;
4. both live states and all bytes are read back.

If step 3 fails, CNB is immediately demoted again.  If the process was killed
between steps 2 and 3, the next invocation detects and demotes that exact,
same-build CNB release before retrying.  It never deletes a release or asset.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import sync_github_release as github
from scripts.verify_cnb_release_inventory import verify_release_inventory
from scripts.verify_cnb_release_state import _get, _is_prerelease, _tag


def _patch_cnb(endpoint: str, token: str, repo: str, release_id: object, value: dict) -> None:
    if not isinstance(release_id, (str, int)) or not str(release_id):
        raise ValueError("cnb_release_id_invalid")
    request = urllib.request.Request(
        f"{endpoint}/{repo}/-/releases/{release_id}",
        data=json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        method="PATCH",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        response.read()


def _cnb_state(
    *,
    endpoint: str,
    token: str,
    repo: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    verify_bytes: bool = True,
) -> tuple[str, dict]:
    target = _get(f"{endpoint}/{repo}/-/releases/tags/{tag}", token, allow_missing=True)
    latest = _get(f"{endpoint}/{repo}/-/releases/latest", token, allow_missing=True)
    if not isinstance(target, dict) or _tag(target) != tag:
        raise ValueError("cnb_release_missing")
    description = str(target.get("description") or target.get("body") or "").rstrip()
    if not description.endswith(f"Product build: {product_build_id}"):
        raise ValueError("release_not_owned_by_product_build")
    if verify_bytes:
        verify_release_inventory(
            endpoint=endpoint,
            token=token,
            repo=repo,
            tag=tag,
            product_build_id=product_build_id,
            authorization_path=authorization_path,
        )
    is_latest = isinstance(latest, dict) and (
        latest.get("id") == target.get("id") or _tag(latest) == tag
    )
    if is_latest:
        if _is_prerelease(target) or target.get("draft") is True:
            raise ValueError("cnb_latest_release_state_invalid")
        return "latest", target
    if target.get("draft") is True or not _is_prerelease(target):
        raise ValueError("cnb_release_is_not_prepared_nonlatest")
    return "nonlatest", target


def _set_cnb_state(
    *,
    endpoint: str,
    token: str,
    repo: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    release: dict,
    latest: bool,
) -> tuple[str, dict]:
    _patch_cnb(
        endpoint,
        token,
        repo,
        release.get("id"),
        {
            "draft": False,
            "prerelease": not latest,
            "make_latest": "true" if latest else "false",
        },
    )
    observed = _cnb_state(
        endpoint=endpoint,
        token=token,
        repo=repo,
        tag=tag,
        product_build_id=product_build_id,
        authorization_path=authorization_path,
        verify_bytes=False,
    )
    wanted = "latest" if latest else "nonlatest"
    if observed[0] != wanted:
        raise ValueError(f"cnb_release_transition_failed:{wanted}")
    return observed


def _github_is_latest(release: dict, token: str) -> bool:
    latest = github._get_latest(token)
    return isinstance(latest, dict) and latest.get("id") == release.get("id")


def promote(
    *,
    endpoint: str,
    cnb_token: str,
    github_token: str,
    repo: str,
    tag: str,
    product_build_id: str,
    authorization_path: Path,
    asset_dir: Path,
) -> dict:
    """Promote both exact releases, compensating or resuming split states."""

    cnb_state, cnb_release = _cnb_state(
        endpoint=endpoint,
        token=cnb_token,
        repo=repo,
        tag=tag,
        product_build_id=product_build_id,
        authorization_path=authorization_path,
        verify_bytes=False,
    )
    # Repair a hard interruption *before* doing any GitHub draft/upload work.
    # The only exception is the already-complete idempotent state, established
    # by exact identity/latest checks and then a full GitHub byte readback.
    if cnb_state == "latest":
        existing_github = github._get_release(tag, github_token)
        github_complete = False
        if isinstance(existing_github, dict):
            release_commit, release_tree = github._authorized_release_identity(
                authorization_path
            )
            github._validate_identity(
                existing_github,
                tag,
                product_build_id,
                release_commit,
                release_tree,
                github_token,
                verify_tag_target=github._state(existing_github) != "draft",
            )
            github_complete = (
                github._state(existing_github) == "published"
                and _github_is_latest(existing_github, github_token)
            )
        if github_complete:
            verified = github.prepare(
                tag, product_build_id, authorization_path, asset_dir, github_token
            )
            if verified["state"] != "published":
                raise ValueError("dual_release_postflight_failed")
            return {"state": "published", "cnb": "latest", "github": "latest"}
        cnb_state, cnb_release = _set_cnb_state(
            endpoint=endpoint,
            token=cnb_token,
            repo=repo,
            tag=tag,
            product_build_id=product_build_id,
            authorization_path=authorization_path,
            release=cnb_release,
            latest=False,
        )

    github_state = github.arm_nonlatest(
        tag, product_build_id, authorization_path, asset_dir, github_token
    )
    github_latest = github_state["is_latest"]

    if github_latest and cnb_state != "latest":
        if github_state["state"] != "published":
            raise ValueError("unsafe_split_state_github_latest_cnb_nonlatest")
        # This can only be produced when GitHub accepted the final PATCH but
        # its response was lost and CNB compensation then ran.  The exact
        # build and all GitHub bytes were verified by arm_nonlatest above, so
        # finishing CNB is the only non-destructive recovery.
        _set_cnb_state(
            endpoint=endpoint,
            token=cnb_token,
            repo=repo,
            tag=tag,
            product_build_id=product_build_id,
            authorization_path=authorization_path,
            release=cnb_release,
            latest=True,
        )
        return {"state": "published", "cnb": "latest", "github": "latest"}

    if github_state["state"] != "nonlatest" or github_latest:
        raise ValueError("github_release_is_not_prepared_nonlatest")

    try:
        cnb_state, cnb_release = _set_cnb_state(
            endpoint=endpoint,
            token=cnb_token,
            repo=repo,
            tag=tag,
            product_build_id=product_build_id,
            authorization_path=authorization_path,
            release=cnb_release,
            latest=True,
        )
    except Exception:
        # A PATCH may have succeeded even when its response/readback failed.
        # Best-effort compensation is safe because it targets only the exact
        # release already bound to this Product build.
        try:
            _, current = _cnb_state(
                endpoint=endpoint,
                token=cnb_token,
                repo=repo,
                tag=tag,
                product_build_id=product_build_id,
                authorization_path=authorization_path,
                verify_bytes=False,
            )
            _set_cnb_state(
                endpoint=endpoint,
                token=cnb_token,
                repo=repo,
                tag=tag,
                product_build_id=product_build_id,
                authorization_path=authorization_path,
                release=current,
                latest=False,
            )
        except Exception:
            pass
        raise

    try:
        github_result = github.promote_armed(
            tag,
            product_build_id,
            authorization_path,
            asset_dir,
            github_token,
            github_state,
        )
    except Exception:
        # If GitHub did apply the idempotent PATCH and only readback failed,
        # the next run observes both latest.  Otherwise restore CNB to the
        # non-latest phase so a normal failure exposes no one-sided latest.
        applied = False
        try:
            observed = github.prepare(
                tag, product_build_id, authorization_path, asset_dir, github_token
            )
            applied = observed["state"] == "published" and _github_is_latest(
                observed["release"], github_token
            )
        except Exception:
            applied = False
        if not applied:
            _set_cnb_state(
                endpoint=endpoint,
                token=cnb_token,
                repo=repo,
                tag=tag,
                product_build_id=product_build_id,
                authorization_path=authorization_path,
                release=cnb_release,
                latest=False,
            )
            raise
        github_result = observed

    final_cnb, _ = _cnb_state(
        endpoint=endpoint,
        token=cnb_token,
        repo=repo,
        tag=tag,
        product_build_id=product_build_id,
        authorization_path=authorization_path,
        verify_bytes=False,
    )
    final_github_release = github._get_release(tag, github_token)
    if final_github_release is None:
        raise ValueError("dual_release_postflight_failed")
    release_commit, release_tree = github._authorized_release_identity(authorization_path)
    github._validate_identity(
        final_github_release,
        tag,
        product_build_id,
        release_commit,
        release_tree,
        github_token,
    )
    if (
        final_cnb != "latest"
        or github_result["state"] != "published"
        or github._state(final_github_release) != "published"
        or not _github_is_latest(final_github_release, github_token)
    ):
        raise ValueError("dual_release_postflight_failed")
    return {"state": "published", "cnb": "latest", "github": "latest"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--product-build-id", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--asset-dir", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("dual-promotion-receipt.json"))
    args = parser.parse_args()
    try:
        endpoint = os.environ.get("CNB_API_ENDPOINT", "").rstrip("/")
        cnb_token = os.environ.get("CNB_TOKEN", "")
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if endpoint != "https://api.cnb.cool" or not cnb_token or not github_token:
            raise ValueError("dual_release_environment_missing")
        result = promote(
            endpoint=endpoint,
            cnb_token=cnb_token,
            github_token=github_token,
            repo=args.repo,
            tag=args.tag,
            product_build_id=args.product_build_id,
            authorization_path=args.authorization,
            asset_dir=args.asset_dir,
        )
        receipt = {
            "schema": "dustmirror.dual-promotion-receipt.v1",
            "tag": args.tag,
            "product_build_id": args.product_build_id,
            **result,
        }
        args.output.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        print(json.dumps({"verified": True, **result}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
