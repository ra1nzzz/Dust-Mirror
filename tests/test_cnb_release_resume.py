from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from scripts import verify_cnb_release_inventory as inventory
from scripts import verify_cnb_release_state as state


TAG = "v1.3.27"
BUILD_ID = "product-build-27"


def _target(*, build_id: str = BUILD_ID, prerelease: bool = True) -> dict:
    return {
        "id": 27,
        "tag_name": TAG,
        "pre_release": prerelease,
        "description": f"等待公开仓完整资产复核。Product build: {build_id}",
    }


def _latest() -> dict:
    return {"id": 26, "tag_name": "v1.3.26"}


def _mock_releases(monkeypatch: pytest.MonkeyPatch, target: dict | None, latest: dict | None) -> None:
    def fake_get(url: str, _token: str, *, allow_missing: bool = False):
        if url.endswith("/releases/latest"):
            return latest
        if url.endswith(f"/releases/tags/{TAG}"):
            return target
        raise AssertionError(url)

    monkeypatch.setattr(state, "_get", fake_get)


def test_missing_tag_selects_create(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_releases(monkeypatch, None, _latest())
    action = state.preflight_action(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=tmp_path / "publication-authorization.json",
    )
    assert action == "create"


def test_exact_nonlatest_prerelease_with_matching_assets_selects_resume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_releases(monkeypatch, _target(), _latest())
    observed = {}

    def verified(**kwargs):
        observed.update(kwargs)
        return {"present": ["manifest.json"], "missing": []}

    monkeypatch.setattr(state, "verify_release_inventory_state", verified)
    authorization = tmp_path / "publication-authorization.json"
    action = state.preflight_action(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=authorization,
    )
    assert action == "resume"
    assert observed["tag"] == TAG
    assert observed["product_build_id"] == BUILD_ID
    assert observed["authorization_path"] == authorization
    assert observed["allow_partial"] is True


def test_verified_authorized_subset_selects_resume_upload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_releases(monkeypatch, _target(), _latest())
    monkeypatch.setattr(
        state,
        "verify_release_inventory_state",
        lambda **_kwargs: {
            "present": ["manifest.json"],
            "missing": ["bundle.zip"],
        },
    )
    decision = state.preflight_decision(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=tmp_path / "publication-authorization.json",
    )
    assert decision == {"action": "resume_upload", "missing": ["bundle.zip"]}


@pytest.mark.parametrize(
    ("target", "latest", "error"),
    (
        (_target(build_id="different-build"), _latest(), "release_not_owned_by_product_build"),
        (_target(prerelease=False), _latest(), "existing_release_is_not_resumable_prerelease"),
    ),
)
def test_resume_rejects_wrong_build_or_unexpected_published_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: dict,
    latest: dict,
    error: str,
) -> None:
    _mock_releases(monkeypatch, target, latest)
    with pytest.raises(ValueError, match=error):
        state.preflight_action(
            endpoint="https://api.cnb.cool",
            token="secret",
            repo="yitaocn/dust-mirror",
            tag=TAG,
            product_build_id=BUILD_ID,
            authorization_path=tmp_path / "publication-authorization.json",
        )


def test_exact_same_build_already_latest_resumes_finalization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = _target(prerelease=False)
    _mock_releases(monkeypatch, target, target)
    monkeypatch.setattr(state, "verify_release_inventory", lambda **_kwargs: ["manifest.json"])
    assert state.preflight_action(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=tmp_path / "publication-authorization.json",
    ) == "resume"


def test_resume_rejects_any_inventory_or_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_releases(monkeypatch, _target(), _latest())

    def rejected(**_kwargs):
        raise ValueError("release_asset_bytes_mismatch:manifest.json")

    monkeypatch.setattr(state, "verify_release_inventory_state", rejected)
    with pytest.raises(ValueError, match="release_asset_bytes_mismatch"):
        state.preflight_action(
            endpoint="https://api.cnb.cool",
            token="secret",
            repo="yitaocn/dust-mirror",
            tag=TAG,
            product_build_id=BUILD_ID,
            authorization_path=tmp_path / "publication-authorization.json",
        )


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


@pytest.mark.parametrize("module", (state, inventory))
def test_all_cnb_json_requests_use_bearer_authorization(
    monkeypatch: pytest.MonkeyPatch, module
) -> None:
    captured = {}

    def fake_urlopen(request, timeout):
        captured["authorization"] = request.get_header("Authorization")
        return _Response(json.dumps({"id": 1}).encode("utf-8"))

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    if module is state:
        module._get("https://api.cnb.cool/test", "secret")
    else:
        module._request("https://api.cnb.cool/test", "secret")
    assert captured["authorization"] == "Bearer secret"


def test_cnb_inventory_binds_release_tag_target_to_authorized_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    commit, tree = "a" * 40, "b" * 40
    control_raw, asset_raw = b"control", b"asset"
    authorization = tmp_path / "publication-authorization.json"
    signature = tmp_path / "publication-authorization.sig"
    signature.write_bytes(b"signature")
    payload = {
        "release_commit": commit,
        "release_tree": tree,
        "controls": {
            "manifest": {
                "name": "manifest.json",
                "size_bytes": len(control_raw),
                "sha256": __import__("hashlib").sha256(control_raw).hexdigest(),
            }
        },
        "assets": {
            "FREE": {
                "name": "bundle.zip",
                "size_bytes": len(asset_raw),
                "sha256": __import__("hashlib").sha256(asset_raw).hexdigest(),
            }
        },
    }
    authorization.write_text(json.dumps(payload), encoding="utf-8")
    records = inventory._expected_records(authorization)
    raw_by_name = {
        "manifest.json": control_raw,
        "bundle.zip": asset_raw,
        "publication-authorization.json": authorization.read_bytes(),
        "publication-authorization.sig": signature.read_bytes(),
    }
    release = {
        "id": "release-27",
        "tag_name": TAG,
        "tag_commitish": commit,
        "prerelease": True,
        "body": f"Product build: {BUILD_ID}",
        "assets": [{"name": name} for name in records],
    }
    monkeypatch.setattr(inventory, "_request", lambda *_args: release)
    monkeypatch.setattr(
        inventory,
        "_stream_digest",
        lambda url, _token, **_kwargs: (
            len(raw_by_name[url.rsplit("/", 1)[-1]]),
            __import__("hashlib").sha256(raw_by_name[url.rsplit("/", 1)[-1]]).hexdigest(),
        ),
    )
    assert inventory.verify_release_inventory(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=authorization,
    ) == sorted(records)

    one_name = next(iter(records))
    release["assets"] = [{"name": one_name}]
    partial = inventory.verify_release_inventory_state(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=authorization,
        allow_partial=True,
    )
    assert partial == {
        "present": [one_name],
        "missing": sorted(set(records) - {one_name}),
    }

    release["assets"] = [{"name": "not-authorized.bin"}]
    with pytest.raises(ValueError, match="release_inventory_mismatch"):
        inventory.verify_release_inventory_state(
            endpoint="https://api.cnb.cool",
            token="secret",
            repo="yitaocn/dust-mirror",
            tag=TAG,
            product_build_id=BUILD_ID,
            authorization_path=authorization,
            allow_partial=True,
        )

    release["assets"] = [{"name": name} for name in records]
    release["tag_commitish"] = "c" * 40
    with pytest.raises(ValueError, match="tag_target_mismatch"):
        inventory.verify_release_inventory(
            endpoint="https://api.cnb.cool",
            token="secret",
            repo="yitaocn/dust-mirror",
            tag=TAG,
            product_build_id=BUILD_ID,
            authorization_path=authorization,
        )
