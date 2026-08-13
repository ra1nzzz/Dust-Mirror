from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts import resume_cnb_release_upload as upload


TAG = "v1.3.27"
BUILD_ID = "product-build-27"
COMMIT = "a" * 40


def _records(tmp_path: Path) -> tuple[Path, dict[str, dict]]:
    authorization = tmp_path / "publication-authorization.json"
    authorization.write_text('{"release_commit":"' + COMMIT + '"}', encoding="utf-8")
    result = {}
    for name, raw in (("existing.bin", b"existing"), ("missing.bin", b"missing")):
        (tmp_path / name).write_bytes(raw)
        result[name] = {
            "name": name,
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    return authorization, result


def _release(names: set[str]) -> tuple[dict, dict]:
    base = {
        "id": "release-27",
        "tag_name": TAG,
        "tag_commitish": COMMIT,
        "body": f"Product build: {BUILD_ID}",
    }
    return base, {**base, "assets": [{"name": name} for name in sorted(names)]}


def test_resume_upload_requests_only_missing_with_overwrite_false(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    authorization, records = _records(tmp_path)
    names = {"existing.bin"}
    monkeypatch.setattr(upload, "_expected_records", lambda _path: records)
    monkeypatch.setattr(upload, "_current_release", lambda *_args: _release(names))
    requests = []

    def api(_url, _token, *, value):
        requests.append(value)
        return {
            "upload_url": "https://storage.example/upload",
            "verify_url": (
                "https://api.cnb.cool/yitaocn/dust-mirror/-/releases/"
                "release-27/asset-upload-confirmation/token/path"
            ),
        }

    monkeypatch.setattr(upload, "_api_json", api)
    monkeypatch.setattr(upload, "_put_file_once", lambda _url, _path: None)
    monkeypatch.setattr(upload, "_confirm", lambda *_args, **_kwargs: names.add("missing.bin"))
    monkeypatch.setattr(upload, "_wait_for_asset", lambda *_args: True)
    monkeypatch.setattr(
        upload, "verify_release_inventory", lambda **_kwargs: sorted(records)
    )

    assert upload.resume_missing(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=authorization,
        expected_missing={"missing.bin"},
    ) == sorted(records)
    assert requests == [
        {
            "asset_name": "missing.bin",
            "overwrite": False,
            "size": len(b"missing"),
            "ttl": 0,
        }
    ]


def test_resume_upload_accepts_already_confirmed_progress_but_blocks_regression(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    authorization, records = _records(tmp_path)
    monkeypatch.setattr(upload, "_expected_records", lambda _path: records)
    monkeypatch.setattr(
        upload, "_current_release", lambda *_args: _release({"existing.bin", "missing.bin"})
    )
    monkeypatch.setattr(
        upload, "_api_json", lambda *_args, **_kwargs: pytest.fail("must not request upload")
    )
    monkeypatch.setattr(
        upload,
        "verify_release_inventory_state",
        lambda **_kwargs: {"present": sorted(records), "missing": []},
    )
    monkeypatch.setattr(
        upload, "verify_release_inventory", lambda **_kwargs: sorted(records)
    )
    assert upload.resume_missing(
        endpoint="https://api.cnb.cool",
        token="secret",
        repo="yitaocn/dust-mirror",
        tag=TAG,
        product_build_id=BUILD_ID,
        authorization_path=authorization,
        expected_missing={"missing.bin"},
    ) == sorted(records)

    monkeypatch.setattr(upload, "_current_release", lambda *_args: _release(set()))
    with pytest.raises(ValueError, match="resume_missing_set_changed"):
        upload.resume_missing(
            endpoint="https://api.cnb.cool",
            token="secret",
            repo="yitaocn/dust-mirror",
            tag=TAG,
            product_build_id=BUILD_ID,
            authorization_path=authorization,
            expected_missing={"missing.bin"},
        )

    with pytest.raises(ValueError, match="expected_missing_assets_invalid"):
        upload.resume_missing(
            endpoint="https://api.cnb.cool",
            token="secret",
            repo="yitaocn/dust-mirror",
            tag=TAG,
            product_build_id=BUILD_ID,
            authorization_path=authorization,
            expected_missing={"evil.bin"},
        )
