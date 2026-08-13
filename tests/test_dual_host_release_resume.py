from __future__ import annotations

from pathlib import Path

import pytest

from scripts import promote_public_release as dual
from scripts import sync_github_release as github


TAG = "v1.3.27"
BUILD_ID = "product-build-27"
TOKEN = "test-token"
RELEASE_COMMIT = "a" * 40
RELEASE_TREE = "b" * 40


def _files(tmp_path: Path) -> tuple[list[Path], dict[str, bytes]]:
    paths = [tmp_path / template.format(tag=TAG) for template in github.ASSET_NAMES]
    content = {}
    for index, path in enumerate(paths):
        raw = f"asset-{index}-{path.name}".encode()
        path.write_bytes(raw)
        content[path.name] = raw
    authorization = tmp_path / "publication-authorization.json"
    raw = github.canonical(
        {"release_commit": RELEASE_COMMIT, "release_tree": RELEASE_TREE}
    )
    authorization.write_bytes(raw)
    content[authorization.name] = raw
    return paths, content


def _draft(assets: list[dict]) -> dict:
    return {
        "id": 27,
        "tag_name": TAG,
        "body": github._release_body(BUILD_ID),
        "target_commitish": RELEASE_COMMIT,
        "draft": True,
        "prerelease": True,
        "upload_url": "https://uploads.github.com/repos/ra1nzzz/Dust-Mirror/releases/27/assets{?name}",
        "assets": assets,
    }


def _remote(name: str, raw: bytes, asset_id: int) -> dict:
    return {
        "id": asset_id,
        "name": name,
        "url": f"{github.GITHUB_API}/repos/ra1nzzz/Dust-Mirror/releases/assets/{asset_id}",
        "raw": raw,
    }


def _install_github_fake(
    monkeypatch: pytest.MonkeyPatch,
    release: dict,
    content: dict[str, bytes],
    *,
    fail_after_uploads: int | None = None,
) -> list[str]:
    uploads: list[str] = []
    monkeypatch.setattr(github, "_get_release", lambda _tag, _token: release)
    monkeypatch.setattr(
        github,
        "_stream_asset_digest",
        lambda asset, _token, **_kwargs: (
            len(asset["raw"]),
            github.sha256_bytes(asset["raw"]),
        ),
    )
    monkeypatch.setattr(
        github, "_tag_commit_and_tree", lambda _tag, _token: (RELEASE_COMMIT, RELEASE_TREE)
    )
    monkeypatch.setattr(github.time, "sleep", lambda _seconds: None)

    def upload(url: str, _token: str, path: Path):
        if fail_after_uploads is not None and len(uploads) == fail_after_uploads:
            raise ConnectionResetError("simulated upload interruption")
        name = path.name
        assert name in url
        uploads.append(name)
        release["assets"].append(_remote(name, content[name], 100 + len(uploads)))
        return b"{}"

    monkeypatch.setattr(github, "_upload_asset_once", upload)
    return uploads


def test_partial_same_byte_draft_resumes_only_missing_uploads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    paths, content = _files(tmp_path)
    first = paths[0].name
    release = _draft([_remote(first, content[first], 1)])
    uploads = _install_github_fake(monkeypatch, release, content)

    result = github.prepare(
        TAG, BUILD_ID, tmp_path / "publication-authorization.json", tmp_path, TOKEN
    )

    assert result["state"] == "draft"
    assert uploads == [path.name for path in paths[1:]]
    assert set(result["assets"]) == set(content)


def test_interrupted_partial_upload_resumes_without_replacing_existing_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    paths, content = _files(tmp_path)
    release = _draft([])
    first_uploads = _install_github_fake(
        monkeypatch, release, content, fail_after_uploads=3
    )
    with pytest.raises(ConnectionResetError, match="simulated upload interruption"):
        github.prepare(
            TAG, BUILD_ID, tmp_path / "publication-authorization.json", tmp_path, TOKEN
        )
    assert first_uploads == [path.name for path in paths[:3]]

    resumed_uploads = _install_github_fake(monkeypatch, release, content)
    result = github.prepare(
        TAG, BUILD_ID, tmp_path / "publication-authorization.json", tmp_path, TOKEN
    )
    assert resumed_uploads == [path.name for path in paths[3:]]
    assert result["state"] == "draft"
    assert len(release["assets"]) == len(paths)


def test_existing_different_byte_blocks_without_upload_or_overwrite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    paths, content = _files(tmp_path)
    first = paths[0].name
    release = _draft([_remote(first, b"different", 1)])
    uploads = _install_github_fake(monkeypatch, release, content)
    with pytest.raises(ValueError, match="asset_digest_mismatch"):
        github.prepare(
            TAG, BUILD_ID, tmp_path / "publication-authorization.json", tmp_path, TOKEN
        )
    assert uploads == []
    assert release["assets"][0]["raw"] == b"different"


def test_github_draft_targets_authorized_release_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}

    def fake_json(_url, _token, *, method="GET", value=None):
        captured.update({"method": method, "value": value})
        return {"id": 27}

    monkeypatch.setattr(github, "_json", fake_json)
    github._create_draft(TAG, BUILD_ID, RELEASE_COMMIT, TOKEN)
    assert captured["method"] == "POST"
    assert captured["value"]["target_commitish"] == RELEASE_COMMIT
    assert captured["value"]["target_commitish"] != "main"


def test_github_postflight_rejects_release_or_tag_target_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _draft([])
    release["target_commitish"] = "c" * 40
    with pytest.raises(ValueError, match="target_commitish_mismatch"):
        github._validate_identity(
            release, TAG, BUILD_ID, RELEASE_COMMIT, RELEASE_TREE, TOKEN
        )

    release["target_commitish"] = RELEASE_COMMIT
    monkeypatch.setattr(
        github, "_tag_commit_and_tree", lambda *_args: (RELEASE_COMMIT, "d" * 40)
    )
    with pytest.raises(ValueError, match="tag_target_mismatch"):
        github._validate_identity(
            release, TAG, BUILD_ID, RELEASE_COMMIT, RELEASE_TREE, TOKEN
        )


def _github_result(state: str, *, latest: bool) -> dict:
    return {
        "release": {
            "id": 27,
            "tag_name": TAG,
            "body": github._release_body(BUILD_ID),
            "draft": state == "draft",
            "prerelease": state != "published",
        },
        "state": state,
        "is_latest": latest,
        "assets": {},
    }


def _dual_kwargs(tmp_path: Path) -> dict:
    (tmp_path / "publication-authorization.json").write_bytes(
        github.canonical(
            {"release_commit": RELEASE_COMMIT, "release_tree": RELEASE_TREE}
        )
    )
    return {
        "endpoint": "https://api.cnb.cool",
        "cnb_token": TOKEN,
        "github_token": TOKEN,
        "repo": "yitaocn/dust-mirror",
        "tag": TAG,
        "product_build_id": BUILD_ID,
        "authorization_path": tmp_path / "publication-authorization.json",
        "asset_dir": tmp_path,
    }


def test_github_promotion_failure_compensates_cnb_to_nonlatest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = {"id": 27, "tag_name": TAG}
    monkeypatch.setattr(dual, "_cnb_state", lambda **_kwargs: ("nonlatest", release))
    transitions: list[bool] = []

    def set_state(*, latest: bool, **_kwargs):
        transitions.append(latest)
        return ("latest" if latest else "nonlatest", release)

    monkeypatch.setattr(dual, "_set_cnb_state", set_state)
    monkeypatch.setattr(
        dual.github, "arm_nonlatest", lambda *_args: _github_result("nonlatest", latest=False)
    )
    monkeypatch.setattr(
        dual.github, "promote_armed", lambda *_args: (_ for _ in ()).throw(RuntimeError("github down"))
    )
    monkeypatch.setattr(
        dual.github, "prepare", lambda *_args: _github_result("nonlatest", latest=False)
    )
    monkeypatch.setattr(dual, "_github_is_latest", lambda *_args: False)

    with pytest.raises(RuntimeError, match="github down"):
        dual.promote(**_dual_kwargs(tmp_path))
    assert transitions == [True, False]


def test_retry_repairs_interrupted_cnb_first_commit_then_finishes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = {"id": 27, "tag_name": TAG}
    states = iter((("latest", release), ("latest", release)))
    monkeypatch.setattr(dual, "_cnb_state", lambda **_kwargs: next(states))
    transitions: list[bool] = []
    events: list[str] = []

    def set_state(*, latest: bool, **_kwargs):
        transitions.append(latest)
        events.append("cnb-latest" if latest else "cnb-nonlatest")
        return ("latest" if latest else "nonlatest", release)

    monkeypatch.setattr(dual, "_set_cnb_state", set_state)
    def arm(*_args):
        events.append("github-arm")
        return _github_result("nonlatest", latest=False)

    monkeypatch.setattr(dual.github, "arm_nonlatest", arm)
    monkeypatch.setattr(
        dual.github, "promote_armed", lambda *_args: _github_result("published", latest=True)
    )
    monkeypatch.setattr(
        dual.github, "prepare", lambda *_args: _github_result("published", latest=True)
    )
    github_releases = iter(
        (
            _github_result("nonlatest", latest=False)["release"],
            _github_result("published", latest=True)["release"],
        )
    )
    monkeypatch.setattr(dual.github, "_get_release", lambda *_args: next(github_releases))
    monkeypatch.setattr(dual, "_github_is_latest", lambda *_args: True)
    monkeypatch.setattr(dual.github, "_validate_identity", lambda *_args, **_kwargs: None)

    assert dual.promote(**_dual_kwargs(tmp_path))["state"] == "published"
    assert transitions == [False, True]
    assert events[:2] == ["cnb-nonlatest", "github-arm"]


def test_both_latest_same_build_is_idempotent_noop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = {"id": 27, "tag_name": TAG}
    monkeypatch.setattr(dual, "_cnb_state", lambda **_kwargs: ("latest", release))
    monkeypatch.setattr(
        dual.github, "arm_nonlatest", lambda *_args: _github_result("published", latest=True)
    )
    monkeypatch.setattr(
        dual.github,
        "_get_release",
        lambda *_args: _github_result("published", latest=True)["release"],
    )
    monkeypatch.setattr(dual.github, "_validate_identity", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(dual, "_github_is_latest", lambda *_args: True)
    monkeypatch.setattr(
        dual.github, "prepare", lambda *_args: _github_result("published", latest=True)
    )
    monkeypatch.setattr(
        dual, "_set_cnb_state", lambda **_kwargs: pytest.fail("must not rewrite completed release")
    )

    assert dual.promote(**_dual_kwargs(tmp_path)) == {
        "state": "published",
        "cnb": "latest",
        "github": "latest",
    }


def test_retry_finishes_reverse_split_after_lost_github_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = {"id": 27, "tag_name": TAG}
    monkeypatch.setattr(dual, "_cnb_state", lambda **_kwargs: ("nonlatest", release))
    monkeypatch.setattr(
        dual.github, "arm_nonlatest", lambda *_args: _github_result("published", latest=True)
    )
    transitions: list[bool] = []

    def set_state(*, latest: bool, **_kwargs):
        transitions.append(latest)
        return ("latest", release)

    monkeypatch.setattr(dual, "_set_cnb_state", set_state)
    assert dual.promote(**_dual_kwargs(tmp_path))["state"] == "published"
    assert transitions == [True]
