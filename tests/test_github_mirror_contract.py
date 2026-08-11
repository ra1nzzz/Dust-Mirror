from pathlib import Path

import pytest

from scripts import sync_github_release as mirror


ROOT = Path(__file__).resolve().parents[1]


def test_mirror_client_has_no_coordinator_dependency():
    source = (ROOT / "scripts/sync_github_release.py").read_text(encoding="utf-8")
    assert "DUSTMIRROR_RELEASE_COORDINATOR" not in source
    assert 'GITHUB_API = "https://api.github.com"' in source
    assert 'GITHUB_REPOSITORY = "ra1nzzz/Dust-Mirror"' in source
    assert "GITHUB_TOKEN" in source


def test_mirror_has_exact_eight_authorized_assets_and_readback():
    source = (ROOT / "scripts/sync_github_release.py").read_text(encoding="utf-8")
    for marker in (
        "manifest.json",
        "manifest.sig",
        "trust.json",
        "trust.sig",
        "publication-authorization.json",
        "publication-authorization.sig",
        "_validate_remote_assets",
        "make_latest",
        "stage",
        "rollback",
    ):
        assert marker in source


def _asset_dir(tmp_path: Path, tag: str) -> Path:
    for template in mirror.ASSET_NAMES:
        (tmp_path / template.format(tag=tag)).write_bytes(template.encode("utf-8"))
    return tmp_path


def test_stage_never_publishes_the_github_release(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    tag = "v1.3.3"
    release = {"id": 7, "tag_name": tag, "draft": True, "prerelease": True, "assets": []}
    monkeypatch.setattr(mirror, "_get_release", lambda *_: release)
    monkeypatch.setattr(mirror, "_upload_missing_assets", lambda current, expected_paths, expected, token: {name: record for name, record in expected.items()})
    monkeypatch.setattr(mirror, "_publish", lambda *_: pytest.fail("stage must not publish"))
    receipt = mirror.stage(tag, _asset_dir(tmp_path, tag), "token")
    assert receipt["state"] == "staged"


def test_promote_requires_a_fully_staged_draft(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    tag = "v1.3.3"
    release = {"id": 7, "tag_name": tag, "draft": True, "prerelease": True, "assets": []}
    monkeypatch.setattr(mirror, "_get_release", lambda *_: release)
    monkeypatch.setattr(mirror, "_validate_remote_assets", lambda *_: {})
    monkeypatch.setattr(mirror, "_publish", lambda current, token: {**current, "draft": False, "prerelease": False})
    receipt = mirror.promote(tag, _asset_dir(tmp_path, tag), "token")
    assert receipt["state"] == "published"


def test_rollback_unpublishes_only_the_requested_release(monkeypatch: pytest.MonkeyPatch):
    tag = "v1.3.3"
    release = {"id": 7, "tag_name": tag, "draft": False, "prerelease": False, "assets": []}
    monkeypatch.setattr(mirror, "_get_release", lambda *_: release)
    monkeypatch.setattr(mirror, "_unpublish", lambda current, token: {**current, "draft": True, "prerelease": True})
    receipt = mirror.rollback(tag, "token")
    assert receipt["state"] == "rolled_back"


def test_setup_docs_explain_the_single_github_credential():
    docs = (ROOT / "docs/GITHUB_MIRROR_SETUP.md").read_text(encoding="utf-8")
    assert "GITHUB_TOKEN" in docs
    assert "DUSTMIRROR_RELEASE_COORDINATOR_ORIGIN" in docs
    assert "不需要" in docs
