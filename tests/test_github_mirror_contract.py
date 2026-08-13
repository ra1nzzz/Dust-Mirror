from pathlib import Path


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
        "target_commitish",
        "release_commit",
        "release_tree",
        "_tag_commit_and_tree",
    ):
        assert marker in source
    assert '"target_commitish": "main"' not in source


def test_setup_docs_explain_the_single_github_credential():
    docs = (ROOT / "docs/GITHUB_MIRROR_SETUP.md").read_text(encoding="utf-8")
    assert "GITHUB_TOKEN" in docs
    assert "DUSTMIRROR_RELEASE_COORDINATOR_ORIGIN" in docs
    assert "不需要" in docs
