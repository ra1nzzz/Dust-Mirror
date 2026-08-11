from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_signed_verification_precedes_release_creation_and_latest_promotion():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    verify = source.index("verify_publication_authorization.py")
    preflight = source.index("--mode preflight")
    create = source.index("Create a non-latest prerelease")
    inventory = source.index("verify_cnb_release_inventory.py")
    mirror_stage = source.index("Stage the exact bytes in a GitHub draft")
    promote = source.index("Promote the verified CNB release to latest")
    mirror_promote = source.index("Promote the already-verified GitHub draft")
    postflight = source.index("--mode postflight")
    assert verify < preflight < create < inventory < mirror_stage < promote < mirror_promote < postflight
    assert "release_coordinator_client.py" not in source
    assert "DUSTMIRROR_RELEASE_COORDINATOR_ORIGIN" not in source
    assert "sync_github_release.py" in source
    assert "GITHUB_TOKEN" in source


def test_any_publication_failure_runs_dual_endpoint_compensation():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    assert "failStages:" in source
    assert "rollback_cnb_release.py" in source
    assert "sync_github_release.py --mode rollback" in source
    assert "release-preflight-state.json" in source
    assert "PRODUCT_BUILD_ID" in source


def test_release_plugin_is_digest_pinned_and_private_handoff_is_used():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    assert "cnbcool/attachments:latest" not in source
    assert source.count("cnbcool/attachments@sha256:") == 2
    assert "slug: yitaocn/dustmirror" in source
    assert "commit: $PRODUCT_COMMIT" in source
    assert "api_trigger_prepare_windows_release" not in source
