from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_signed_verification_precedes_release_creation_and_latest_promotion():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    verify = source.index("verify_publication_authorization.py")
    preflight = source.index("--mode preflight")
    create = source.index("Create a non-latest prerelease")
    inventory = source.index("verify_cnb_release_inventory.py")
    promote = source.index("Promote CNB and synchronize the exact bytes")
    postflight = source.index("--mode postflight")
    assert verify < preflight < create < inventory < promote < postflight


def test_release_plugin_is_digest_pinned_and_private_handoff_is_used():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    assert "cnbcool/attachments:latest" not in source
    assert source.count("cnbcool/attachments@sha256:") == 2
    assert "slug: yitaocn/dustmirror" in source
    assert "commit: $PRODUCT_COMMIT" in source
    assert "api_trigger_prepare_windows_release" not in source
