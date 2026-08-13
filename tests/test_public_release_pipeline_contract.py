from pathlib import Path
import inspect
import re

import yaml

from scripts import (
    promote_public_release,
    resume_cnb_release_upload,
    sync_github_release,
    verify_cnb_release_inventory,
)


ROOT = Path(__file__).resolve().parents[1]


def test_both_hosts_are_byte_verified_before_recoverable_latest_promotion():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    verify = source.index("verify_publication_authorization.py")
    preflight = source.index("--mode preflight")
    create = source.index("Create a non-latest prerelease")
    inventory = source.index("verify_cnb_release_inventory.py")
    promote = source.index("Prepare both hosts and commit the recoverable two-host promotion")
    postflight = source.index("--mode postflight")
    assert verify < preflight < create < inventory < promote < postflight
    assert "release_coordinator_client.py" not in source
    assert "DUSTMIRROR_RELEASE_COORDINATOR_ORIGIN" not in source
    assert "sync_github_release.py" in source
    assert "promote_public_release.py" in source
    assert source.count("--authorization publication-authorization.json") >= 3
    assert "GITHUB_TOKEN" in source
    assert "--product-build-id \"$PRODUCT_BUILD_ID\"" in source
    assert "--authorization publication-authorization.json --set-output" in source
    assert "release_action: PUBLIC_RELEASE_ACTION" in source
    assert source.count('[ "$PUBLIC_RELEASE_ACTION" = "create" ]') == 3
    assert '[ "$PUBLIC_RELEASE_ACTION" = "resume_upload" ]' in source
    assert "missing_assets: PUBLIC_RELEASE_MISSING_ASSETS" in source
    assert "resume_cnb_release_upload.py" in source
    assert "python3 scripts/verify_release_runtime.py" not in source
    assert "./.release-ci-venv/bin/python scripts/verify_release_runtime.py --require-venv" in source
    assert "--require-hashes -r requirements-release-ci.txt" in source
    assert "--only-binary=:all:" in source
    assert "python3 scripts/" not in source
    assert source.index("verify_release_runtime.py") < source.index(
        "verify_publication_authorization.py"
    )
    assert "verify_release_inventory" in (
        ROOT / "scripts" / "verify_cnb_release_state.py"
    ).read_text(encoding="utf-8")
    # No built-in CNB latest promotion is allowed to run before GitHub draft
    # upload/readback.  The only commit point is the compensating coordinator.
    assert "Promote the verified CNB release to latest" not in source
    assert "overlying: true" not in source

    promoter = (ROOT / "scripts" / "promote_public_release.py").read_text(
        encoding="utf-8"
    )
    demote = promoter.index('if cnb_state == "latest"')
    github_arm = promoter.index("github.arm_nonlatest")
    cnb_commit = promoter.index("github_result = github.promote_armed")
    assert demote < github_arm < cnb_commit


def test_release_plugin_is_digest_pinned_and_private_handoff_is_used():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    assert "cnbcool/attachments:latest" not in source
    assert source.count("cnbcool/attachments@sha256:") == 3
    assert "slug: yitaocn/dustmirror" in source
    assert "commit: $PRODUCT_COMMIT" in source
    assert "DustMirror-candidate-handoff-$PRODUCT_BUILD_ID.zip" in source
    assert "extract_product_candidate_handoff.py" in source
    assert "api_trigger_prepare_windows_release" not in source
    assert '--product-tree "$PRODUCT_TREE"' in source
    assert "DustMirror-publication-resume-grant-$PUBLICATION_RESUME_GRANT_ID.json" in source
    assert "DustMirror-publication-resume-grant-$PUBLICATION_RESUME_GRANT_ID.sig" in source
    assert "publication_resume_only: PUBLICATION_RESUME_ONLY" in source
    assert 'test "$PUBLIC_RELEASE_ACTION" = "resume" -o "$PUBLIC_RELEASE_ACTION" = "resume_upload"' in source
    assert source.index("verify_publication_authorization.py") < source.index(
        "Enforce that a fresh resume grant can never create a Release"
    ) < source.index("Create a non-latest prerelease")


def test_only_protected_signer_can_trigger_and_all_signed_identities_are_required():
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    assert 'test "$API_TRIGGER_REPO_SLUG" = "yitaocn/dustmirror-release-signer"' in source
    assert 'test "$API_TRIGGER_REPO_SLUG" = "yitaocn/dustmirror"' not in source
    for name in (
        "PRODUCT_VERSION",
        "PRODUCT_BUILD_ID",
        "PRODUCT_COMMIT",
        "PRODUCT_TREE",
        "PRODUCT_HANDOFF_ATTACHMENT",
        "PRODUCT_VERIFIER_EVIDENCE_ATTACHMENT",
        "PRODUCT_REQUEST_SHA256",
        "PRODUCT_RELEASE_LEDGER_COMMIT",
        "PRODUCT_RELEASE_LEDGER_TREE",
    ):
        assert name in source
    assert 'v*) normalized_version="$PRODUCT_VERSION"' in source
    assert '*) normalized_version="v$PRODUCT_VERSION"' in source
    assert "release_version: RELEASE_VERSION" in source
    assert 'test "$CNB_COMMIT" = "$PRODUCT_RELEASE_LEDGER_COMMIT"' in source
    assert 'test "$(git rev-parse \'HEAD^{tree}\')" = "$PRODUCT_RELEASE_LEDGER_TREE"' in source


def test_handoff_and_independent_verifier_archive_are_exact_name_downloaded_and_verified():
    pipeline = yaml.safe_load((ROOT / ".cnb.yml").read_text(encoding="utf-8"))
    stages = pipeline["main"]["api_trigger_publish_windows_release"][0]["stages"]
    download = next(
        stage
        for stage in stages
        if stage["name"] == "Download the exact handoff and independent verifier evidence from Product"
    )
    assert download["settings"]["commit"] == "$PRODUCT_COMMIT"
    assert download["settings"]["attachments"] == [
        "$PRODUCT_HANDOFF_ATTACHMENT",
        "$PRODUCT_VERIFIER_EVIDENCE_ATTACHMENT",
    ]
    source = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    handoff = source.index("extract_product_candidate_handoff.py")
    authorization = source.index("verify_publication_authorization.py")
    verifier = source.index("verify_product_verifier_evidence.py")
    preflight = source.index("--mode preflight")
    assert handoff < authorization < verifier < preflight
    assert '--expected-verifier-attachment "$PRODUCT_VERIFIER_EVIDENCE_ATTACHMENT"' in source
    assert "--release-gate-manifest product-verification/release-gate-manifest.json" in source


def test_release_secrets_are_stage_scoped_after_no_secret_runtime_bootstrap():
    pipeline = yaml.safe_load((ROOT / ".cnb.yml").read_text(encoding="utf-8"))
    job = pipeline["main"]["api_trigger_publish_windows_release"][0]
    assert "imports" not in job
    stages = job["stages"]
    by_name = {stage["name"]: stage for stage in stages}
    bootstrap = by_name[
        "Prepare the hash-locked verifier before importing any release secret"
    ]
    assert "imports" not in bootstrap
    assert stages.index(bootstrap) < min(
        index for index, stage in enumerate(stages) if "imports" in stage
    )
    imported = {stage["name"] for stage in stages if "imports" in stage}
    assert imported == {
        "Verify authorization and reject replay or downgrade before creating a Release",
        "Resume only the verified missing CNB attachments without overwrite",
        "Reject any missing, duplicate or extra prerelease attachment",
        "Prepare both hosts and commit the recoverable two-host promotion",
        "Read back both live latest states and the complete CNB inventory",
    }
    for stage in stages:
        if "imports" in stage:
            assert stage["imports"] == [
                "https://cnb.cool/yitaocn/dustmirror-release-secrets/-/blob/main/env.release.yml"
            ]


def test_resume_grant_download_is_optional_secretless_and_bound_to_product_commit():
    pipeline = yaml.safe_load((ROOT / ".cnb.yml").read_text(encoding="utf-8"))
    stages = pipeline["main"]["api_trigger_publish_windows_release"][0]["stages"]
    grant = next(
        stage
        for stage in stages
        if stage["name"] == "Download a fresh signed resume-only grant when explicitly requested"
    )
    assert "imports" not in grant
    assert grant["settings"]["commit"] == "$PRODUCT_COMMIT"
    assert "PUBLICATION_RESUME_GRANT_ID" in grant["if"]
    assert grant["settings"]["attachments"] == [
        "DustMirror-publication-resume-grant-$PUBLICATION_RESUME_GRANT_ID.json",
        "DustMirror-publication-resume-grant-$PUBLICATION_RESUME_GRANT_ID.sig",
    ]


def test_release_runtime_lock_is_a_complete_hash_pinned_closure():
    lock = (ROOT / "requirements-release-ci.txt").read_text(encoding="utf-8")
    assert {match.group(1) for match in re.finditer(r"(?m)^([a-z0-9-]+)==", lock)} == {
        "cryptography",
        "cffi",
        "pycparser",
    }
    assert lock.count("--hash=sha256:") >= 3
    for logical in lock.replace("\\\n", " ").splitlines():
        if logical.strip():
            assert "--hash=sha256:" in logical


def test_large_asset_download_budget_has_only_phase_one_and_final_readback():
    pipeline = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    promoter = inspect.getsource(promote_public_release.promote)
    commit = inspect.getsource(sync_github_release.promote_armed)
    # Phase 1 uses arm_nonlatest -> prepare (two downloads per asset).  The
    # commit point is metadata-only, and the one final pipeline verify performs
    # the second two-download readback.  No redundant standalone prepare/arm
    # stages or promote_latest re-arm are allowed.
    assert pipeline.count("sync_github_release.py --mode verify") == 1
    assert "--mode prepare" not in pipeline
    assert "--mode arm" not in pipeline
    assert "github.promote_armed" in promoter
    assert "github.promote_latest" not in promoter
    assert "_download_asset" not in commit
    assert "_validate_remote_assets" not in commit


def test_large_zip_io_is_streamed_with_heartbeat_and_bounded_retries():
    github_stream = inspect.getsource(sync_github_release._stream_asset_digest_once)
    cnb_stream = inspect.getsource(verify_cnb_release_inventory._stream_digest_once)
    uploader = inspect.getsource(resume_cnb_release_upload._put_file_once)
    for source in (github_stream, cnb_stream, uploader):
        assert "CHUNK_SIZE" in source
        assert "heartbeat" in source
    assert "read(CHUNK_SIZE)" in github_stream
    assert "read(CHUNK_SIZE)" in cnb_stream
    assert "read(CHUNK_SIZE)" in uploader
    assert sync_github_release.MAX_DOWNLOAD_ATTEMPTS == 3
    assert verify_cnb_release_inventory.MAX_DOWNLOAD_ATTEMPTS == 3
    assert resume_cnb_release_upload.MAX_UPLOAD_ATTEMPTS == 3
    github_upload = inspect.getsource(sync_github_release._upload_asset_once)
    github_upload_chunks = inspect.getsource(sync_github_release._upload_chunks)
    assert "_upload_chunks(path)" in github_upload
    assert "Content-Length" in github_upload
    assert "read(CHUNK_SIZE)" in github_upload_chunks
    assert "heartbeat" in github_upload_chunks
    assert sync_github_release.MAX_UPLOAD_ATTEMPTS == 3
    assert "path.read_bytes()" not in inspect.getsource(sync_github_release.prepare)
    assert "path.read_bytes()" not in inspect.getsource(sync_github_release.local_asset)


def test_release_runtime_lock_and_live_verifier_are_welded_into_pipeline():
    from scripts import verify_release_runtime

    locked = verify_release_runtime._locked_requirements(
        ROOT / "requirements-release-ci.txt"
    )
    assert set(locked) == {"cryptography", "cffi", "pycparser"}
    assert all(locked.values())
    pipeline = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
    assert "--only-binary=:all: --require-hashes" in pipeline
    assert "scripts/verify_release_runtime.py --require-venv" in pipeline
    source = inspect.getsource(verify_release_runtime)
    assert "release_runtime_record_hash_mismatch" in source
    assert "release_runtime_module_unhashed" in source
