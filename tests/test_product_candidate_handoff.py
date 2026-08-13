from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

import pytest

from scripts import extract_product_candidate_handoff as handoff


VERSION = "1.3.27"
TAG = f"v{VERSION}"
BUILD = "candidate-1"
COMMIT = "a" * 40
TREE = "b" * 40


def _archive(tmp_path: Path, *, extra: str = "", build_id: str = BUILD) -> Path:
    path = tmp_path / handoff.archive_name(BUILD)
    approval = {
        "schema": "dustmirror.pre-tag-candidate/v1", "status": "passed",
        "version": VERSION, "build_id": build_id, "product_commit": COMMIT,
        "product_tree": TREE,
    }
    authorization = {
        "schema": "dustmirror.publication-authorization.v1",
        "tag": TAG,
        "cnb_build_id": build_id,
        "product_commit": COMMIT,
        "product_tree": TREE,
    }
    with zipfile.ZipFile(path, "w") as zipped:
        for name in handoff.full_inventory(VERSION):
            if name == "candidate-approved.json":
                content = json.dumps(approval).encode()
            elif name == "publication-authorization.json":
                content = json.dumps(authorization).encode()
            else:
                content = name.encode()
            zipped.writestr(name, content)
        if extra:
            zipped.writestr(extra, b"no")
    return path


def _args(archive: Path, output: Path) -> argparse.Namespace:
    return argparse.Namespace(
        archive=archive, output_directory=output, tag=TAG,
        product_build_id=BUILD, product_commit=COMMIT, product_tree=TREE,
    )


def test_extracts_exactly_the_eight_public_files(tmp_path: Path) -> None:
    output = tmp_path / "output"
    result = handoff.extract(_args(_archive(tmp_path), output))
    assert result == {"status": "extracted", "file_count": 8}
    assert {item.name for item in output.iterdir()} == handoff.public_inventory(VERSION)


def test_rejects_extra_member_and_path_traversal(tmp_path: Path) -> None:
    for extra in ("unexpected.txt", "../escape.txt"):
        case = tmp_path / extra.replace("/", "_").replace(".", "x")
        case.mkdir()
        with pytest.raises(handoff.HandoffError, match="handoff_(inventory|member|path)_invalid"):
            handoff.extract(_args(_archive(case, extra=extra), case / "output"))
        assert not (tmp_path / "escape.txt").exists()


def test_rejects_wrong_product_build_binding(tmp_path: Path) -> None:
    with pytest.raises(handoff.HandoffError, match="candidate_approval_identity_mismatch"):
        handoff.extract(_args(_archive(tmp_path, build_id="other-build"), tmp_path / "output"))


def test_rejects_wrong_product_tree_binding(tmp_path: Path) -> None:
    args = _args(_archive(tmp_path), tmp_path / "output")
    args.product_tree = "c" * 40
    with pytest.raises(handoff.HandoffError, match="candidate_approval_identity_mismatch"):
        handoff.extract(args)


def test_pipeline_consumes_only_the_single_product_handoff() -> None:
    pipeline = (Path(__file__).resolve().parents[1] / ".cnb.yml").read_text(encoding="utf-8")
    download = pipeline.index("Download the build-bound private handoff")
    extract = pipeline.index("Safely extract only the authorized public files")
    verify = pipeline.index("Verify authorization and reject replay")
    assert download < extract < verify
    assert pipeline.count("DustMirror-candidate-handoff-$PRODUCT_BUILD_ID.zip") >= 3
    block = pipeline[download:extract]
    assert "manifest.json" not in block
    assert "DustMirror-$RELEASE_VERSION-FREE-win64.zip" not in block
    assert '--product-tree "$PRODUCT_TREE"' in pipeline
    assert "ota-legacy-1.2.14-evidence.json" in handoff.CONTROL_FILES
    assert "ota-legacy-1.2.14-evidence.sig" in handoff.CONTROL_FILES


def test_archive_filename_is_strictly_bound_to_expected_build_id(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    wrong = archive.with_name(handoff.archive_name("other-build"))
    archive.rename(wrong)
    with pytest.raises(handoff.HandoffError, match="handoff_archive_invalid"):
        handoff.extract(_args(wrong, tmp_path / "output"))
