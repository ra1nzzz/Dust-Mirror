from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import rollback_cnb_release as subject


def _state(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema": "dustmirror.cnb-release-preflight.v1",
        "tag": "v1.3.3",
        "previous_latest_tag": "v1.2.22",
        "previous_latest_id": 22,
    }), encoding="utf-8")
    return path


def test_rollback_demotes_candidate_and_restores_previous(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    calls = []

    def fake(url, token, *, method="GET", value=None, allow_missing=False):
        calls.append((url, method, value))
        if url.endswith("/tags/v1.3.3"):
            return {"id": 33, "tag_name": "v1.3.3", "body": "Product build: build-1"}
        if url.endswith("/latest"):
            return {"id": 22, "tag_name": "v1.2.22"}
        return {}

    monkeypatch.setattr(subject, "_request", fake)
    result = subject.rollback(
        endpoint="https://api.cnb.cool", repo="yitaocn/dust-mirror",
        tag="v1.3.3", product_build_id="build-1",
        state_path=_state(tmp_path / "state.json"), token="token",
    )
    assert result["status"] == "rolled_back"
    assert any(call[1:] == ("PATCH", {"draft": False, "prerelease": True, "make_latest": "false"}) for call in calls)
    assert any(call[1:] == ("PATCH", {"make_latest": "true"}) for call in calls)


def test_rollback_refuses_release_owned_by_another_build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(subject, "_request", lambda *args, **kwargs: {
        "id": 33, "tag_name": "v1.3.3", "body": "Product build: other"
    })
    with pytest.raises(ValueError, match="release_not_owned_by_product_build"):
        subject.rollback(
            endpoint="https://api.cnb.cool", repo="yitaocn/dust-mirror",
            tag="v1.3.3", product_build_id="build-1",
            state_path=_state(tmp_path / "state.json"), token="token",
        )
