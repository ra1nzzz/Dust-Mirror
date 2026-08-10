from __future__ import annotations

import pytest

from scripts.verify_cnb_release_inventory import _asset_names


def test_inventory_names_are_complete_and_unique():
    assert _asset_names({"assets": [{"name": "a.zip"}, {"asset_name": "manifest.json"}]}) == ["a.zip", "manifest.json"]


def test_inventory_rejects_missing_name():
    with pytest.raises(ValueError, match="asset_name_invalid"):
        _asset_names({"assets": [{"size": 1}]})
