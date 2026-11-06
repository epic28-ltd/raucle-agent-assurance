"""BUG-HUNT round 2: malformed crosswalk rows must fail named in workpaper export.

Round-2 fuzzing of the N7 workpaper exporter found raw KeyError leaks on
malformed rows — instead of the exporter's own named WorkpaperError.
"""

import pytest
from tools.grc_export.workpaper import WorkpaperError, build_workpaper, export_rows


def _row(**overrides):
    base = {
        "framework": "AIUC-1",
        "control_id": "AIUC-1-AC-1",
        "derivation": "d",
        "control_text": "t",
        "source_heading": "h",
        "source_url": "u",
        "family_heading": "f",
        "family_url": "fu",
        "status": "SUPPORTED",
    }
    base.update(overrides)
    return base


def test_row_without_control_id_is_named_not_keyerror():
    row = _row()
    del row["control_id"]
    with pytest.raises(WorkpaperError) as exc:
        export_rows({"rows": [row]})
    assert "control_id" in str(exc.value)


def test_row_without_status_is_named_not_keyerror():
    row = _row()
    del row["status"]
    with pytest.raises(WorkpaperError) as exc:
        build_workpaper(row, None, lambda packet, dotted: None)
    assert "status" in str(exc.value)


def test_non_mapping_row_is_named_not_attributeerror():
    with pytest.raises(WorkpaperError):
        export_rows({"rows": ["junk"]})


def test_crosswalk_without_rows_list_is_named():
    with pytest.raises(WorkpaperError):
        export_rows({"rows": None})
