"""Reject incomplete vmmap totals and retain no mapped names or addresses."""

import json

import pytest

from scripts.bench_guard_cigar_mapping_diagnostic import parse_summary

SUMMARY = """Path: /private/never-record-this
Physical footprint: 16M
Physical footprint (peak): 32M
MALLOC_LARGE                  1.0G 512M 256M 0K 0K 0K 0K 2
__TEXT                        16M 8M 0K 0K 0K 0K 0K 1
never-record-this-0x1234       1M 1M 0K 0K 0K 0K 0K 1
TOTAL                         2G 1G 512M 0K 0K 0K 0K 4
"""


def test_region_aggregates_convert_rounded_units_without_retaining_unknown_labels():
    report = parse_summary(SUMMARY)
    assert report["groups"]["malloc"]["resident_approx_bytes"] == 512 * 1024**2
    assert report["groups"]["malloc"]["region_count"] == 2
    assert report["malloc_types"]["MALLOC_LARGE"]["region_count"] == 2
    assert report["groups"]["other"]["region_count"] == 1
    assert report["physical_footprint_approx_bytes"] == 16 * 1024**2
    assert report["physical_footprint_peak_approx_bytes"] == 32 * 1024**2
    assert "never-record-this" not in json.dumps(report)
    assert "0x1234" not in json.dumps(report)


def test_malloc_breakdown_only_retains_fixed_os_type_names():
    report = parse_summary(SUMMARY.replace("never-record-this-0x1234", "MALLOC_never-record-this-0x1234"))
    assert set(report["malloc_types"]) == {"MALLOC_LARGE"}
    assert "never-record-this" not in json.dumps(report)


@pytest.mark.parametrize("missing", ["TOTAL", "Physical footprint:", "Physical footprint (peak):"])
def test_missing_totals_or_footprint_refuse_instead_of_inventing_zero(missing):
    altered = "\n".join(line for line in SUMMARY.splitlines() if not line.startswith(missing))
    with pytest.raises(RuntimeError):
        parse_summary(altered)
