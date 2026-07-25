from __future__ import annotations

import argparse
import json
from datetime import timedelta

import pytest

from aws_orphan_finder import cli, output
from aws_orphan_finder.models import Finding, ScanError
from aws_orphan_finder.summary import summarize
from tests.conftest import FakeEC2


def _sample_findings():
    return [
        Finding("us-east-1", "eip", "eipalloc-1", 3.65, "idle EIP", {"public_ip": "1.2.3.4"}),
        Finding("eu-west-1", "ebs_volume", "vol-1", 8.0, "available", {"size_gb": 100}),
    ]


def test_summary_totals():
    s = summarize(_sample_findings())
    assert s["total_findings"] == 2
    assert s["total_monthly_cost"] == 11.65
    assert s["by_region"]["us-east-1"]["count"] == 1
    assert s["by_kind"]["ebs_volume"]["monthly_cost"] == 8.0


def test_render_json_roundtrip():
    findings = _sample_findings()
    out = output.render("json", findings, summarize(findings))
    data = json.loads(out)
    assert len(data["findings"]) == 2
    assert data["summary"]["total_monthly_cost"] == 11.65


def test_render_csv_has_header_and_rows():
    findings = _sample_findings()
    out = output.render("csv", findings, summarize(findings))
    lines = out.strip().splitlines()
    assert lines[0] == "region,kind,resource_id,monthly_cost,reason,detail"
    assert len(lines) == 3


def test_render_table_contains_total():
    findings = _sample_findings()
    out = output.render("table", findings, summarize(findings))
    assert "TOTAL" in out
    assert "eipalloc-1" in out


def test_parse_duration_days():
    assert cli.parse_duration_days("30d") == 30
    assert cli.parse_duration_days("2w") == 14
    assert cli.parse_duration_days("3m") == 90
    assert cli.parse_duration_days("45") == 45


def test_parse_regions():
    assert cli.parse_regions("eu-west-1, us-east-1") == ["eu-west-1", "us-east-1"]


def test_parse_regions_deduplicates():
    """A repeated region would double every finding and double the cost total."""
    assert cli.parse_regions("us-east-1,us-east-1,eu-west-1") == ["us-east-1", "eu-west-1"]


def test_parse_regions_accepts_other_partitions():
    assert cli.parse_regions("us-gov-west-1,cn-north-1") == ["us-gov-west-1", "cn-north-1"]


@pytest.mark.parametrize("bad", ["us_east_1", "useast1", "Europe", "us-east-", "../etc"])
def test_parse_regions_rejects_malformed(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_regions(bad)


def test_render_json_always_carries_errors_key():
    findings = _sample_findings()
    data = json.loads(output.render("json", findings, summarize(findings)))
    assert data["errors"] == []


def test_render_table_marks_an_incomplete_scan():
    errors = [ScanError("us-east-1", "snapshot", "DescribeImages", "AccessDenied", "nope")]
    out = output.render("table", [], summarize([]), errors)
    assert "INCOMPLETE SCAN" in out
    assert "AccessDenied" in out


def test_cli_exits_nonzero_when_a_check_was_skipped(capsys, now):
    """A partial scan must not look like a clean bill of health to a script."""
    fake = FakeEC2(
        snapshots=[{"SnapshotId": "snap-1", "VolumeSize": 10, "StartTime": now}],
        fail={"describe_images": "AccessDenied"},
    )
    rc = cli.main(
        ["scan", "--regions", "us-east-1", "--output", "json"],
        client_factory=lambda r: fake,
    )
    captured = capsys.readouterr()
    assert rc == cli.EXIT_INCOMPLETE
    data = json.loads(captured.out)
    assert data["findings"] == []
    assert data["errors"][0]["code"] == "AccessDenied"
    assert "incomplete" in captured.err


def test_cli_ignore_errors_restores_zero_exit(capsys, now):
    fake = FakeEC2(
        snapshots=[{"SnapshotId": "snap-1", "VolumeSize": 10, "StartTime": now}],
        fail={"describe_images": "AccessDenied"},
    )
    rc = cli.main(
        ["scan", "--regions", "us-east-1", "--output", "json", "--ignore-errors"],
        client_factory=lambda r: fake,
    )
    assert rc == 0
    assert "incomplete" in capsys.readouterr().err


def test_cli_end_to_end_json(capsys, now):
    fake = FakeEC2(
        addresses=[{"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4"}],
        volumes=[
            {
                "VolumeId": "vol-1",
                "State": "available",
                "Size": 100,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=90),
            }
        ],
    )
    rc = cli.main(
        ["scan", "--regions", "us-east-1", "--older-than", "30d", "--output", "json"],
        client_factory=lambda r: fake,
    )
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    ids = {f["resource_id"] for f in data["findings"]}
    assert ids == {"eipalloc-1", "vol-1"}
    assert data["summary"]["total_monthly_cost"] > 0
