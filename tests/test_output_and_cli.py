from __future__ import annotations

import json
from datetime import timedelta

from aws_orphan_finder import cli, output
from aws_orphan_finder.models import Finding
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
