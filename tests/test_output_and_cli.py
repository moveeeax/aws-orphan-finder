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


def test_render_table_treats_bracketed_values_as_plain_text():
    """`output.render` is public API: a caller can hand it any Finding, and a
    bracketed field must never be parsed as Rich console markup. Before this
    was fixed, a mismatched tag like "[/mismatched]" raised
    rich.errors.MarkupError and crashed rendering outright; a well-formed one
    like "[bold]x[/bold]" would silently apply formatting and strip the tags
    instead of showing the literal resource text.
    """
    findings = [
        Finding(
            "us-east-1",
            "eip",
            "[/mismatched]",
            1.0,
            "reason with [bold]brackets[/bold] in it",
        ),
    ]
    out = output.render("table", findings, summarize(findings))
    assert "[/mismatched]" in out
    assert "reason with [bold]brackets[/bold] in it" in out


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


def test_default_client_factory_sets_bounded_timeouts(monkeypatch):
    """A network-level failure (blackholed endpoint, dropped SYN, a region
    that never answers) must not hang a scan for botocore's full default of
    60s connect + 60s read times up to 10 retry attempts. The client config
    needs its own bounded connect/read timeouts, not just a retry count.
    """
    import boto3

    captured = {}

    class FakeSession:
        def __init__(self, profile_name=None):
            captured["profile_name"] = profile_name

        def client(self, service, region_name=None, config=None):
            captured["service"] = service
            captured["region_name"] = region_name
            captured["config"] = config
            return "fake-client"

    monkeypatch.setattr(boto3, "Session", FakeSession)

    factory = cli._default_client_factory(None)
    client = factory("us-east-1")

    assert client == "fake-client"
    assert captured["service"] == "ec2"
    assert captured["region_name"] == "us-east-1"
    config = captured["config"]
    assert config.connect_timeout is not None
    assert config.read_timeout is not None
    # Bounded, not merely "set to something huge".
    assert config.connect_timeout <= 15
    assert config.read_timeout <= 60


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


def _snapshot_chain(n, volume_id="vol-1", exists=False):
    return [
        Finding(
            "us-east-1",
            "snapshot",
            f"snap-{i}",
            0.5,
            "retained",
            {"volume_id": volume_id, "source_volume_exists": exists, "age_days": 100 + i},
        )
        for i in range(n)
    ]


def test_group_by_volume_collapses_a_chain_into_one_row():
    findings = _snapshot_chain(40) + _sample_findings()
    out = output.render("table", findings, summarize(findings), group_by="volume")
    assert "snap-0" not in out
    assert "40 snapshots, 100-139 days old" in out
    assert "source volume deleted" in out
    assert "retention that never prunes" in out
    data = json.loads(output.render("json", findings, summarize(findings), group_by="volume"))
    group = data["snapshot_groups"][0]
    assert group["volume_id"] == "vol-1"
    assert group["count"] == 40
    assert group["monthly_cost"] == 20.0
    assert group["possible_unpruned_retention"] is True
    # Findings stay per snapshot: they are the deletion candidate list.
    assert len([f for f in data["findings"] if f["kind"] == "snapshot"]) == 40


def test_short_chain_is_not_called_unpruned():
    findings = _snapshot_chain(3)
    data = json.loads(output.render("json", findings, summarize(findings), group_by="volume"))
    assert data["snapshot_groups"][0]["possible_unpruned_retention"] is False


def test_render_html_escapes_values_and_marks_incomplete():
    findings = [Finding("us-east-1", "eip", "<script>x</script>", 1.0, "a & b")]
    errors = [ScanError("us-east-1", "snapshot", "DescribeImages", "AccessDenied", "nope")]
    out = output.render("html", findings, summarize(findings), errors)
    assert out.startswith("<!doctype html>")
    assert "<script>" not in out
    assert "&lt;script&gt;x&lt;/script&gt;" in out
    assert "a &amp; b" in out
    assert "Incomplete scan" in out


def test_render_commands_are_all_commented_out():
    findings = [
        Finding("us-east-1", "eip", "eipalloc-1", 3.65, "idle"),
        Finding("us-east-1", "snapshot", "snap-1", 1.0, "old"),
        Finding("us-east-1", "nat_gateway", "nat-1", 36.5, "idle",
                {"allocation_ids": ["eipalloc-n"]}),
        Finding("us-east-1", "load_balancer", "web", 16.4, "idle",
                {"type": "application", "arn": "arn:aws:elasticloadbalancing:x"}),
        Finding("us-east-1", "load_balancer", "old-clb", 18.2, "idle", {"type": "classic"}),
        Finding("us-east-1", "eip_stopped_instance", "eipalloc-2", 3.65, "stopped",
                {"association_id": "eipassoc-2"}),
    ]
    out = output.render("commands", findings, summarize(findings))
    lines = [l for l in out.splitlines() if l.strip()]
    assert all(l.startswith("#") for l in lines)
    assert "# aws ec2 release-address --region us-east-1 --allocation-id eipalloc-1" in out
    assert "# aws ec2 delete-snapshot --region us-east-1 --snapshot-id snap-1" in out
    assert "# aws ec2 delete-nat-gateway --region us-east-1 --nat-gateway-id nat-1" in out
    assert "# aws ec2 release-address --region us-east-1 --allocation-id eipalloc-n" in out
    assert "--load-balancer-arn arn:aws:elasticloadbalancing:x" in out
    assert "# aws elb delete-load-balancer --region us-east-1 --load-balancer-name old-clb" in out
    assert "disassociate-address --region us-east-1 --association-id eipassoc-2" in out


def test_cli_public_ipv4_flag_adds_report(capsys):
    fake = FakeEC2(
        enis=[{"NetworkInterfaceId": "eni-1", "Attachment": {"InstanceId": "i-1"},
               "PrivateIpAddresses": [{"Association": {"PublicIp": "4.4.4.4"}}]}],
    )
    rc = cli.main(
        ["scan", "--regions", "us-east-1", "--output", "json", "--public-ipv4"],
        client_factory=lambda r: fake,
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["public_ipv4"]["summary"]["by_owner"]["instance"]["count"] == 1
    # In-use addresses are spend, not waste: they stay out of the findings.
    assert data["findings"] == []


def test_cli_without_public_ipv4_has_no_report_key(capsys):
    rc = cli.main(
        ["scan", "--regions", "us-east-1", "--output", "json"], client_factory=lambda r: FakeEC2()
    )
    assert rc == 0
    assert "public_ipv4" not in json.loads(capsys.readouterr().out)


def test_cli_passes_idle_thresholds_to_load_balancer_check(capsys, now):
    from datetime import datetime, timezone
    from tests.conftest import FakeCloudWatch, FakeELBv2, service_factory

    created = datetime.now(timezone.utc) - timedelta(days=40)
    lb = {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/n/1",
        "LoadBalancerName": "n",
        "Type": "network",
        "State": {"Code": "active"},
        "CreatedTime": created,
        "_target_groups": [{"_targets": ["healthy"]}],
    }
    cw = FakeCloudWatch({"net/n/1": 500})
    factory = service_factory(elbv2=FakeELBv2([lb]), cloudwatch=cw)
    argv = ["scan", "--regions", "us-east-1", "--output", "json"]

    cli.main(argv, client_factory=lambda r: FakeEC2(), service_factory=factory)
    assert json.loads(capsys.readouterr().out)["findings"] == []

    cli.main(
        argv + ["--lb-lookback", "30d", "--lb-min-traffic", "1000"],
        client_factory=lambda r: FakeEC2(),
        service_factory=factory,
    )
    data = json.loads(capsys.readouterr().out)
    assert [f["kind"] for f in data["findings"]] == ["load_balancer"]
    assert data["findings"][0]["detail"]["lookback_days"] == 30


@pytest.mark.parametrize("bad", ["-1", "abc"])
def test_min_traffic_rejects_bad_values(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_positive_float(bad)


def test_lookback_must_be_positive():
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_lookback_days("0")


def test_default_client_factory_builds_other_services(monkeypatch):
    import boto3

    services = []

    class FakeSession:
        def __init__(self, profile_name=None):
            pass

        def client(self, service, region_name=None, config=None):
            services.append(service)
            return service

    monkeypatch.setattr(boto3, "Session", FakeSession)
    factory = cli._default_client_factory(None)
    assert factory("us-east-1", "elbv2") == "elbv2"
    assert factory("us-east-1", "cloudwatch") == "cloudwatch"
    assert services == ["elbv2", "cloudwatch"]
