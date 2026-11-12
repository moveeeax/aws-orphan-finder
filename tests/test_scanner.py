from __future__ import annotations

from datetime import timedelta

import pytest
from botocore.exceptions import ClientError

from aws_orphan_finder import scanner
from aws_orphan_finder.models import ScanError
from tests.conftest import FakeEC2


def test_scan_eips_only_unattached(now):
    ec2 = FakeEC2(
        addresses=[
            {"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4"},  # orphan
            {"AllocationId": "eipalloc-2", "PublicIp": "5.6.7.8", "AssociationId": "assoc-x"},
        ]
    )
    findings = scanner.scan_eips(ec2, "us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == "eipalloc-1"
    assert findings[0].kind == "eip"
    assert findings[0].monthly_cost > 0


def test_scan_eips_in_use_without_association_id(now):
    """An EIP bound to an instance or ENI is in use even with no AssociationId."""
    ec2 = FakeEC2(
        addresses=[
            {"AllocationId": "eipalloc-instance", "PublicIp": "1.1.1.1", "InstanceId": "i-123"},
            {"AllocationId": "eipalloc-eni", "PublicIp": "2.2.2.2", "NetworkInterfaceId": "eni-1"},
            {"AllocationId": "eipalloc-idle", "PublicIp": "3.3.3.3"},
        ]
    )
    findings = scanner.scan_eips(ec2, "us-east-1")
    assert [f.resource_id for f in findings] == ["eipalloc-idle"]


def test_scan_volumes_available_and_age_filter(now):
    ec2 = FakeEC2(
        volumes=[
            {
                "VolumeId": "vol-old",
                "State": "available",
                "Size": 100,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=40),
            },
            {
                "VolumeId": "vol-new",
                "State": "available",
                "Size": 8,
                "VolumeType": "gp2",
                "CreateTime": now - timedelta(days=5),
            },
            {"VolumeId": "vol-attached", "State": "in-use", "Size": 50, "VolumeType": "gp3"},
        ]
    )
    # no age filter -> both available volumes
    all_avail = scanner.scan_volumes(ec2, "us-east-1", now)
    assert {f.resource_id for f in all_avail} == {"vol-old", "vol-new"}

    # older-than 30d -> only vol-old
    old = scanner.scan_volumes(ec2, "us-east-1", now, older_than_days=30)
    assert [f.resource_id for f in old] == ["vol-old"]
    assert old[0].detail["age_days"] == 40
    # 100GB gp3 @ 0.08 = 8.00 in us-east-1
    assert round(old[0].monthly_cost, 2) == 8.00


def test_scan_enis_detached(now):
    ec2 = FakeEC2(
        enis=[
            {"NetworkInterfaceId": "eni-1", "Status": "available", "SubnetId": "subnet-a"},
            {"NetworkInterfaceId": "eni-2", "Status": "in-use", "SubnetId": "subnet-b"},
        ]
    )
    findings = scanner.scan_enis(ec2, "us-east-1")
    assert [f.resource_id for f in findings] == ["eni-1"]
    assert findings[0].monthly_cost == 0.0


def test_scan_snapshots_age_filter(now):
    ec2 = FakeEC2(
        snapshots=[
            {"SnapshotId": "snap-old", "VolumeSize": 200, "StartTime": now - timedelta(days=120)},
            {"SnapshotId": "snap-new", "VolumeSize": 10, "StartTime": now - timedelta(days=3)},
        ]
    )
    stale = scanner.scan_snapshots(ec2, "us-east-1", now, older_than_days=90)
    assert [f.resource_id for f in stale] == ["snap-old"]
    # 200GB @ 0.05 = 10.00
    assert round(stale[0].monthly_cost, 2) == 10.00


def test_scan_region_aggregates_all_kinds(now):
    ec2 = FakeEC2(
        addresses=[{"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4"}],
        volumes=[
            {
                "VolumeId": "vol-1",
                "State": "available",
                "Size": 10,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=1),
            }
        ],
        enis=[{"NetworkInterfaceId": "eni-1", "Status": "available"}],
        snapshots=[{"SnapshotId": "snap-1", "VolumeSize": 5, "StartTime": now - timedelta(days=1)}],
    )
    findings = scanner.scan_region(ec2, "us-east-1", now)
    kinds = sorted(f.kind for f in findings)
    assert kinds == ["ebs_volume", "eip", "eni", "snapshot"]


def test_scan_regions_multi_region_aggregation(now):
    def vol(vid):
        return {"VolumeId": vid, "State": "available", "Size": 100, "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=1)}

    data = {
        "eu-west-1": FakeEC2(volumes=[vol("vol-eu")]),
        "us-east-1": FakeEC2(volumes=[vol("vol-us")]),
    }
    findings = scanner.scan_regions(lambda r: data[r], ["eu-west-1", "us-east-1"], now)
    assert {f.region for f in findings} == {"eu-west-1", "us-east-1"}
    # eu-west-1 multiplier (1.05) makes its EBS cost higher than us-east-1 (1.0)
    eu = next(f for f in findings if f.region == "eu-west-1")
    us = next(f for f in findings if f.region == "us-east-1")
    assert eu.monthly_cost > us.monthly_cost


def test_public_ipv4_rate_is_the_same_in_every_region(now):
    """AWS charges $0.005/h per public IPv4 in all commercial regions."""
    data = {
        "sa-east-1": FakeEC2(addresses=[{"AllocationId": "a1", "PublicIp": "1.1.1.1"}]),
        "us-east-1": FakeEC2(addresses=[{"AllocationId": "a2", "PublicIp": "2.2.2.2"}]),
    }
    findings = scanner.scan_regions(lambda r: data[r], ["sa-east-1", "us-east-1"], now)
    assert {round(f.monthly_cost, 2) for f in findings} == {3.65}


def test_byoip_elastic_ip_costs_nothing(now):
    ec2 = FakeEC2(
        addresses=[{"AllocationId": "a1", "PublicIp": "1.1.1.1", "PublicIpv4Pool": "ipv4pool-ec2-1"}]
    )
    findings = scanner.scan_eips(ec2, "us-east-1")
    assert findings[0].monthly_cost == 0.0
    assert findings[0].detail["public_ipv4_pool"] == "ipv4pool-ec2-1"


def test_never_mutates(now):
    ec2 = FakeEC2(addresses=[{"AllocationId": "a1", "PublicIp": "1.1.1.1"}])
    scanner.scan_region(ec2, "us-east-1", now)
    assert ec2.mutating_calls == []


# --- false-positive guards -------------------------------------------------


def test_volume_with_live_attachment_is_not_reported(now):
    """A volume still carrying an attachment is in use, whatever its status."""
    ec2 = FakeEC2(
        volumes=[
            {
                "VolumeId": "vol-detaching",
                "State": "available",
                "Size": 100,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=40),
                "Attachments": [{"InstanceId": "i-123", "State": "detaching"}],
            },
            {
                "VolumeId": "vol-idle",
                "State": "available",
                "Size": 100,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=40),
            },
        ]
    )
    findings = scanner.scan_volumes(ec2, "us-east-1", now)
    assert [f.resource_id for f in findings] == ["vol-idle"]


def test_eni_with_live_attachment_is_not_reported(now):
    ec2 = FakeEC2(
        enis=[
            {
                "NetworkInterfaceId": "eni-attached",
                "Status": "available",
                "Attachment": {"AttachmentId": "eni-attach-1", "InstanceId": "i-1"},
            },
            {"NetworkInterfaceId": "eni-idle", "Status": "available"},
        ]
    )
    findings = scanner.scan_enis(ec2, "us-east-1")
    assert [f.resource_id for f in findings] == ["eni-idle"]


def test_eni_requester_managed_is_flagged_in_detail(now):
    ec2 = FakeEC2(
        enis=[
            {
                "NetworkInterfaceId": "eni-lambda",
                "Status": "available",
                "RequesterManaged": True,
                "RequesterId": "amazon-aws",
            }
        ]
    )
    findings = scanner.scan_enis(ec2, "us-east-1")
    assert findings[0].detail["requester_managed"] is True
    assert "reclaim via that service" in findings[0].reason


def test_snapshot_backing_an_ami_is_not_reported(now):
    """The backing snapshot of a registered AMI is in use, not waste."""
    ec2 = FakeEC2(
        snapshots=[
            {
                "SnapshotId": "snap-ami",
                "VolumeSize": 100,
                "State": "completed",
                "StartTime": now - timedelta(days=400),
            },
            {
                "SnapshotId": "snap-orphan",
                "VolumeSize": 100,
                "State": "completed",
                "StartTime": now - timedelta(days=400),
            },
        ],
        images=[
            {
                "ImageId": "ami-1",
                "BlockDeviceMappings": [
                    {"Ebs": {"SnapshotId": "snap-ami"}},
                    {"VirtualName": "ephemeral0"},  # no Ebs key
                ],
            }
        ],
    )
    findings = scanner.scan_snapshots(ec2, "us-east-1", now)
    assert [f.resource_id for f in findings] == ["snap-orphan"]


def test_snapshot_still_pending_is_not_reported(now):
    ec2 = FakeEC2(
        snapshots=[
            {
                "SnapshotId": "snap-pending",
                "VolumeSize": 100,
                "State": "pending",
                "StartTime": now - timedelta(days=1),
            },
            {
                "SnapshotId": "snap-done",
                "VolumeSize": 100,
                "State": "completed",
                "StartTime": now - timedelta(days=1),
            },
        ]
    )
    findings = scanner.scan_snapshots(ec2, "us-east-1", now)
    assert [f.resource_id for f in findings] == ["snap-done"]


# --- errors must never masquerade as "nothing found" -----------------------


def test_access_denied_on_describe_images_skips_the_whole_snapshot_check(now):
    """The critical case: no AMI cross-reference means no snapshot verdict.

    Falling back to "no AMIs exist" would report every image-backing snapshot
    as deletable waste, which is the worst false positive this tool can emit.
    """
    ec2 = FakeEC2(
        snapshots=[
            {
                "SnapshotId": "snap-ami",
                "VolumeSize": 100,
                "State": "completed",
                "StartTime": now - timedelta(days=400),
            }
        ],
        images=[{"ImageId": "ami-1", "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-ami"}}]}],
        fail={"describe_images": "AccessDenied"},
    )
    errors = []
    findings = scanner.scan_region(ec2, "us-east-1", now, errors=errors)

    assert [f.kind for f in findings if f.kind == "snapshot"] == []
    # The AMI check reads DescribeImages too, so it is skipped alongside.
    assert [(e.kind, e.code, e.operation) for e in errors] == [
        ("snapshot", "AccessDenied", "DescribeImages"),
        ("ami", "AccessDenied", "DescribeImages"),
    ]


def test_one_failed_check_does_not_suppress_the_others(now):
    ec2 = FakeEC2(
        addresses=[{"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4"}],
        volumes=[
            {
                "VolumeId": "vol-1",
                "State": "available",
                "Size": 10,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=1),
            }
        ],
        fail={"describe_network_interfaces": "RequestLimitExceeded"},
    )
    errors = []
    findings = scanner.scan_region(ec2, "us-east-1", now, errors=errors)
    assert {f.kind for f in findings} == {"eip", "ebs_volume"}
    assert [(e.kind, e.code) for e in errors] == [("eni", "RequestLimitExceeded")]


def test_errors_propagate_when_no_collector_is_supplied(now):
    """Legacy callers that pass no `errors` list still get a loud failure."""
    ec2 = FakeEC2(fail={"describe_addresses": "AccessDenied"})
    with pytest.raises(scanner.CheckFailed) as exc:
        scanner.scan_region(ec2, "us-east-1", now)
    assert exc.value.code == "AccessDenied"


def test_failed_region_does_not_abort_remaining_regions(now):
    good = FakeEC2(addresses=[{"AllocationId": "a2", "PublicIp": "2.2.2.2"}])

    def factory(region):
        if region == "eu-west-1":
            raise ClientError(
                {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}}, "CreateClient"
            )
        return good

    errors = []
    findings = scanner.scan_regions(factory, ["eu-west-1", "us-east-1"], now, errors=errors)
    assert [f.region for f in findings] == ["us-east-1"]
    assert [(e.region, e.kind) for e in errors] == [("eu-west-1", "region")]


def test_pagination_failure_does_not_return_a_partial_page(now):
    """A mid-pagination failure must not yield the first page as the answer."""

    class FlakyEC2(FakeEC2):
        def describe_volumes(self, **kwargs):
            if kwargs.get("NextToken"):
                raise ClientError(
                    {"Error": {"Code": "RequestLimitExceeded", "Message": "slow down"}},
                    "DescribeVolumes",
                )
            return {"Volumes": [self.volumes[0]], "NextToken": "page2"}

    ec2 = FlakyEC2(
        volumes=[
            {
                "VolumeId": "vol-1",
                "State": "available",
                "Size": 10,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=1),
            },
            {
                "VolumeId": "vol-2",
                "State": "available",
                "Size": 10,
                "VolumeType": "gp3",
                "CreateTime": now - timedelta(days=1),
            },
        ]
    )
    errors = []
    findings = scanner.scan_region(ec2, "us-east-1", now, errors=errors)
    assert [f for f in findings if f.kind == "ebs_volume"] == []
    assert [(e.kind, e.code) for e in errors] == [("ebs_volume", "RequestLimitExceeded")]


def test_scan_error_is_serialisable():
    e = ScanError("us-east-1", "snapshot", "DescribeImages", "AccessDenied", "nope")
    assert e.to_dict()["code"] == "AccessDenied"


# --- stopped instances (#8) and EIPs on them (#6) --------------------------


def _stopped(instance_id, stopped_days_ago, now, volumes=(), reason=None):
    stopped_at = now - timedelta(days=stopped_days_ago)
    return {
        "InstanceId": instance_id,
        "InstanceType": "t3.large",
        "State": {"Name": "stopped"},
        "StateTransitionReason": reason
        if reason is not None
        else f"User initiated ({stopped_at:%Y-%m-%d %H:%M:%S} GMT)",
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": v}} for v in volumes],
    }


def test_stopped_instance_reports_volume_cost_and_eip_separately(now):
    ec2 = FakeEC2(
        instances=[
            _stopped("i-stopped", 45, now, volumes=["vol-root", "vol-data"]),
            {"InstanceId": "i-running", "State": {"Name": "running"}},
        ],
        volumes=[
            {"VolumeId": "vol-root", "State": "in-use", "Size": 20, "VolumeType": "gp3",
             "Attachments": [{"InstanceId": "i-stopped"}]},
            {"VolumeId": "vol-data", "State": "in-use", "Size": 100, "VolumeType": "gp2",
             "Attachments": [{"InstanceId": "i-stopped"}]},
        ],
        addresses=[
            {"AllocationId": "eipalloc-s", "PublicIp": "9.9.9.9", "InstanceId": "i-stopped",
             "AssociationId": "eipassoc-1"},
            {"AllocationId": "eipalloc-r", "PublicIp": "8.8.8.8", "InstanceId": "i-running"},
        ],
    )
    findings = scanner.scan_stopped_instances(ec2, "us-east-1", now, older_than_days=30)
    by_kind = {f.kind: f for f in findings}
    assert set(by_kind) == {"stopped_instance", "eip_stopped_instance"}

    inst = by_kind["stopped_instance"]
    assert inst.resource_id == "i-stopped"
    # 20 GiB gp3 @ 0.08 + 100 GiB gp2 @ 0.10 = 1.60 + 10.00
    assert round(inst.monthly_cost, 2) == 11.60
    assert "vol-root (20 GiB gp3)" in inst.reason
    assert "vol-data (100 GiB gp2)" in inst.reason
    assert "9.9.9.9" in inst.reason
    assert inst.detail["age_days"] == 45

    eip = by_kind["eip_stopped_instance"]
    assert eip.resource_id == "eipalloc-s"
    assert round(eip.monthly_cost, 2) == 3.65
    assert "i-stopped" in eip.reason and "stopped since" in eip.reason
    # The EIP of the running instance is in use and not reported anywhere.
    assert all(f.detail.get("public_ip") != "8.8.8.8" for f in findings)


def test_stopped_instance_honours_older_than(now):
    ec2 = FakeEC2(instances=[_stopped("i-recent", 3, now), _stopped("i-old", 60, now)])
    findings = scanner.scan_stopped_instances(ec2, "us-east-1", now, older_than_days=30)
    assert [f.resource_id for f in findings] == ["i-old"]


def test_stopped_instance_with_unreadable_stop_time_needs_no_age_filter(now):
    """Unknown age is not old age: with --older-than it is skipped."""
    ec2 = FakeEC2(instances=[_stopped("i-x", 0, now, reason="")])
    assert scanner.scan_stopped_instances(ec2, "us-east-1", now, older_than_days=30) == []
    findings = scanner.scan_stopped_instances(ec2, "us-east-1", now)
    assert [f.resource_id for f in findings] == ["i-x"]
    assert findings[0].detail["age_days"] is None


def test_stopped_instance_check_failure_is_isolated(now):
    ec2 = FakeEC2(
        addresses=[{"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4"}],
        fail={"describe_instances": "UnauthorizedOperation"},
    )
    errors = []
    findings = scanner.scan_region(ec2, "us-east-1", now, errors=errors)
    assert [f.kind for f in findings] == ["eip"]
    assert [(e.kind, e.operation) for e in errors] == [("stopped_instance", "DescribeInstances")]


# --- AMIs and snapshot sprawl (#5) ------------------------------------------


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def test_unused_ami_is_reported_with_backing_snapshot_cost(now):
    ec2 = FakeEC2(
        images=[
            {
                "ImageId": "ami-stale",
                "State": "available",
                "CreationDate": _iso(now - timedelta(days=400)),
                "LastLaunchedTime": _iso(now - timedelta(days=200)),
                "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-a", "VolumeSize": 30}}],
            },
            {
                "ImageId": "ami-fresh",
                "State": "available",
                "CreationDate": _iso(now - timedelta(days=400)),
                "LastLaunchedTime": _iso(now - timedelta(days=5)),
            },
            {
                "ImageId": "ami-never",
                "State": "available",
                "CreationDate": _iso(now - timedelta(days=120)),
            },
            {
                "ImageId": "ami-new",
                "State": "available",
                "CreationDate": _iso(now - timedelta(days=10)),
            },
        ]
    )
    findings = scanner.scan_amis(ec2, "us-east-1", now, unused_days=90)
    assert {f.resource_id for f in findings} == {"ami-stale", "ami-never"}
    stale = next(f for f in findings if f.resource_id == "ami-stale")
    assert stale.detail["age_days"] == 200
    assert stale.detail["snapshot_ids"] == ["snap-a"]
    assert round(stale.monthly_cost, 2) == 1.50  # 30 GB @ 0.05
    never = next(f for f in findings if f.resource_id == "ami-never")
    assert "no recorded launch" in never.reason


def test_ami_in_a_launch_template_is_not_reported(now):
    ec2 = FakeEC2(
        images=[
            {"ImageId": "ami-asg", "State": "available",
             "CreationDate": _iso(now - timedelta(days=400))},
        ],
        launch_templates={"lt-1": [{"LaunchTemplateData": {"ImageId": "ami-asg"}}]},
    )
    assert scanner.scan_amis(ec2, "us-east-1", now, unused_days=90) == []


def test_ami_check_fails_whole_if_launch_templates_cannot_be_read(now):
    ec2 = FakeEC2(
        images=[{"ImageId": "ami-1", "State": "available",
                 "CreationDate": _iso(now - timedelta(days=400))}],
        fail={"describe_launch_templates": "AccessDenied"},
    )
    errors = []
    findings = scanner.scan_region(ec2, "us-east-1", now, errors=errors)
    assert [f for f in findings if f.kind == "ami"] == []
    assert [(e.kind, e.operation) for e in errors] == [("ami", "DescribeLaunchTemplates")]


def test_snapshot_detail_names_source_volume_and_whether_it_exists(now):
    ec2 = FakeEC2(
        volumes=[{"VolumeId": "vol-live", "State": "in-use", "Size": 10}],
        snapshots=[
            {"SnapshotId": "snap-1", "VolumeId": "vol-live", "VolumeSize": 10,
             "State": "completed", "StartTime": now - timedelta(days=10)},
            {"SnapshotId": "snap-2", "VolumeId": "vol-gone", "VolumeSize": 10,
             "State": "completed", "StartTime": now - timedelta(days=10)},
            {"SnapshotId": "snap-3", "VolumeId": "vol-ffffffff", "VolumeSize": 10,
             "State": "completed", "StartTime": now - timedelta(days=10),
             "Description": "[Copied snap-0abc from us-east-1]"},
        ],
    )
    findings = {f.resource_id: f for f in scanner.scan_snapshots(ec2, "eu-west-1", now)}
    assert findings["snap-1"].detail["source_volume_exists"] is True
    assert "no longer exists" not in findings["snap-1"].reason
    assert findings["snap-2"].detail["source_volume_exists"] is False
    assert "source volume vol-gone no longer exists" in findings["snap-2"].reason
    copy = findings["snap-3"]
    assert copy.detail["volume_id"] is None
    assert copy.detail["copied_from"] == {"snapshot_id": "snap-0abc", "region": "us-east-1"}
    assert "cross-region copy of snap-0abc from us-east-1" in copy.reason
