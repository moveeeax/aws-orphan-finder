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
    data = {
        "eu-west-1": FakeEC2(addresses=[{"AllocationId": "a1", "PublicIp": "1.1.1.1"}]),
        "us-east-1": FakeEC2(addresses=[{"AllocationId": "a2", "PublicIp": "2.2.2.2"}]),
    }
    findings = scanner.scan_regions(lambda r: data[r], ["eu-west-1", "us-east-1"], now)
    assert {f.region for f in findings} == {"eu-west-1", "us-east-1"}
    # eu-west-1 multiplier (1.05) makes its EIP cost higher than us-east-1 (1.0)
    eu = next(f for f in findings if f.region == "eu-west-1")
    us = next(f for f in findings if f.region == "us-east-1")
    assert eu.monthly_cost > us.monthly_cost


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
    assert [(e.kind, e.code, e.operation) for e in errors] == [
        ("snapshot", "AccessDenied", "DescribeImages")
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
