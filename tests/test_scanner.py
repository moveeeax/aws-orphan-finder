from __future__ import annotations

from datetime import timedelta

from aws_orphan_finder import scanner
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
