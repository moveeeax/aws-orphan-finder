"""Offline demo: run the scanner against a canned dataset (no AWS calls).

    python examples/demo.py            # table
    python examples/demo.py json       # JSON
    python examples/demo.py csv        # CSV
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

from aws_orphan_finder import output
from aws_orphan_finder.scanner import scan_regions
from aws_orphan_finder.summary import summarize

NOW = datetime.now(timezone.utc)


class DemoEC2:
    def __init__(self, addresses, volumes, enis, snapshots, images=()):
        self._a, self._v, self._e, self._s = addresses, volumes, enis, snapshots
        self._i = list(images)

    def describe_addresses(self, **_):
        return {"Addresses": self._a}

    def describe_volumes(self, **_):
        return {"Volumes": self._v}

    def describe_network_interfaces(self, **_):
        return {"NetworkInterfaces": self._e}

    def describe_snapshots(self, **_):
        return {"Snapshots": self._s}

    def describe_images(self, **_):
        return {"Images": self._i}


DATA = {
    "eu-west-1": DemoEC2(
        addresses=[{"AllocationId": "eipalloc-0a1b", "PublicIp": "52.10.1.2"}],
        volumes=[
            {
                "VolumeId": "vol-0abc",
                "State": "available",
                "Size": 200,
                "VolumeType": "gp3",
                "CreateTime": NOW - timedelta(days=120),
                "Tags": [{"Key": "Name", "Value": "leftover-data"}],
            }
        ],
        enis=[{"NetworkInterfaceId": "eni-0aa", "Status": "available", "SubnetId": "subnet-1"}],
        snapshots=[
            {
                "SnapshotId": "snap-0xy",
                "VolumeSize": 200,
                "State": "completed",
                "StartTime": NOW - timedelta(days=400),
            },
            # Old, but it backs a registered AMI -- must NOT be reported.
            {
                "SnapshotId": "snap-0ami",
                "VolumeSize": 500,
                "State": "completed",
                "StartTime": NOW - timedelta(days=500),
            },
        ],
        images=[
            {
                "ImageId": "ami-0abc",
                "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-0ami"}}],
            }
        ],
    ),
    "us-east-1": DemoEC2(
        addresses=[],
        volumes=[
            {
                "VolumeId": "vol-0def",
                "State": "available",
                "Size": 50,
                "VolumeType": "gp2",
                "CreateTime": NOW - timedelta(days=60),
            }
        ],
        enis=[],
        snapshots=[],
    ),
}


def main():
    fmt = sys.argv[1] if len(sys.argv) > 1 else "table"
    findings = scan_regions(lambda r: DATA[r], list(DATA), NOW, older_than_days=30)
    print(output.render(fmt, findings, summarize(findings)))


if __name__ == "__main__":
    main()
