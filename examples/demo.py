"""Offline demo: run the scanner against a canned dataset (no AWS calls).

    python examples/demo.py            # table
    python examples/demo.py json       # JSON
    python examples/demo.py csv        # CSV
    python examples/demo.py html       # self-contained HTML page
    python examples/demo.py commands   # commented-out AWS CLI commands
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

from aws_orphan_finder import output
from aws_orphan_finder.models import ScanOptions
from aws_orphan_finder.scanner import scan_regions
from aws_orphan_finder.summary import summarize

# Fixed clock so examples/sample_scan.json does not change from day to day.
NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)


def _status_filter(items, kwargs, field):
    for flt in kwargs.get("Filters") or kwargs.get("Filter") or []:
        if flt["Name"] in ("status", "state"):
            items = [i for i in items if i.get(field) in flt["Values"]]
    return items


class DemoEC2:
    def __init__(self, addresses, volumes, enis, snapshots, images=(), instances=(), nat_gateways=()):
        self._a, self._v, self._e, self._s = addresses, volumes, enis, snapshots
        self._i = list(images)
        self._inst = list(instances)
        self._nat = list(nat_gateways)

    def describe_addresses(self, **_):
        return {"Addresses": self._a}

    def describe_volumes(self, **kw):
        return {"Volumes": _status_filter(self._v, kw, "State")}

    def describe_network_interfaces(self, **kw):
        return {"NetworkInterfaces": _status_filter(self._e, kw, "Status")}

    def describe_snapshots(self, **_):
        return {"Snapshots": self._s}

    def describe_images(self, **_):
        return {"Images": self._i}

    def describe_instances(self, **_):
        return {"Reservations": [{"Instances": self._inst}]}

    def describe_launch_templates(self, **_):
        return {"LaunchTemplates": []}

    def describe_nat_gateways(self, **kw):
        return {"NatGateways": _status_filter(self._nat, kw, "State")}

    def describe_vpc_endpoint_service_configurations(self, **_):
        return {"ServiceConfigurations": []}

    def describe_vpc_endpoints(self, **_):
        return {"VpcEndpoints": []}


class DemoELBv2:
    def __init__(self, lbs):
        self._lbs = lbs

    def describe_load_balancers(self, **_):
        return {"LoadBalancers": self._lbs}

    def describe_target_groups(self, **_):
        return {"TargetGroups": []}

    def describe_listeners(self, **_):
        return {"Listeners": [{"ListenerArn": "l-1", "DefaultActions": [{"Type": "forward"}]}]}

    def describe_rules(self, **_):
        return {"Rules": []}


class DemoELB:
    def describe_load_balancers(self, **_):
        return {"LoadBalancerDescriptions": []}


class DemoCloudWatch:
    # NAT gateway metrics are published even at zero.
    def get_metric_statistics(self, **kw):
        if kw["Namespace"] == "AWS/NATGateway":
            return {"Datapoints": [{"Sum": 0.0}]}
        return {"Datapoints": []}


DATA = {
    "eu-west-1": DemoEC2(
        addresses=[
            {"AllocationId": "eipalloc-0a1b", "PublicIp": "52.10.1.2"},
            {
                "AllocationId": "eipalloc-0c2d",
                "PublicIp": "52.10.3.4",
                "InstanceId": "i-0stopped",
                "AssociationId": "eipassoc-0c2d",
            },
        ],
        volumes=[
            {
                "VolumeId": "vol-0abc",
                "State": "available",
                "Size": 200,
                "VolumeType": "gp3",
                "CreateTime": NOW - timedelta(days=120),
                "Tags": [{"Key": "Name", "Value": "leftover-data"}],
            },
            {
                "VolumeId": "vol-0root",
                "State": "in-use",
                "Size": 30,
                "VolumeType": "gp3",
                "Attachments": [{"InstanceId": "i-0stopped", "State": "attached"}],
            },
        ],
        enis=[{"NetworkInterfaceId": "eni-0aa", "Status": "available", "SubnetId": "subnet-1"}],
        snapshots=[
            {
                "SnapshotId": "snap-0xy",
                "VolumeId": "vol-0gone",
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
                "State": "available",
                "CreationDate": "2025-01-10T09:00:00.000Z",
                "LastLaunchedTime": "2025-03-02T10:15:00.000Z",
                "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-0ami", "VolumeSize": 500}}],
            }
        ],
        instances=[
            {
                "InstanceId": "i-0stopped",
                "InstanceType": "m5.large",
                "State": {"Name": "stopped"},
                "StateTransitionReason": "User initiated (2026-08-01 08:30:00 GMT)",
                "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-0root"}}],
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
        nat_gateways=[
            {
                "NatGatewayId": "nat-0idle",
                "State": "available",
                "CreateTime": NOW - timedelta(days=200),
                "SubnetId": "subnet-9",
                "VpcId": "vpc-9",
                "ConnectivityType": "public",
                "NatGatewayAddresses": [{"AllocationId": "eipalloc-0nat", "PublicIp": "3.80.0.1"}],
            }
        ],
    ),
}

SERVICES = {
    "eu-west-1": {
        "elbv2": DemoELBv2(
            [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:"
                    "loadbalancer/app/old-staging/0f1e2d3c4b5a6978",
                    "LoadBalancerName": "old-staging",
                    "Type": "application",
                    "State": {"Code": "active"},
                    "CreatedTime": NOW - timedelta(days=300),
                    "AvailabilityZones": [{"ZoneName": "eu-west-1a"}, {"ZoneName": "eu-west-1b"}],
                }
            ]
        ),
        "elb": DemoELB(),
        "cloudwatch": DemoCloudWatch(),
    },
    "us-east-1": {"elbv2": DemoELBv2([]), "elb": DemoELB(), "cloudwatch": DemoCloudWatch()},
}


def main():
    fmt = sys.argv[1] if len(sys.argv) > 1 else "table"
    findings = scan_regions(
        lambda r: DATA[r],
        list(DATA),
        NOW,
        older_than_days=30,
        service_factory=lambda r, s: SERVICES[r][s],
        options=ScanOptions(),
    )
    print(output.render(fmt, findings, summarize(findings)))


if __name__ == "__main__":
    main()
