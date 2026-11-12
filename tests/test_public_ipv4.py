from __future__ import annotations

from aws_orphan_finder import public_ipv4
from tests.conftest import FakeEC2


def _eni(eni_id, ip, **extra):
    eni = {
        "NetworkInterfaceId": eni_id,
        "Status": "in-use",
        "InterfaceType": "interface",
        "PrivateIpAddresses": [{"Association": {"PublicIp": ip, "IpOwnerId": "amazon"}}],
    }
    eni.update(extra)
    return eni


def test_counts_every_public_ip_grouped_by_owner():
    ec2 = FakeEC2(
        enis=[
            _eni("eni-inst", "1.0.0.1", Attachment={"InstanceId": "i-1"}),
            _eni("eni-nat", "1.0.0.2", InterfaceType="natGateway", RequesterManaged=True),
            _eni("eni-alb", "1.0.0.3", Description="ELB app/web/123", RequesterManaged=True),
            _eni("eni-rds", "1.0.0.4", Description="RDSNetworkInterface", RequesterManaged=True),
            # private-only ENI: no cost
            {"NetworkInterfaceId": "eni-private", "PrivateIpAddresses": [{}]},
        ],
        addresses=[
            {"AllocationId": "eipalloc-nat", "PublicIp": "1.0.0.2", "NetworkInterfaceId": "eni-nat",
             "PublicIpv4Pool": "amazon"},
            {"AllocationId": "eipalloc-idle", "PublicIp": "1.0.0.9", "PublicIpv4Pool": "amazon"},
        ],
        subnets=[
            {"SubnetId": "subnet-pub", "VpcId": "vpc-1", "MapPublicIpOnLaunch": True},
            {"SubnetId": "subnet-priv", "VpcId": "vpc-1", "MapPublicIpOnLaunch": False},
        ],
    )
    report = public_ipv4.scan_public_ipv4(lambda r: ec2, ["us-east-1"], errors=[])
    summary = report["summary"]
    assert summary["total_addresses"] == 5
    assert summary["total_monthly_cost"] == round(5 * 3.65, 2)
    assert {k: v["count"] for k, v in summary["by_owner"].items()} == {
        "instance": 1,
        "nat_gateway": 1,
        "load_balancer": 1,
        "rds": 1,
        "unattached_eip": 1,
    }
    types = {a["public_ip"]: a["address_type"] for a in report["addresses"]}
    assert types["1.0.0.1"] == "auto_assigned"
    assert types["1.0.0.2"] == "elastic_ip"
    assert report["auto_assign_subnets"] == [
        {"region": "us-east-1", "subnet_id": "subnet-pub", "vpc_id": "vpc-1"}
    ]


def test_secondary_ips_and_byoip():
    ec2 = FakeEC2(
        enis=[
            {
                "NetworkInterfaceId": "eni-1",
                "Attachment": {"InstanceId": "i-1"},
                "PrivateIpAddresses": [
                    {"Association": {"PublicIp": "2.0.0.1"}},
                    {"Association": {"PublicIp": "2.0.0.2", "AllocationId": "eipalloc-b"}},
                ],
                "Association": {"PublicIp": "2.0.0.1"},
            }
        ],
        addresses=[{"AllocationId": "eipalloc-b", "PublicIp": "2.0.0.2", "PublicIpv4Pool": "ipv4pool-ec2-x"}],
    )
    report = public_ipv4.scan_public_ipv4(lambda r: ec2, ["us-east-1"], errors=[])
    costs = {a["public_ip"]: (a["address_type"], a["monthly_cost"]) for a in report["addresses"]}
    assert costs == {"2.0.0.1": ("auto_assigned", 3.65), "2.0.0.2": ("byoip", 0.0)}


def test_failed_region_is_reported_not_counted_as_zero():
    good = FakeEC2(enis=[_eni("eni-1", "3.0.0.1", Attachment={"InstanceId": "i-1"})])
    bad = FakeEC2(fail={"describe_subnets": "AccessDenied"})
    errors = []
    report = public_ipv4.scan_public_ipv4(
        lambda r: {"us-east-1": good, "eu-west-1": bad}[r], ["us-east-1", "eu-west-1"], errors
    )
    assert report["summary"]["total_addresses"] == 1
    assert [(e.region, e.kind, e.code) for e in errors] == [("eu-west-1", "public_ipv4", "AccessDenied")]
