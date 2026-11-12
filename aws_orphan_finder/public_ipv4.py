"""Public IPv4 spend report (`scan --public-ipv4`).

Since 2024-02-01 AWS bills every public IPv4 address, in use or idle, at the
same hourly rate. The orphan checks only see idle Elastic IPs; most of the
money is in addresses that are in use: auto-assigned instance IPs, NAT
gateways, load balancer nodes. This report counts all of them.

It is not a list of waste, so nothing here goes into the findings or their
totals. It answers "where does the IPv4 bill come from".
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from . import pricing
from ._aws import CheckFailed, call, paginate
from .models import ScanError

# InterfaceType values (DescribeNetworkInterfaces) that name their owner.
_OWNER_BY_INTERFACE_TYPE = {
    "natGateway": "nat_gateway",
    "network_load_balancer": "load_balancer",
    "gateway_load_balancer": "load_balancer",
    "load_balancer": "load_balancer",
    "global_accelerator_managed": "global_accelerator",
    "vpc_endpoint": "vpc_endpoint",
    "api_gateway_managed": "api_gateway",
    "lambda": "lambda",
    "transit_gateway": "transit_gateway",
}


def classify_owner(eni: Dict[str, Any]) -> str:
    """Best-effort owner of a network interface, for grouping the bill."""
    itype = eni.get("InterfaceType") or "interface"
    if itype in _OWNER_BY_INTERFACE_TYPE:
        return _OWNER_BY_INTERFACE_TYPE[itype]
    description = eni.get("Description") or ""
    # ALB and CLB nodes use plain "interface" ENIs owned by amazon-elb with an
    # "ELB app/..." or "ELB <name>" description.
    if description.startswith("ELB "):
        return "load_balancer"
    if description == "RDSNetworkInterface":
        return "rds"
    if (eni.get("Attachment") or {}).get("InstanceId") and not eni.get("RequesterManaged"):
        return "instance"
    return "other"


def _public_ips(eni: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every public IPv4 association on an ENI, primary and secondary."""
    seen: Dict[str, Dict[str, Any]] = {}
    for private in eni.get("PrivateIpAddresses") or []:
        assoc = private.get("Association") or {}
        if assoc.get("PublicIp"):
            seen.setdefault(assoc["PublicIp"], assoc)
    assoc = eni.get("Association") or {}
    if assoc.get("PublicIp"):
        seen.setdefault(assoc["PublicIp"], assoc)
    return list(seen.values())


def scan_region_public_ipv4(ec2: Any, region: str) -> Dict[str, Any]:
    """Public IPv4 addresses in one region, plus subnets that hand them out."""
    addresses = paginate(ec2.describe_addresses, "Addresses", "DescribeAddresses")
    pool_by_ip = {a.get("PublicIp"): a.get("PublicIpv4Pool") for a in addresses}
    enis = paginate(
        ec2.describe_network_interfaces, "NetworkInterfaces", "DescribeNetworkInterfaces"
    )
    subnets = paginate(ec2.describe_subnets, "Subnets", "DescribeSubnets")

    rows: List[Dict[str, Any]] = []
    seen_ips = set()
    for eni in enis:
        owner = classify_owner(eni)
        for assoc in _public_ips(eni):
            ip = assoc["PublicIp"]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            pool = pool_by_ip.get(ip)
            byoip = bool(pool) and pool != "amazon"
            is_eip = bool(assoc.get("AllocationId")) or ip in pool_by_ip
            rows.append(
                {
                    "region": region,
                    "public_ip": ip,
                    "owner": owner,
                    "address_type": "byoip" if byoip else ("elastic_ip" if is_eip else "auto_assigned"),
                    "network_interface_id": eni.get("NetworkInterfaceId"),
                    "instance_id": (eni.get("Attachment") or {}).get("InstanceId"),
                    "description": eni.get("Description", ""),
                    "monthly_cost": round(pricing.public_ipv4_monthly(region, byoip=byoip), 2),
                }
            )
    # Elastic IPs on no interface bill too; they are the eip findings.
    for addr in addresses:
        ip = addr.get("PublicIp")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        pool = addr.get("PublicIpv4Pool")
        byoip = bool(pool) and pool != "amazon"
        rows.append(
            {
                "region": region,
                "public_ip": ip,
                "owner": "unattached_eip" if not addr.get("InstanceId") else "instance",
                "address_type": "byoip" if byoip else "elastic_ip",
                "network_interface_id": addr.get("NetworkInterfaceId"),
                "instance_id": addr.get("InstanceId"),
                "description": "",
                "monthly_cost": round(pricing.public_ipv4_monthly(region, byoip=byoip), 2),
            }
        )

    auto_assign = [
        {"region": region, "subnet_id": s.get("SubnetId"), "vpc_id": s.get("VpcId")}
        for s in subnets
        if s.get("MapPublicIpOnLaunch")
    ]
    return {"addresses": rows, "auto_assign_subnets": auto_assign}


def summarize_public_ipv4(addresses: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_owner: Dict[str, Dict[str, Any]] = {}
    by_region: Dict[str, Dict[str, Any]] = {}
    total = 0.0
    for row in addresses:
        total += row["monthly_cost"]
        for bucket, key in ((by_owner, row["owner"]), (by_region, row["region"])):
            agg = bucket.setdefault(key, {"count": 0, "monthly_cost": 0.0})
            agg["count"] += 1
            agg["monthly_cost"] += row["monthly_cost"]
    for bucket in (by_owner, by_region):
        for agg in bucket.values():
            agg["monthly_cost"] = round(agg["monthly_cost"], 2)
    return {
        "total_addresses": len(addresses),
        "total_monthly_cost": round(total, 2),
        "by_owner": by_owner,
        "by_region": by_region,
    }


def scan_public_ipv4(
    client_factory: Callable[[str], Any],
    regions: List[str],
    errors: Optional[List[ScanError]] = None,
) -> Dict[str, Any]:
    """Run the public IPv4 report over several regions.

    A region whose listing fails contributes nothing and is recorded as a
    skipped `public_ipv4` check, so the total is never silently understated.
    """
    addresses: List[Dict[str, Any]] = []
    subnets: List[Dict[str, Any]] = []
    for region in regions:
        try:
            ec2 = call(lambda: client_factory(region), "CreateClient")
            part = scan_region_public_ipv4(ec2, region)
        except CheckFailed as exc:
            if errors is None:
                raise
            errors.append(
                ScanError(
                    region=region,
                    kind="public_ipv4",
                    operation=exc.operation,
                    code=exc.code,
                    message=exc.message,
                )
            )
            continue
        addresses.extend(part["addresses"])
        subnets.extend(part["auto_assign_subnets"])
    return {
        "summary": summarize_public_ipv4(addresses),
        "addresses": addresses,
        "auto_assign_subnets": subnets,
    }
