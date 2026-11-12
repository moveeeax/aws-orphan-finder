from __future__ import annotations

HOURS_PER_MONTH = 730.0

# Public IPv4: since 2024-02-01 AWS bills $0.005 / hour for every public IPv4
# address, in use or idle, attached or not, at the same rate in every
# commercial region. https://aws.amazon.com/vpc/pricing/
# Addresses brought to AWS with BYOIP are not charged.
_PUBLIC_IPV4_HOURLY = 0.005

# Hourly charge of an idle load balancer, us-east-1, excluding LCUs (an idle
# balancer consumes next to none). Gateway Load Balancers bill per enabled
# Availability Zone. https://aws.amazon.com/elasticloadbalancing/pricing/
_LB_HOURLY = {
    "application": 0.0225,
    "network": 0.0225,
    "classic": 0.025,
}
_GWLB_HOURLY_PER_AZ = 0.0125

# NAT gateway hourly charge, excluding per-GB processing (zero for an idle
# gateway). AWS publishes $0.045 / hour in its US East pricing example.
# https://aws.amazon.com/vpc/pricing/
_NAT_GATEWAY_HOURLY = 0.045

# EBS storage price ($ per GB-month), us-east-1 baseline, by volume type.
_EBS_GB_MONTH = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}
_EBS_DEFAULT = 0.10

# EBS snapshot storage price ($ per GB-month), us-east-1 baseline.
_SNAPSHOT_GB_MONTH = 0.05

# Relative regional multiplier applied to the us-east-1 baseline. Regions not
# listed fall back to 1.0. These are deliberately coarse but let multi-region
# estimates differ in a defensible way.
_REGION_MULTIPLIER = {
    "us-east-1": 1.00,
    "us-east-2": 1.00,
    "us-west-1": 1.02,
    "us-west-2": 1.00,
    "eu-west-1": 1.05,
    "eu-west-2": 1.06,
    "eu-central-1": 1.08,
    "eu-north-1": 1.04,
    "ap-southeast-1": 1.10,
    "ap-southeast-2": 1.12,
    "ap-northeast-1": 1.11,
    "ap-south-1": 1.06,
    "sa-east-1": 1.25,
}


def region_multiplier(region: str) -> float:
    return _REGION_MULTIPLIER.get(region, 1.0)


def public_ipv4_monthly(region: str, byoip: bool = False) -> float:
    # No regional multiplier: the IPv4 rate is the same in every commercial
    # region. `region` is kept so every pricing helper has the same shape.
    if byoip:
        return 0.0
    return _PUBLIC_IPV4_HOURLY * HOURS_PER_MONTH


def eip_monthly(region: str) -> float:
    return public_ipv4_monthly(region)


def load_balancer_monthly(region: str, lb_type: str, az_count: int = 1) -> float:
    if lb_type == "gateway":
        hourly = _GWLB_HOURLY_PER_AZ * max(az_count, 1)
    else:
        hourly = _LB_HOURLY.get(lb_type, _LB_HOURLY["application"])
    return hourly * HOURS_PER_MONTH * region_multiplier(region)


def nat_gateway_monthly(region: str) -> float:
    return _NAT_GATEWAY_HOURLY * HOURS_PER_MONTH * region_multiplier(region)


def ebs_volume_monthly(region: str, volume_type: str, size_gb: float) -> float:
    per_gb = _EBS_GB_MONTH.get(volume_type, _EBS_DEFAULT)
    return per_gb * float(size_gb) * region_multiplier(region)


def snapshot_monthly(region: str, size_gb: float) -> float:
    return _SNAPSHOT_GB_MONTH * float(size_gb) * region_multiplier(region)


def eni_monthly(region: str) -> float:
    # A detached elastic network interface carries no direct charge, but it is
    # still clutter worth surfacing (and may pin an EIP). Estimated at $0.
    return 0.0
