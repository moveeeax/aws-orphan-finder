from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict


@dataclass(frozen=True)
class Finding:
    """A single orphaned resource and its estimated monthly cost."""

    region: str
    # one of: eip, ebs_volume, eni, snapshot, ami, stopped_instance,
    # eip_stopped_instance, load_balancer, nat_gateway
    kind: str
    resource_id: str
    monthly_cost: float
    reason: str
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["monthly_cost"] = round(self.monthly_cost, 2)
        return d


@dataclass(frozen=True)
class ScanError:
    """A check that could not be completed, and was therefore reported as nothing.

    This exists so a failed API call is never silently rendered as "no orphans
    here". A scan that could not read AMIs, for example, must not conclude that
    every snapshot is unreferenced -- it must say the snapshot check was skipped.
    """

    region: str
    kind: str  # which check was skipped: a Finding kind, public_ipv4, or region
    operation: str  # the AWS API call that failed, e.g. DescribeImages
    code: str  # AWS error code, e.g. AccessDenied / RequestLimitExceeded
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanOptions:
    """Thresholds for the checks that judge idleness rather than attachment.

    idle_lookback_days: CloudWatch window for load balancer and NAT gateway
        traffic. A resource younger than this is never reported.
    idle_min_traffic: traffic sum over that window below which a resource is
        idle (requests for ALB/CLB, new flows for NLB/GWLB, packets out for NAT).
    ami_unused_days: an AMI not launched (or, if never launched, not created)
        within this many days is reported.
    """

    idle_lookback_days: int = 14
    idle_min_traffic: float = 100.0
    ami_unused_days: int = 90
