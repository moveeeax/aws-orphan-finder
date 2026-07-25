from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict


@dataclass(frozen=True)
class Finding:
    """A single orphaned resource and its estimated monthly cost."""

    region: str
    kind: str  # one of: eip, ebs_volume, eni, snapshot
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
    kind: str  # which check was skipped: eip, ebs_volume, eni, snapshot, region
    operation: str  # the AWS API call that failed, e.g. DescribeImages
    code: str  # AWS error code, e.g. AccessDenied / RequestLimitExceeded
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
