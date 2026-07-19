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
