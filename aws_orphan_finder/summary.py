from __future__ import annotations

from typing import Any, Dict, List

from .models import Finding


def summarize(findings: List[Finding]) -> Dict[str, Any]:
    """Aggregate findings by region and by kind, plus grand totals."""
    by_region: Dict[str, Dict[str, Any]] = {}
    by_kind: Dict[str, Dict[str, Any]] = {}
    total_cost = 0.0

    for f in findings:
        total_cost += f.monthly_cost

        r = by_region.setdefault(f.region, {"count": 0, "monthly_cost": 0.0})
        r["count"] += 1
        r["monthly_cost"] += f.monthly_cost

        k = by_kind.setdefault(f.kind, {"count": 0, "monthly_cost": 0.0})
        k["count"] += 1
        k["monthly_cost"] += f.monthly_cost

    for bucket in (by_region, by_kind):
        for v in bucket.values():
            v["monthly_cost"] = round(v["monthly_cost"], 2)

    return {
        "total_findings": len(findings),
        "total_monthly_cost": round(total_cost, 2),
        "by_region": by_region,
        "by_kind": by_kind,
    }
