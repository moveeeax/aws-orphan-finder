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


# A chain this long whose oldest snapshot is this old looks like a schedule
# that creates and never prunes. A heuristic: the API does not say whether a
# retention rule exists, only what is left.
_UNPRUNED_MIN_SNAPSHOTS = 30
_UNPRUNED_MIN_AGE_DAYS = 90


def group_snapshots(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Collapse snapshot findings into one row per (region, source volume).

    Snapshots with no source volume (copies, or volumes AWS no longer names)
    share a group with `volume_id` None.
    """
    groups: Dict[Any, Dict[str, Any]] = {}
    for f in findings:
        if f.kind != "snapshot":
            continue
        volume_id = f.detail.get("volume_id")
        g = groups.setdefault(
            (f.region, volume_id),
            {
                "region": f.region,
                "volume_id": volume_id,
                "source_volume_exists": f.detail.get("source_volume_exists"),
                "count": 0,
                "monthly_cost": 0.0,
                "oldest_age_days": None,
                "newest_age_days": None,
                "snapshot_ids": [],
            },
        )
        g["count"] += 1
        g["monthly_cost"] += f.monthly_cost
        g["snapshot_ids"].append(f.resource_id)
        age = f.detail.get("age_days")
        if age is not None:
            g["oldest_age_days"] = age if g["oldest_age_days"] is None else max(g["oldest_age_days"], age)
            g["newest_age_days"] = age if g["newest_age_days"] is None else min(g["newest_age_days"], age)
    out = []
    for g in groups.values():
        g["monthly_cost"] = round(g["monthly_cost"], 2)
        g["possible_unpruned_retention"] = bool(
            g["volume_id"]
            and g["count"] >= _UNPRUNED_MIN_SNAPSHOTS
            and (g["oldest_age_days"] or 0) >= _UNPRUNED_MIN_AGE_DAYS
        )
        out.append(g)
    return sorted(out, key=lambda g: (-g["monthly_cost"], g["region"], g["volume_id"] or ""))
