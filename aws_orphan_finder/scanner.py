from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from . import pricing
from .models import Finding

# Type of the client factory: given a region, return an object exposing the
# EC2 describe_* calls used below. Injectable so tests can supply fakes and the
# production path can hand back a real boto3 client.
ClientFactory = Callable[[str], Any]


def _paginate(fn: Callable[..., Dict[str, Any]], key: str, **kwargs: Any) -> List[Dict[str, Any]]:
    """Follow NextToken pagination for a describe_* call, collecting `key`."""
    items: List[Dict[str, Any]] = []
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        resp = fn(**params)
        items.extend(resp.get(key, []) or [])
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _name_tag(tags: Optional[List[Dict[str, str]]]) -> Optional[str]:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value")
    return None


def _age_days(created: Optional[datetime], now: datetime) -> Optional[int]:
    if created is None:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return int((now - created).total_seconds() // 86400)


def scan_eips(ec2: Any, region: str) -> List[Finding]:
    """Unattached Elastic IPs (no AssociationId)."""
    findings: List[Finding] = []
    for addr in ec2.describe_addresses().get("Addresses", []) or []:
        if addr.get("AssociationId"):
            continue
        rid = addr.get("AllocationId") or addr.get("PublicIp", "unknown")
        detail: Dict[str, Any] = {"public_ip": addr.get("PublicIp")}
        name = _name_tag(addr.get("Tags"))
        if name:
            detail["name"] = name
        findings.append(
            Finding(
                region=region,
                kind="eip",
                resource_id=rid,
                monthly_cost=pricing.eip_monthly(region),
                reason="Elastic IP not associated with any instance or interface",
                detail=detail,
            )
        )
    return findings


def scan_volumes(
    ec2: Any, region: str, now: datetime, older_than_days: Optional[int] = None
) -> List[Finding]:
    """EBS volumes in the `available` (unattached) state."""
    findings: List[Finding] = []
    vols = _paginate(
        ec2.describe_volumes,
        "Volumes",
        Filters=[{"Name": "status", "Values": ["available"]}],
    )
    for v in vols:
        age = _age_days(v.get("CreateTime"), now)
        if older_than_days is not None and (age is None or age < older_than_days):
            continue
        size = v.get("Size", 0)
        vtype = v.get("VolumeType", "gp2")
        detail = {"size_gb": size, "volume_type": vtype, "age_days": age}
        name = _name_tag(v.get("Tags"))
        if name:
            detail["name"] = name
        findings.append(
            Finding(
                region=region,
                kind="ebs_volume",
                resource_id=v.get("VolumeId", "unknown"),
                monthly_cost=pricing.ebs_volume_monthly(region, vtype, size),
                reason="EBS volume is available (not attached to any instance)",
                detail=detail,
            )
        )
    return findings


def scan_enis(ec2: Any, region: str) -> List[Finding]:
    """Network interfaces in the `available` (detached) state."""
    findings: List[Finding] = []
    enis = _paginate(
        ec2.describe_network_interfaces,
        "NetworkInterfaces",
        Filters=[{"Name": "status", "Values": ["available"]}],
    )
    for eni in enis:
        detail = {
            "description": eni.get("Description", ""),
            "subnet_id": eni.get("SubnetId"),
        }
        findings.append(
            Finding(
                region=region,
                kind="eni",
                resource_id=eni.get("NetworkInterfaceId", "unknown"),
                monthly_cost=pricing.eni_monthly(region),
                reason="Network interface is detached (available)",
                detail=detail,
            )
        )
    return findings


def scan_snapshots(
    ec2: Any, region: str, now: datetime, older_than_days: Optional[int] = None
) -> List[Finding]:
    """Self-owned EBS snapshots, optionally filtered to those older than N days."""
    findings: List[Finding] = []
    snaps = _paginate(ec2.describe_snapshots, "Snapshots", OwnerIds=["self"])
    for s in snaps:
        age = _age_days(s.get("StartTime"), now)
        if older_than_days is not None and (age is None or age < older_than_days):
            continue
        size = s.get("VolumeSize", 0)
        detail = {"size_gb": size, "age_days": age, "description": s.get("Description", "")}
        findings.append(
            Finding(
                region=region,
                kind="snapshot",
                resource_id=s.get("SnapshotId", "unknown"),
                monthly_cost=pricing.snapshot_monthly(region, size),
                reason="EBS snapshot retained"
                + (f" for {age} days" if age is not None else ""),
                detail=detail,
            )
        )
    return findings


def scan_region(
    ec2: Any, region: str, now: Optional[datetime] = None, older_than_days: Optional[int] = None
) -> List[Finding]:
    """Run every orphan check against a single region's EC2 client."""
    now = now or datetime.now(timezone.utc)
    findings: List[Finding] = []
    findings.extend(scan_eips(ec2, region))
    findings.extend(scan_volumes(ec2, region, now, older_than_days))
    findings.extend(scan_enis(ec2, region))
    findings.extend(scan_snapshots(ec2, region, now, older_than_days))
    return findings


def scan_regions(
    client_factory: ClientFactory,
    regions: List[str],
    now: Optional[datetime] = None,
    older_than_days: Optional[int] = None,
) -> List[Finding]:
    """Scan multiple regions and aggregate every finding."""
    now = now or datetime.now(timezone.utc)
    all_findings: List[Finding] = []
    for region in regions:
        ec2 = client_factory(region)
        all_findings.extend(scan_region(ec2, region, now, older_than_days))
    return all_findings
