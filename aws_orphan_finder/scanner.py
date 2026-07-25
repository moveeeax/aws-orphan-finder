from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import pricing
from .models import Finding, ScanError

try:  # botocore ships with boto3, which is a hard dependency
    from botocore.exceptions import BotoCoreError, ClientError

    _AWS_ERRORS: Tuple[type, ...] = (BotoCoreError, ClientError)
except ImportError:  # pragma: no cover - only if botocore is unavailable
    _AWS_ERRORS = ()

# Type of the client factory: given a region, return an object exposing the
# EC2 describe_* calls used below. Injectable so tests can supply fakes and the
# production path can hand back a real boto3 client.
ClientFactory = Callable[[str], Any]

# An EIP is in use if any of these is set. AssociationId alone is not enough:
# an address attached to an EC2-Classic instance reports InstanceId with no
# AssociationId, and checking only AssociationId would call it orphaned.
_EIP_IN_USE_FIELDS = ("AssociationId", "InstanceId", "NetworkInterfaceId")

# Only a completed snapshot is idle storage. A pending one is still being
# written (its source is actively in use) and an errored one bills nothing.
_SNAPSHOT_READY_STATE = "completed"


class CheckFailed(Exception):
    """A check could not be completed, so it must report nothing at all.

    Reporting an empty or partial result for a failed check is precisely how a
    false positive is manufactured: an AccessDenied on DescribeImages would
    otherwise make every AMI-backed snapshot look unreferenced, and the tool
    would recommend deleting the backing store of live machine images.
    """

    def __init__(self, operation: str, code: str, message: str) -> None:
        super().__init__(f"{operation}: {code}: {message}")
        self.operation = operation
        self.code = code
        self.message = message


def _error_parts(exc: BaseException) -> Tuple[str, str]:
    """Pull (code, message) out of a botocore exception as best we can."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        err = response.get("Error") or {}
        if isinstance(err, dict) and err.get("Code"):
            return str(err["Code"]), str(err.get("Message") or exc)
    return exc.__class__.__name__, str(exc)


def _call(fn: Callable[..., Any], operation: str, **kwargs: Any) -> Any:
    """Invoke one AWS call, converting any AWS-side failure into CheckFailed.

    Throttling (RequestLimitExceeded) is retried inside botocore via the client
    config; if it still surfaces here the check is abandoned rather than being
    reported as an empty result.
    """
    try:
        return fn(**kwargs)
    except _AWS_ERRORS as exc:  # type: ignore[misc]
        code, message = _error_parts(exc)
        raise CheckFailed(operation, code, message) from exc


def _paginate(
    fn: Callable[..., Dict[str, Any]], key: str, operation: str, **kwargs: Any
) -> List[Dict[str, Any]]:
    """Follow NextToken pagination for a describe_* call, collecting `key`.

    Every page must succeed. A failure part-way through raises rather than
    returning the pages gathered so far -- a truncated listing of *attachments*
    is what turns an in-use resource into a reported orphan.
    """
    items: List[Dict[str, Any]] = []
    token: Optional[str] = None
    seen_tokens: Set[str] = set()
    while True:
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        resp = _call(fn, operation, **params)
        items.extend(resp.get(key, []) or [])
        token = resp.get("NextToken")
        if not token:
            break
        if token in seen_tokens:
            # A server repeating a token would otherwise spin forever.
            raise CheckFailed(operation, "PaginationLoop", "NextToken repeated by the API")
        seen_tokens.add(token)
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
    """Elastic IPs not associated with an instance, interface or association."""
    findings: List[Finding] = []
    addresses = _paginate(ec2.describe_addresses, "Addresses", "DescribeAddresses")
    for addr in addresses:
        if any(addr.get(f) for f in _EIP_IN_USE_FIELDS):
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
        "DescribeVolumes",
        Filters=[{"Name": "status", "Values": ["available"]}],
    )
    for v in vols:
        # Re-check client-side: a volume mid-detach can come back with an
        # Attachments entry, and a volume that is still attached is not waste.
        if v.get("State", "available") != "available":
            continue
        if v.get("Attachments"):
            continue
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
        "DescribeNetworkInterfaces",
        Filters=[{"Name": "status", "Values": ["available"]}],
    )
    for eni in enis:
        if eni.get("Status", "available") != "available":
            continue
        if eni.get("Attachment"):
            continue
        requester_managed = bool(eni.get("RequesterManaged"))
        detail: Dict[str, Any] = {
            "description": eni.get("Description", ""),
            "subnet_id": eni.get("SubnetId"),
            "requester_managed": requester_managed,
        }
        requester_id = eni.get("RequesterId")
        if requester_id:
            detail["requester_id"] = requester_id
        reason = "Network interface is detached (available)"
        if requester_managed:
            # e.g. a leaked Lambda/VPC-endpoint ENI. Real waste, but the owning
            # service should reclaim it -- deleting it by hand can break things.
            reason += "; managed by an AWS service, reclaim via that service"
        findings.append(
            Finding(
                region=region,
                kind="eni",
                resource_id=eni.get("NetworkInterfaceId", "unknown"),
                monthly_cost=pricing.eni_monthly(region),
                reason=reason,
                detail=detail,
            )
        )
    return findings


def ami_backed_snapshot_ids(ec2: Any) -> Set[str]:
    """Snapshot IDs referenced by a block device mapping of a self-owned AMI.

    These are emphatically not orphans: they are the backing store of a
    registered image. Raises CheckFailed if the images cannot be listed.
    """
    images = _paginate(ec2.describe_images, "Images", "DescribeImages", Owners=["self"])
    in_use: Set[str] = set()
    for img in images:
        for bdm in img.get("BlockDeviceMappings", []) or []:
            snapshot_id = (bdm.get("Ebs") or {}).get("SnapshotId")
            if snapshot_id:
                in_use.add(snapshot_id)
    return in_use


def scan_snapshots(
    ec2: Any, region: str, now: datetime, older_than_days: Optional[int] = None
) -> List[Finding]:
    """Self-owned EBS snapshots that no self-owned AMI depends on.

    The AMI lookup happens first and on purpose: if it fails the whole check
    fails, because a snapshot list with no AMI cross-reference would flag every
    image-backing snapshot as deletable waste.
    """
    in_use = ami_backed_snapshot_ids(ec2)
    findings: List[Finding] = []
    snaps = _paginate(ec2.describe_snapshots, "Snapshots", "DescribeSnapshots", OwnerIds=["self"])
    for s in snaps:
        snapshot_id = s.get("SnapshotId", "unknown")
        if snapshot_id in in_use:
            continue
        if s.get("State", _SNAPSHOT_READY_STATE) != _SNAPSHOT_READY_STATE:
            continue
        age = _age_days(s.get("StartTime"), now)
        if older_than_days is not None and (age is None or age < older_than_days):
            continue
        size = s.get("VolumeSize", 0)
        detail = {"size_gb": size, "age_days": age, "description": s.get("Description", "")}
        findings.append(
            Finding(
                region=region,
                kind="snapshot",
                resource_id=snapshot_id,
                monthly_cost=pricing.snapshot_monthly(region, size),
                reason="EBS snapshot retained, not referenced by any self-owned AMI"
                + (f" ({age} days old)" if age is not None else ""),
                detail=detail,
            )
        )
    return findings


def _run_check(
    kind: str,
    region: str,
    check: Callable[[], List[Finding]],
    errors: Optional[List[ScanError]],
) -> List[Finding]:
    """Run one check; on failure record it and yield nothing for that kind.

    With `errors=None` the exception propagates, preserving the pre-0.2
    behaviour for library callers that did not opt into error collection.
    """
    try:
        return check()
    except CheckFailed as exc:
        if errors is None:
            raise
        errors.append(
            ScanError(
                region=region,
                kind=kind,
                operation=exc.operation,
                code=exc.code,
                message=exc.message,
            )
        )
        return []


def scan_region(
    ec2: Any,
    region: str,
    now: Optional[datetime] = None,
    older_than_days: Optional[int] = None,
    errors: Optional[List[ScanError]] = None,
) -> List[Finding]:
    """Run every orphan check against a single region's EC2 client.

    Pass `errors` to collect checks that had to be skipped instead of raising.
    A skipped check contributes no findings -- never a silent empty result.
    """
    now = now or datetime.now(timezone.utc)
    findings: List[Finding] = []
    findings.extend(_run_check("eip", region, lambda: scan_eips(ec2, region), errors))
    findings.extend(
        _run_check(
            "ebs_volume", region, lambda: scan_volumes(ec2, region, now, older_than_days), errors
        )
    )
    findings.extend(_run_check("eni", region, lambda: scan_enis(ec2, region), errors))
    findings.extend(
        _run_check(
            "snapshot", region, lambda: scan_snapshots(ec2, region, now, older_than_days), errors
        )
    )
    return findings


def scan_regions(
    client_factory: ClientFactory,
    regions: List[str],
    now: Optional[datetime] = None,
    older_than_days: Optional[int] = None,
    errors: Optional[List[ScanError]] = None,
) -> List[Finding]:
    """Scan multiple regions and aggregate every finding.

    One unreachable or unauthorised region is recorded and skipped rather than
    aborting the remaining regions, provided `errors` is supplied.
    """
    now = now or datetime.now(timezone.utc)
    all_findings: List[Finding] = []
    for region in regions:
        try:
            ec2 = _call(lambda: client_factory(region), "CreateClient")
        except CheckFailed as exc:
            if errors is None:
                raise
            errors.append(
                ScanError(
                    region=region,
                    kind="region",
                    operation=exc.operation,
                    code=exc.code,
                    message=exc.message,
                )
            )
            continue
        all_findings.extend(scan_region(ec2, region, now, older_than_days, errors))
    return all_findings
