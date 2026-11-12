from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from . import idle, pricing
from ._aws import CheckFailed, age_days, as_datetime, call, name_tag, paginate
from .models import Finding, ScanError, ScanOptions

# Kept under their pre-0.3 private names for callers and tests that import them.
_call = call
_paginate = paginate
_name_tag = name_tag
_age_days = age_days

# Type of the client factory: given a region, return an object exposing the
# EC2 describe_* calls used below. Injectable so tests can supply fakes and the
# production path can hand back a real boto3 client.
ClientFactory = Callable[[str], Any]

# Factory for the non-EC2 clients (elbv2, elb, cloudwatch): (region, service).
# Optional: without one, the checks that need those services are not run.
ServiceFactory = Callable[[str, str], Any]

# An EIP is in use if any of these is set. AssociationId alone is not enough:
# an address attached to an EC2-Classic instance reports InstanceId with no
# AssociationId, and checking only AssociationId would call it orphaned.
_EIP_IN_USE_FIELDS = ("AssociationId", "InstanceId", "NetworkInterfaceId")

# Only a completed snapshot is idle storage. A pending one is still being
# written (its source is actively in use) and an errored one bills nothing.
_SNAPSHOT_READY_STATE = "completed"

# CopySnapshot and CopyImage give the copy this placeholder as its VolumeId;
# it never names a real volume.
_PLACEHOLDER_VOLUME_ID = "vol-ffffffff"

# Default description CopySnapshot writes on a copy: "[Copied snap-x from us-east-1]".
_COPIED_SNAPSHOT_RE = re.compile(r"\[Copied (snap-[0-9a-f]+) from ([a-z0-9-]+)\]")

# StateTransitionReason of a stopped instance carries the stop time, e.g.
# "User initiated (2026-10-01 12:34:56 GMT)". It is the only place the EC2 API
# exposes it; there is no structured field.
_STOPPED_AT_RE = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")


def _is_byoip(addr: Dict[str, Any]) -> bool:
    """An address from a BYOIP pool is not billed the public IPv4 rate."""
    pool = addr.get("PublicIpv4Pool")
    return bool(pool) and pool != "amazon"


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
        byoip = _is_byoip(addr)
        if byoip:
            detail["public_ipv4_pool"] = addr.get("PublicIpv4Pool")
        findings.append(
            Finding(
                region=region,
                kind="eip",
                resource_id=rid,
                monthly_cost=pricing.public_ipv4_monthly(region, byoip=byoip),
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


def _source_volume(snapshot: Dict[str, Any]) -> Optional[str]:
    volume_id = snapshot.get("VolumeId")
    if not volume_id or volume_id == _PLACEHOLDER_VOLUME_ID:
        return None
    return volume_id


def scan_snapshots(
    ec2: Any, region: str, now: datetime, older_than_days: Optional[int] = None
) -> List[Finding]:
    """Self-owned EBS snapshots that no self-owned AMI depends on.

    The AMI lookup happens first and on purpose: if it fails the whole check
    fails, because a snapshot list with no AMI cross-reference would flag every
    image-backing snapshot as deletable waste. The volume listing is only used
    to say whether the source volume still exists, but it is just as
    all-or-nothing: a truncated list would claim live volumes were deleted.
    """
    in_use = ami_backed_snapshot_ids(ec2)
    findings: List[Finding] = []
    snaps = _paginate(ec2.describe_snapshots, "Snapshots", "DescribeSnapshots", OwnerIds=["self"])
    candidates = []
    for s in snaps:
        snapshot_id = s.get("SnapshotId", "unknown")
        if snapshot_id in in_use:
            continue
        if s.get("State", _SNAPSHOT_READY_STATE) != _SNAPSHOT_READY_STATE:
            continue
        age = _age_days(s.get("StartTime"), now)
        if older_than_days is not None and (age is None or age < older_than_days):
            continue
        candidates.append((s, snapshot_id, age))
    if not candidates:
        return findings

    existing_volumes = {
        v.get("VolumeId")
        for v in _paginate(ec2.describe_volumes, "Volumes", "DescribeVolumes")
    }
    for s, snapshot_id, age in candidates:
        size = s.get("VolumeSize", 0)
        description = s.get("Description", "")
        volume_id = _source_volume(s)
        detail: Dict[str, Any] = {
            "size_gb": size,
            "age_days": age,
            "description": description,
            "volume_id": volume_id,
            "source_volume_exists": volume_id in existing_volumes if volume_id else None,
        }
        reason = "EBS snapshot retained, not referenced by any self-owned AMI"
        copied = _COPIED_SNAPSHOT_RE.search(description or "")
        if copied:
            detail["copied_from"] = {"snapshot_id": copied.group(1), "region": copied.group(2)}
            if copied.group(2) != region:
                # A cross-region copy starts as a full copy of the data, not an
                # increment, so it is usually the most expensive snapshot.
                reason += f"; cross-region copy of {copied.group(1)} from {copied.group(2)}"
        elif volume_id and volume_id not in existing_volumes:
            reason += f"; source volume {volume_id} no longer exists"
        if age is not None:
            reason += f" ({age} days old)"
        findings.append(
            Finding(
                region=region,
                kind="snapshot",
                resource_id=snapshot_id,
                monthly_cost=pricing.snapshot_monthly(region, size),
                reason=reason,
                detail=detail,
            )
        )
    return findings


def launch_template_image_ids(ec2: Any) -> Set[str]:
    """AMI IDs named by the default or latest version of any launch template.

    An AMI that nothing has launched recently is still in use if an Auto
    Scaling group or a deploy script will launch it from a template tomorrow.
    Templates that resolve the AMI through an SSM parameter cannot be matched.
    """
    templates = _paginate(
        ec2.describe_launch_templates, "LaunchTemplates", "DescribeLaunchTemplates"
    )
    image_ids: Set[str] = set()
    for t in templates:
        versions = _paginate(
            ec2.describe_launch_template_versions,
            "LaunchTemplateVersions",
            "DescribeLaunchTemplateVersions",
            LaunchTemplateId=t.get("LaunchTemplateId"),
            Versions=["$Default", "$Latest"],
        )
        for v in versions:
            image_id = (v.get("LaunchTemplateData") or {}).get("ImageId")
            if image_id:
                image_ids.add(image_id)
    return image_ids


def scan_amis(ec2: Any, region: str, now: datetime, unused_days: int) -> List[Finding]:
    """Self-owned AMIs not launched in `unused_days` and not named by a launch template.

    The cost is what the backing snapshots would bill at full size. Snapshots
    are incremental, so the real figure can be lower; it cannot be higher.
    Those snapshots are never reported by the snapshot check (they back an
    AMI), so the AMI row is the only place their cost shows up.
    """
    images = _paginate(ec2.describe_images, "Images", "DescribeImages", Owners=["self"])
    candidates = []
    for img in images:
        if img.get("State", "available") != "available":
            continue
        created = as_datetime(img.get("CreationDate"))
        last_launched = as_datetime(img.get("LastLaunchedTime"))
        dates = [d for d in (created, last_launched) if d is not None]
        if not dates:
            continue  # no date at all: cannot prove it is unused
        idle_days = int((now - max(dates)).total_seconds() // 86400)
        if idle_days < unused_days:
            continue
        candidates.append((img, last_launched, idle_days))
    findings: List[Finding] = []
    if not candidates:
        return findings

    templated = launch_template_image_ids(ec2)
    for img, last_launched, idle_days in candidates:
        image_id = img.get("ImageId", "unknown")
        if image_id in templated:
            continue
        snapshot_ids = []
        size = 0
        for bdm in img.get("BlockDeviceMappings", []) or []:
            ebs = bdm.get("Ebs") or {}
            if ebs.get("SnapshotId"):
                snapshot_ids.append(ebs["SnapshotId"])
                size += ebs.get("VolumeSize", 0) or 0
        if last_launched is not None:
            reason = f"AMI not launched in {idle_days} days and not in any launch template"
        else:
            reason = (
                "AMI has no recorded launch and is not in any launch template "
                f"(created {idle_days} days ago)"
            )
        detail: Dict[str, Any] = {
            "name": img.get("Name"),
            "snapshot_ids": snapshot_ids,
            "size_gb": size,
            "last_launched": last_launched.isoformat() if last_launched else None,
            "age_days": idle_days,
        }
        findings.append(
            Finding(
                region=region,
                kind="ami",
                resource_id=image_id,
                monthly_cost=pricing.snapshot_monthly(region, size),
                reason=reason,
                detail=detail,
            )
        )
    return findings


def _stopped_at(instance: Dict[str, Any]) -> Optional[datetime]:
    m = _STOPPED_AT_RE.search(instance.get("StateTransitionReason") or "")
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def scan_stopped_instances(
    ec2: Any, region: str, now: datetime, older_than_days: Optional[int] = None
) -> List[Finding]:
    """Stopped instances whose EBS volumes keep billing, plus their Elastic IPs.

    Two kinds come out of one pass so the money is counted once:
    `stopped_instance` carries the cost of the attached volumes, and every
    Elastic IP on the instance is its own `eip_stopped_instance` row with the
    public IPv4 rate, since releasing an address and terminating an instance
    are separate decisions.

    With `older_than_days`, an instance whose stop time cannot be read from
    StateTransitionReason is skipped: an unknown age is not an old age.
    """
    reservations = _paginate(
        ec2.describe_instances,
        "Reservations",
        "DescribeInstances",
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}],
    )
    instances = [
        i
        for r in reservations
        for i in (r.get("Instances") or [])
        if (i.get("State") or {}).get("Name") == "stopped"
    ]
    if not instances:
        return []

    addresses_by_instance: Dict[str, List[Dict[str, Any]]] = {}
    for addr in _paginate(ec2.describe_addresses, "Addresses", "DescribeAddresses"):
        if addr.get("InstanceId"):
            addresses_by_instance.setdefault(addr["InstanceId"], []).append(addr)

    volumes_by_id = {
        v.get("VolumeId"): v
        for v in _paginate(
            ec2.describe_volumes,
            "Volumes",
            "DescribeVolumes",
            Filters=[{"Name": "status", "Values": ["in-use"]}],
        )
    }

    findings: List[Finding] = []
    for inst in instances:
        instance_id = inst.get("InstanceId", "unknown")
        stopped_at = _stopped_at(inst)
        age = _age_days(stopped_at, now)
        if older_than_days is not None and (age is None or age < older_than_days):
            continue
        since = f"stopped since {stopped_at:%Y-%m-%d}" if stopped_at else "stopped"

        billed: List[str] = []
        volumes: List[Dict[str, Any]] = []
        cost = 0.0
        for bdm in inst.get("BlockDeviceMappings", []) or []:
            volume_id = (bdm.get("Ebs") or {}).get("VolumeId")
            if not volume_id:
                continue
            vol = volumes_by_id.get(volume_id) or {}
            size = vol.get("Size", 0)
            vtype = vol.get("VolumeType", "gp2")
            vol_cost = pricing.ebs_volume_monthly(region, vtype, size) if vol else 0.0
            cost += vol_cost
            volumes.append(
                {"volume_id": volume_id, "size_gb": size, "volume_type": vtype,
                 "monthly_cost": round(vol_cost, 2)}
            )
            billed.append(f"{volume_id} ({size} GiB {vtype})" if vol else volume_id)

        eips = addresses_by_instance.get(instance_id, [])
        for addr in eips:
            billed.append(f"Elastic IP {addr.get('PublicIp')} (reported as eip_stopped_instance)")

        detail: Dict[str, Any] = {
            "instance_type": inst.get("InstanceType"),
            "stopped_at": stopped_at.isoformat() if stopped_at else None,
            "age_days": age,
            "volumes": volumes,
            "elastic_ips": [a.get("PublicIp") for a in eips],
        }
        name = _name_tag(inst.get("Tags"))
        if name:
            detail["name"] = name
        reason = f"instance {since}; still billing: " + (", ".join(billed) or "nothing found")
        findings.append(
            Finding(
                region=region,
                kind="stopped_instance",
                resource_id=instance_id,
                monthly_cost=cost,
                reason=reason,
                detail=detail,
            )
        )
        for addr in eips:
            byoip = _is_byoip(addr)
            eip_detail: Dict[str, Any] = {
                "public_ip": addr.get("PublicIp"),
                "instance_id": instance_id,
                "association_id": addr.get("AssociationId"),
                "age_days": age,
            }
            findings.append(
                Finding(
                    region=region,
                    kind="eip_stopped_instance",
                    resource_id=addr.get("AllocationId") or addr.get("PublicIp", "unknown"),
                    monthly_cost=pricing.public_ipv4_monthly(region, byoip=byoip),
                    reason=f"Elastic IP attached to instance {instance_id}, {since}",
                    detail=eip_detail,
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
    *,
    services: Optional[Callable[[str], Any]] = None,
    options: Optional[ScanOptions] = None,
) -> List[Finding]:
    """Run every orphan check against a single region's EC2 client.

    Pass `errors` to collect checks that had to be skipped instead of raising.
    A skipped check contributes no findings -- never a silent empty result.

    `services(name)` returns this region's client for another service
    (`elbv2`, `elb`, `cloudwatch`). Without it the load balancer and NAT
    gateway checks, which need CloudWatch to tell idle from busy, do not run.
    """
    now = now or datetime.now(timezone.utc)
    options = options or ScanOptions()
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
    findings.extend(
        _run_check(
            "stopped_instance",
            region,
            lambda: scan_stopped_instances(ec2, region, now, older_than_days),
            errors,
        )
    )
    findings.extend(
        _run_check(
            "ami", region, lambda: scan_amis(ec2, region, now, options.ami_unused_days), errors
        )
    )
    if services is not None:
        findings.extend(
            _run_check(
                "load_balancer",
                region,
                lambda: idle.scan_load_balancers(
                    services("elbv2"), services("elb"), services("cloudwatch"), ec2,
                    region, now, options,
                ),
                errors,
            )
        )
        findings.extend(
            _run_check(
                "nat_gateway",
                region,
                lambda: idle.scan_nat_gateways(ec2, services("cloudwatch"), region, now, options),
                errors,
            )
        )
    return findings


def scan_regions(
    client_factory: ClientFactory,
    regions: List[str],
    now: Optional[datetime] = None,
    older_than_days: Optional[int] = None,
    errors: Optional[List[ScanError]] = None,
    *,
    service_factory: Optional[ServiceFactory] = None,
    options: Optional[ScanOptions] = None,
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
        services = None
        if service_factory is not None:
            services = (lambda r: lambda name: service_factory(r, name))(region)
        all_findings.extend(
            scan_region(
                ec2, region, now, older_than_days, errors, services=services, options=options
            )
        )
    return all_findings
