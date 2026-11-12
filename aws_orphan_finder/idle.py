"""Checks that decide "idle" from traffic, not from a missing attachment.

A load balancer or NAT gateway is never detached; it is idle when nothing
uses it. The evidence is a CloudWatch traffic sum over a lookback window, and
the rules are written so that missing evidence never turns into a finding:

- a resource younger than the lookback window is not judged at all;
- no CloudWatch datapoints means "unknown", not "zero", and is not reported;
- an ALB whose listeners only redirect or return fixed responses has no
  targets by design (an HTTP-to-HTTPS redirector), so it is judged by traffic
  only, never by its empty target list.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from . import pricing
from ._aws import age_days, call, metric_sum, name_tag, paginate, paginate_marker
from .models import Finding, ScanOptions

# Load balancer states worth judging. "provisioning" is not finished yet and
# "failed" bills nothing.
_LB_ACTIVE_STATES = ("active", "active_impaired")

# Actions an ALB listener can take without any target. A listener whose every
# action is one of these is a redirector or a static responder, not waste.
_TARGETLESS_ACTIONS = {"redirect", "fixed-response"}
_AUTH_ACTIONS = {"authenticate-oidc", "authenticate-cognito", "jwt-validation"}

# Target states that count as "something can serve traffic". "unavailable" is
# what a target reports when health checks are disabled: health is unknown,
# so it is not evidence of a dead balancer.
_SERVING_TARGET_STATES = ("healthy", "unavailable")

# (namespace, metric, unit label) per load balancer type. NLB and GWLB use
# NewFlowCount rather than ActiveFlowCount: NewFlowCount is a per-period count
# whose Sum is meaningful, ActiveFlowCount is a gauge.
_LB_METRICS = {
    "application": ("AWS/ApplicationELB", "RequestCount", "requests"),
    "network": ("AWS/NetworkELB", "NewFlowCount", "new flows"),
    "gateway": ("AWS/GatewayELB", "NewFlowCount", "new flows"),
    "classic": ("AWS/ELB", "RequestCount", "requests"),
}

_TYPE_LABEL = {
    "application": "Application Load Balancer",
    "network": "Network Load Balancer",
    "gateway": "Gateway Load Balancer",
    "classic": "Classic Load Balancer",
}

# Packets sent towards the internet (or the destination network, for a
# private NAT gateway). Counts every protocol, unlike the TCP-only connection
# metrics, so a UDP-only workload does not look idle.
_NAT_METRIC = ("AWS/NATGateway", "PacketsOutToDestination", "packets out")


def arn_suffix(arn: str) -> str:
    """CloudWatch's LoadBalancer dimension: the part of the ARN after
    ":loadbalancer/", e.g. "app/my-lb/50dc6c495c0c9188"."""
    marker = ":loadbalancer/"
    i = arn.find(marker)
    return arn[i + len(marker):] if i >= 0 else arn


def _old_enough(created: Any, now: datetime, options: ScanOptions) -> Tuple[bool, Optional[int]]:
    age = age_days(created, now)
    return age is not None and age >= options.idle_lookback_days, age


def _traffic_verdict(
    cloudwatch: Any,
    lb_type: str,
    dimensions: List[Dict[str, str]],
    now: datetime,
    options: ScanOptions,
) -> Tuple[Optional[float], Optional[str]]:
    """Return (traffic, reason) when traffic is below the threshold, else (traffic, None)."""
    namespace, metric, unit = _LB_METRICS[lb_type]
    traffic = metric_sum(
        cloudwatch, namespace, metric, dimensions, now, options.idle_lookback_days
    )
    if traffic is None or traffic >= options.idle_min_traffic:
        return traffic, None
    return traffic, (
        f"{traffic:.0f} {unit} in {options.idle_lookback_days} days "
        f"(below {options.idle_min_traffic:g})"
    )


def _listener_actions(elbv2: Any, lb_arn: str) -> Tuple[int, List[str]]:
    listeners = paginate_marker(
        elbv2.describe_listeners, "Listeners", "DescribeListeners", LoadBalancerArn=lb_arn
    )
    actions: List[str] = []
    for listener in listeners:
        actions.extend(a.get("Type", "") for a in listener.get("DefaultActions") or [])
        rules = paginate_marker(
            elbv2.describe_rules, "Rules", "DescribeRules", ListenerArn=listener.get("ListenerArn")
        )
        for rule in rules:
            actions.extend(a.get("Type", "") for a in rule.get("Actions") or [])
    return len(listeners), actions


def _is_redirect_only(listener_count: int, actions: List[str]) -> bool:
    terminal = [a for a in actions if a not in _AUTH_ACTIONS]
    return listener_count > 0 and bool(terminal) and all(a in _TARGETLESS_ACTIONS for a in terminal)


def _v2_targets(elbv2: Any, lb_arn: str) -> Tuple[int, int, bool]:
    """(registered, serving, has_lambda) across every target group of a balancer."""
    groups = paginate_marker(
        elbv2.describe_target_groups,
        "TargetGroups",
        "DescribeTargetGroups",
        LoadBalancerArn=lb_arn,
    )
    registered = serving = 0
    has_lambda = False
    for tg in groups:
        if tg.get("TargetType") == "lambda":
            # A Lambda target reports "unavailable" unless health checks are
            # on, and is invoked rather than "healthy". Traffic decides.
            has_lambda = True
            continue
        health = call(
            elbv2.describe_target_health,
            "DescribeTargetHealth",
            TargetGroupArn=tg.get("TargetGroupArn"),
        )
        for desc in health.get("TargetHealthDescriptions") or []:
            registered += 1
            if (desc.get("TargetHealth") or {}).get("State") in _SERVING_TARGET_STATES:
                serving += 1
    return registered, serving, has_lambda


def _gwlb_endpoints(ec2: Any) -> Dict[str, List[str]]:
    """GWLB ARN -> IDs of this account's Gateway Load Balancer endpoints on it."""
    services = paginate(
        ec2.describe_vpc_endpoint_service_configurations,
        "ServiceConfigurations",
        "DescribeVpcEndpointServiceConfigurations",
    )
    endpoints = paginate(
        ec2.describe_vpc_endpoints,
        "VpcEndpoints",
        "DescribeVpcEndpoints",
        Filters=[{"Name": "vpc-endpoint-type", "Values": ["GatewayLoadBalancer"]}],
    )
    by_service: Dict[str, List[str]] = {}
    for ep in endpoints:
        by_service.setdefault(ep.get("ServiceName", ""), []).append(ep.get("VpcEndpointId", ""))
    out: Dict[str, List[str]] = {}
    for svc in services:
        for gwlb_arn in svc.get("GatewayLoadBalancerArns") or []:
            out.setdefault(gwlb_arn, []).extend(by_service.get(svc.get("ServiceName", ""), []))
    return out


def scan_elbv2(
    elbv2: Any, cloudwatch: Any, ec2: Any, region: str, now: datetime, options: ScanOptions
) -> List[Finding]:
    """Idle Application, Network and Gateway Load Balancers."""
    findings: List[Finding] = []
    endpoints: Optional[Dict[str, List[str]]] = None
    lbs = paginate_marker(elbv2.describe_load_balancers, "LoadBalancers", "DescribeLoadBalancers")
    for lb in lbs:
        if (lb.get("State") or {}).get("Code", "active") not in _LB_ACTIVE_STATES:
            continue
        old_enough, age = _old_enough(lb.get("CreatedTime"), now, options)
        if not old_enough:
            continue
        arn = lb.get("LoadBalancerArn", "")
        lb_type = lb.get("Type", "application")
        if lb_type not in _LB_METRICS:
            continue
        dims = [{"Name": "LoadBalancer", "Value": arn_suffix(arn)}]
        registered, serving, has_lambda = _v2_targets(elbv2, arn)

        redirect_only = False
        if lb_type == "application":
            listener_count, actions = _listener_actions(elbv2, arn)
            redirect_only = _is_redirect_only(listener_count, actions)

        traffic: Optional[float] = None
        if redirect_only:
            traffic, low = _traffic_verdict(cloudwatch, lb_type, dims, now, options)
            reason = f"redirect-only listeners; {low}" if low else None
        elif registered == 0 and not has_lambda:
            reason = "no registered targets"
        else:
            traffic, low = _traffic_verdict(cloudwatch, lb_type, dims, now, options)
            targets = f"{serving} of {registered} targets serving" if registered else "Lambda targets"
            reason = f"{targets}; {low}" if low else None
        if reason is None:
            continue

        az_count = len(lb.get("AvailabilityZones") or [])
        detail: Dict[str, Any] = {
            "name": lb.get("LoadBalancerName"),
            "type": lb_type,
            "arn": arn,
            "age_days": age,
            "registered_targets": registered,
            "serving_targets": serving,
            "traffic": traffic,
            "lookback_days": options.idle_lookback_days,
        }
        if redirect_only:
            detail["redirect_only"] = True
        if lb_type == "gateway":
            # The endpoints bill on their own and only exist to reach the
            # GWLB, so they go with it. Their hourly rate is not in the
            # estimate: the PrivateLink pricing page does not publish one.
            if endpoints is None:
                endpoints = _gwlb_endpoints(ec2)
            endpoint_ids = endpoints.get(arn, [])
            detail["availability_zones"] = az_count
            detail["gwlb_endpoints"] = endpoint_ids
            if endpoint_ids:
                reason += "; endpoints to remove first: " + ", ".join(endpoint_ids)
        findings.append(
            Finding(
                region=region,
                kind="load_balancer",
                resource_id=lb.get("LoadBalancerName") or arn,
                monthly_cost=pricing.load_balancer_monthly(region, lb_type, az_count),
                reason=f"{_TYPE_LABEL[lb_type]} idle: {reason}",
                detail=detail,
            )
        )

    return findings


def scan_classic(
    elb: Any, cloudwatch: Any, region: str, now: datetime, options: ScanOptions
) -> List[Finding]:
    """Idle Classic Load Balancers."""
    findings: List[Finding] = []
    lbs = paginate_marker(
        elb.describe_load_balancers, "LoadBalancerDescriptions", "DescribeLoadBalancers"
    )
    for lb in lbs:
        old_enough, age = _old_enough(lb.get("CreatedTime"), now, options)
        if not old_enough:
            continue
        name = lb.get("LoadBalancerName", "unknown")
        registered = len(lb.get("Instances") or [])
        traffic: Optional[float] = None
        serving = 0
        if registered == 0:
            reason = "no registered instances"
        else:
            health = call(
                elb.describe_instance_health, "DescribeInstanceHealth", LoadBalancerName=name
            )
            states = health.get("InstanceStates") or []
            serving = sum(1 for s in states if s.get("State") == "InService")
            dims = [{"Name": "LoadBalancerName", "Value": name}]
            traffic, low = _traffic_verdict(cloudwatch, "classic", dims, now, options)
            if not low:
                continue
            reason = f"{serving} of {registered} instances in service; {low}"
        findings.append(
            Finding(
                region=region,
                kind="load_balancer",
                resource_id=name,
                monthly_cost=pricing.load_balancer_monthly(region, "classic"),
                reason=f"{_TYPE_LABEL['classic']} idle: {reason}",
                detail={
                    "name": name,
                    "type": "classic",
                    "age_days": age,
                    "registered_targets": registered,
                    "serving_targets": serving,
                    "traffic": traffic,
                    "lookback_days": options.idle_lookback_days,
                },
            )
        )
    return findings


def scan_load_balancers(
    elbv2: Any,
    elb: Any,
    cloudwatch: Any,
    ec2: Any,
    region: str,
    now: datetime,
    options: ScanOptions,
) -> List[Finding]:
    """ELBv2 and Classic balancers form one check: both or neither.

    Reporting the ALBs while the Classic listing failed would read as "no idle
    Classic Load Balancers", which the scan never established.
    """
    return scan_elbv2(elbv2, cloudwatch, ec2, region, now, options) + scan_classic(
        elb, cloudwatch, region, now, options
    )


def scan_nat_gateways(
    ec2: Any, cloudwatch: Any, region: str, now: datetime, options: ScanOptions
) -> List[Finding]:
    """Available NAT gateways that sent next to nothing over the lookback window.

    The estimate adds the public IPv4 charge of each address on the gateway:
    deleting the gateway and releasing its Elastic IP saves both.
    """
    findings: List[Finding] = []
    gateways = paginate(
        ec2.describe_nat_gateways,
        "NatGateways",
        "DescribeNatGateways",
        Filter=[{"Name": "state", "Values": ["available"]}],
    )
    namespace, metric, unit = _NAT_METRIC
    for gw in gateways:
        if gw.get("State", "available") != "available":
            continue
        if gw.get("AvailabilityMode") == "regional":
            # A regional NAT gateway publishes metrics per Availability Zone
            # (NatGatewayId + AvailabilityZone); a NatGatewayId-only query
            # returns nothing for it. Not judged rather than guessed.
            continue
        old_enough, age = _old_enough(gw.get("CreateTime"), now, options)
        if not old_enough:
            continue
        gw_id = gw.get("NatGatewayId", "unknown")
        traffic = metric_sum(
            cloudwatch,
            namespace,
            metric,
            [{"Name": "NatGatewayId", "Value": gw_id}],
            now,
            options.idle_lookback_days,
        )
        if traffic is None or traffic >= options.idle_min_traffic:
            continue
        public_ips = [a["PublicIp"] for a in gw.get("NatGatewayAddresses") or [] if a.get("PublicIp")]
        cost = pricing.nat_gateway_monthly(region) + len(public_ips) * pricing.public_ipv4_monthly(
            region
        )
        reason = (
            f"NAT gateway idle: {traffic:.0f} {unit} in {options.idle_lookback_days} days "
            f"(below {options.idle_min_traffic:g})"
        )
        if public_ips:
            reason += "; Elastic IP " + ", ".join(public_ips) + " included, release it after deleting"
        detail: Dict[str, Any] = {
            "subnet_id": gw.get("SubnetId"),
            "vpc_id": gw.get("VpcId"),
            "connectivity_type": gw.get("ConnectivityType", "public"),
            "public_ips": public_ips,
            "allocation_ids": [
                a["AllocationId"] for a in gw.get("NatGatewayAddresses") or [] if a.get("AllocationId")
            ],
            "age_days": age,
            "traffic": traffic,
            "lookback_days": options.idle_lookback_days,
        }
        name = name_tag(gw.get("Tags"))
        if name:
            detail["name"] = name
        findings.append(
            Finding(
                region=region,
                kind="nat_gateway",
                resource_id=gw_id,
                monthly_cost=cost,
                reason=reason,
                detail=detail,
            )
        )
    return findings
