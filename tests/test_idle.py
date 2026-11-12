from __future__ import annotations

from datetime import timedelta

from aws_orphan_finder import idle, scanner
from aws_orphan_finder.models import ScanOptions
from tests.conftest import FakeCloudWatch, FakeEC2, FakeELB, FakeELBv2, service_factory

OPTS = ScanOptions(idle_lookback_days=14, idle_min_traffic=100)


def _lb(name, now, lb_type="application", age_days=60, **extra):
    prefix = {"application": "app", "network": "net", "gateway": "gwy"}[lb_type]
    lb = {
        "LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:111:loadbalancer/{prefix}/{name}/abc",
        "LoadBalancerName": name,
        "Type": lb_type,
        "State": {"Code": "active"},
        "CreatedTime": now - timedelta(days=age_days),
        "AvailabilityZones": [{"ZoneName": "us-east-1a"}, {"ZoneName": "us-east-1b"}],
    }
    lb.update(extra)
    return lb


def _forward_listener():
    return {"_rules": [["forward"]]}


def _scan(now, lbs=(), clbs=(), sums=None, ec2=None, options=OPTS):
    return idle.scan_load_balancers(
        FakeELBv2(list(lbs)),
        FakeELB(list(clbs)),
        FakeCloudWatch(sums or {}),
        ec2 or FakeEC2(),
        "us-east-1",
        now,
        options,
    )


def test_arn_suffix():
    arn = "arn:aws:elasticloadbalancing:us-east-1:111:loadbalancer/app/my-lb/50dc6c495c0c9188"
    assert idle.arn_suffix(arn) == "app/my-lb/50dc6c495c0c9188"


def test_alb_without_targets_is_idle(now):
    findings = _scan(now, [_lb("empty", now, _listeners=[_forward_listener()])])
    assert [f.resource_id for f in findings] == ["empty"]
    f = findings[0]
    assert f.kind == "load_balancer"
    assert "no registered targets" in f.reason
    assert round(f.monthly_cost, 2) == round(0.0225 * 730, 2)


def test_alb_with_healthy_targets_and_low_traffic_is_idle(now):
    lb = _lb("quiet", now, _target_groups=[{"_targets": ["healthy"]}], _listeners=[_forward_listener()])
    findings = _scan(now, [lb], sums={"app/quiet/abc": 12})
    assert len(findings) == 1
    assert "1 of 1 targets serving; 12 requests in 14 days" in findings[0].reason
    assert findings[0].detail["traffic"] == 12


def test_alb_with_traffic_is_not_reported(now):
    lb = _lb("busy", now, _target_groups=[{"_targets": ["healthy"]}], _listeners=[_forward_listener()])
    assert _scan(now, [lb], sums={"app/busy/abc": 50000}) == []


def test_no_datapoints_is_unknown_not_idle(now):
    """Absent metrics are not zero traffic: never flag without evidence."""
    lb = _lb("silent", now, _target_groups=[{"_targets": ["healthy"]}], _listeners=[_forward_listener()])
    assert _scan(now, [lb], sums={}) == []


def test_unhealthy_targets_are_judged_by_traffic_not_flagged_outright(now):
    """All-unhealthy is an outage as often as it is waste; traffic decides."""
    lb = _lb("broken", now, _target_groups=[{"_targets": ["unhealthy"]}], _listeners=[_forward_listener()])
    assert _scan(now, [lb], sums={"app/broken/abc": 9000}) == []
    findings = _scan(now, [lb], sums={"app/broken/abc": 0})
    assert "0 of 1 targets serving" in findings[0].reason


def test_redirect_only_alb_is_not_flagged_for_having_no_targets(now):
    lb = _lb("redirector", now, _listeners=[{"_rules": [["redirect"]]}, {"_rules": [["fixed-response"]]}])
    assert _scan(now, [lb], sums={"app/redirector/abc": 1_000_000}) == []
    assert _scan(now, [lb], sums={}) == []
    findings = _scan(now, [lb], sums={"app/redirector/abc": 3})
    assert len(findings) == 1
    assert "redirect-only listeners" in findings[0].reason
    assert findings[0].detail["redirect_only"] is True


def test_lambda_target_group_is_judged_by_traffic(now):
    lb = _lb("fn", now, _target_groups=[{"TargetType": "lambda"}], _listeners=[_forward_listener()])
    assert _scan(now, [lb], sums={"app/fn/abc": 5000}) == []
    assert "Lambda targets" in _scan(now, [lb], sums={"app/fn/abc": 1})[0].reason


def test_load_balancer_younger_than_lookback_is_not_judged(now):
    assert _scan(now, [_lb("new", now, age_days=3, _listeners=[_forward_listener()])]) == []


def test_nlb_uses_new_flow_count(now):
    lb = _lb("tcp", now, lb_type="network", _target_groups=[{"_targets": ["healthy"]}])
    cw = FakeCloudWatch({"net/tcp/abc": 0})
    findings = idle.scan_load_balancers(
        FakeELBv2([lb]), FakeELB(), cw, FakeEC2(), "us-east-1", now, OPTS
    )
    assert len(findings) == 1
    assert cw.calls[0]["Namespace"] == "AWS/NetworkELB"
    assert cw.calls[0]["MetricName"] == "NewFlowCount"
    assert cw.calls[0]["Statistics"] == ["Sum"]
    assert cw.calls[0]["EndTime"] - cw.calls[0]["StartTime"] == timedelta(days=14)


def test_gwlb_priced_per_az_and_lists_its_endpoints(now):
    lb = _lb("inspect", now, lb_type="gateway")
    ec2 = FakeEC2(
        endpoint_services=[
            {"ServiceName": "com.amazonaws.vpce.us-east-1.vpce-svc-1",
             "GatewayLoadBalancerArns": [lb["LoadBalancerArn"]]}
        ],
        vpc_endpoints=[
            {"VpcEndpointId": "vpce-1", "ServiceName": "com.amazonaws.vpce.us-east-1.vpce-svc-1"},
            {"VpcEndpointId": "vpce-other", "ServiceName": "com.amazonaws.vpce.us-east-1.vpce-svc-2"},
        ],
    )
    findings = _scan(now, [lb], ec2=ec2)
    assert len(findings) == 1
    f = findings[0]
    # two AZs @ $0.0125/h
    assert round(f.monthly_cost, 2) == round(2 * 0.0125 * 730, 2)
    assert f.detail["gwlb_endpoints"] == ["vpce-1"]
    assert "vpce-1" in f.reason


def test_classic_load_balancer_rules(now):
    created = now - timedelta(days=60)
    clbs = [
        {"LoadBalancerName": "clb-empty", "CreatedTime": created, "Instances": []},
        {"LoadBalancerName": "clb-quiet", "CreatedTime": created,
         "Instances": [{"InstanceId": "i-1"}], "_health": ["InService"]},
        {"LoadBalancerName": "clb-busy", "CreatedTime": created,
         "Instances": [{"InstanceId": "i-2"}], "_health": ["InService"]},
    ]
    findings = _scan(now, clbs=clbs, sums={"clb-quiet": 4, "clb-busy": 10_000})
    assert sorted(f.resource_id for f in findings) == ["clb-empty", "clb-quiet"]
    quiet = next(f for f in findings if f.resource_id == "clb-quiet")
    assert "1 of 1 instances in service; 4 requests" in quiet.reason
    assert round(quiet.monthly_cost, 2) == round(0.025 * 730, 2)


def test_lb_pagination_follows_next_marker(now):
    lbs = [_lb(f"lb{i}", now, _listeners=[_forward_listener()]) for i in range(3)]
    assert len(_scan(now, lbs)) == 3


def test_classic_failure_skips_the_whole_load_balancer_check(now):
    errors = []
    factory = service_factory(
        elbv2=FakeELBv2([_lb("empty", now, _listeners=[_forward_listener()])]),
        elb=FakeELB(fail={"describe_load_balancers": "AccessDenied"}),
    )
    findings = scanner.scan_regions(
        lambda r: FakeEC2(), ["us-east-1"], now, errors=errors, service_factory=factory
    )
    assert [f for f in findings if f.kind == "load_balancer"] == []
    assert [(e.kind, e.code) for e in errors] == [("load_balancer", "AccessDenied")]


def test_cloudwatch_failure_is_a_skipped_check(now):
    errors = []
    lb = _lb("quiet", now, _target_groups=[{"_targets": ["healthy"]}], _listeners=[_forward_listener()])
    factory = service_factory(elbv2=FakeELBv2([lb]), cloudwatch=FakeCloudWatch(fail="AccessDenied"))
    scanner.scan_regions(lambda r: FakeEC2(), ["us-east-1"], now, errors=errors, service_factory=factory)
    assert ("load_balancer", "GetMetricStatistics") in [(e.kind, e.operation) for e in errors]


def test_without_service_factory_lb_and_nat_checks_do_not_run(now):
    findings = scanner.scan_regions(lambda r: FakeEC2(), ["us-east-1"], now, errors=[])
    assert findings == []


# --- NAT gateways (#4) ------------------------------------------------------


def _nat(gw_id, now, age_days=60, **extra):
    gw = {
        "NatGatewayId": gw_id,
        "State": "available",
        "CreateTime": now - timedelta(days=age_days),
        "SubnetId": "subnet-1",
        "VpcId": "vpc-1",
        "ConnectivityType": "public",
        "NatGatewayAddresses": [{"AllocationId": f"eipalloc-{gw_id}", "PublicIp": "3.3.3.3"}],
    }
    gw.update(extra)
    return gw


def test_idle_nat_gateway_includes_its_public_ip(now):
    ec2 = FakeEC2(
        nat_gateways=[
            _nat("nat-idle", now),
            _nat("nat-busy", now),
            _nat("nat-new", now, age_days=2),
            _nat("nat-nodata", now),
            _nat("nat-regional", now, AvailabilityMode="regional"),
            _nat("nat-deleted", now, State="deleted"),
        ]
    )
    cw = FakeCloudWatch({"nat-idle": 10, "nat-busy": 1e6, "nat-new": 0, "nat-regional": 0})
    findings = idle.scan_nat_gateways(ec2, cw, "us-east-1", now, OPTS)
    assert [f.resource_id for f in findings] == ["nat-idle"]
    f = findings[0]
    assert f.kind == "nat_gateway"
    assert round(f.monthly_cost, 2) == round(0.045 * 730 + 3.65, 2)
    assert "10 packets out in 14 days" in f.reason
    assert f.detail["allocation_ids"] == ["eipalloc-nat-idle"]
    assert cw.calls[0]["MetricName"] == "PacketsOutToDestination"


def test_min_traffic_threshold_is_configurable(now):
    ec2 = FakeEC2(nat_gateways=[_nat("nat-1", now)])
    cw = FakeCloudWatch({"nat-1": 500})
    assert idle.scan_nat_gateways(ec2, cw, "us-east-1", now, OPTS) == []
    loose = ScanOptions(idle_lookback_days=14, idle_min_traffic=1000)
    assert len(idle.scan_nat_gateways(ec2, cw, "us-east-1", now, loose)) == 1
