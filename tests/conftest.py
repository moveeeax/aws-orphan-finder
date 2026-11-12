from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest
from botocore.exceptions import ClientError


class FakeEC2:
    """Minimal stand-in for a boto3 EC2 client used by the scanner.

    Supports the describe_* calls the scanner makes, status-filter matching,
    and NextToken pagination so the paginator code path is exercised.
    """

    def __init__(
        self,
        addresses: List[Dict[str, Any]] = None,
        volumes: List[Dict[str, Any]] = None,
        enis: List[Dict[str, Any]] = None,
        snapshots: List[Dict[str, Any]] = None,
        images: List[Dict[str, Any]] = None,
        instances: List[Dict[str, Any]] = None,
        launch_templates: Dict[str, List[Dict[str, Any]]] = None,
        nat_gateways: List[Dict[str, Any]] = None,
        subnets: List[Dict[str, Any]] = None,
        vpc_endpoints: List[Dict[str, Any]] = None,
        endpoint_services: List[Dict[str, Any]] = None,
        fail: Dict[str, str] = None,
    ):
        self.addresses = addresses or []
        self.volumes = volumes or []
        self.enis = enis or []
        self.snapshots = snapshots or []
        self.images = images or []
        self.instances = instances or []
        # launch template id -> versions returned for $Default/$Latest
        self.launch_templates = launch_templates or {}
        self.nat_gateways = nat_gateways or []
        self.subnets = subnets or []
        self.vpc_endpoints = vpc_endpoints or []
        self.endpoint_services = endpoint_services or []
        # Map of describe_* method name -> AWS error code to raise, so tests
        # can prove a failed call never degrades into an empty result.
        self.fail = fail or {}
        self.mutating_calls: List[str] = []

    # --- read-only describe calls -------------------------------------
    def describe_addresses(self, **kwargs):
        self._maybe_fail("describe_addresses", "DescribeAddresses")
        return {"Addresses": self.addresses}

    def describe_volumes(self, **kwargs):
        self._maybe_fail("describe_volumes", "DescribeVolumes")
        return self._paged("Volumes", self._filter(self.volumes, kwargs, "State"), kwargs)

    def describe_network_interfaces(self, **kwargs):
        self._maybe_fail("describe_network_interfaces", "DescribeNetworkInterfaces")
        return self._paged(
            "NetworkInterfaces", self._filter(self.enis, kwargs, "Status"), kwargs
        )

    def describe_snapshots(self, **kwargs):
        self._maybe_fail("describe_snapshots", "DescribeSnapshots")
        return self._paged("Snapshots", self.snapshots, kwargs)

    def describe_images(self, **kwargs):
        self._maybe_fail("describe_images", "DescribeImages")
        return self._paged("Images", self.images, kwargs)

    def describe_instances(self, **kwargs):
        self._maybe_fail("describe_instances", "DescribeInstances")
        instances = self._filter(self.instances, kwargs, "State")
        return self._paged("Reservations", [{"Instances": [i]} for i in instances], kwargs)

    def describe_launch_templates(self, **kwargs):
        self._maybe_fail("describe_launch_templates", "DescribeLaunchTemplates")
        return {"LaunchTemplates": [{"LaunchTemplateId": t} for t in self.launch_templates]}

    def describe_launch_template_versions(self, **kwargs):
        self._maybe_fail("describe_launch_template_versions", "DescribeLaunchTemplateVersions")
        return {"LaunchTemplateVersions": self.launch_templates[kwargs["LaunchTemplateId"]]}

    def describe_nat_gateways(self, **kwargs):
        self._maybe_fail("describe_nat_gateways", "DescribeNatGateways")
        gws = self._filter(self.nat_gateways, {"Filters": kwargs.get("Filter")}, "State")
        return self._paged("NatGateways", gws, kwargs)

    def describe_subnets(self, **kwargs):
        self._maybe_fail("describe_subnets", "DescribeSubnets")
        return self._paged("Subnets", self.subnets, kwargs)

    def describe_vpc_endpoints(self, **kwargs):
        self._maybe_fail("describe_vpc_endpoints", "DescribeVpcEndpoints")
        return {"VpcEndpoints": self.vpc_endpoints}

    def describe_vpc_endpoint_service_configurations(self, **kwargs):
        self._maybe_fail(
            "describe_vpc_endpoint_service_configurations",
            "DescribeVpcEndpointServiceConfigurations",
        )
        return {"ServiceConfigurations": self.endpoint_services}

    def _maybe_fail(self, method: str, operation: str):
        code = self.fail.get(method)
        if code:
            raise ClientError({"Error": {"Code": code, "Message": f"{code} on {operation}"}}, operation)

    # --- any mutating call should never be invoked --------------------
    def __getattr__(self, name):
        if name.startswith(("delete_", "release_", "modify_", "create_", "terminate_")):
            def _blocked(*a, **k):
                self.mutating_calls.append(name)
                raise AssertionError(f"read-only tool attempted mutating call: {name}")

            return _blocked
        raise AttributeError(name)

    # --- helpers ------------------------------------------------------
    @staticmethod
    def _filter(items, kwargs, field):
        filters = kwargs.get("Filters") or []
        for flt in filters:
            allowed = set(flt["Values"])
            if flt.get("Name") in ("status", "state"):
                items = [i for i in items if i.get(field) in allowed]
            elif flt.get("Name") == "instance-state-name":
                items = [i for i in items if (i.get(field) or {}).get("Name") in allowed]
        return items

    @staticmethod
    def _paged(key, items, kwargs):
        # Emit two pages to exercise NextToken handling.
        token = kwargs.get("NextToken")
        if not items:
            return {key: []}
        if token is None and len(items) > 1:
            return {key: items[:1], "NextToken": "page2"}
        if token == "page2":
            return {key: items[1:]}
        return {key: items}


@pytest.fixture
def now():
    return datetime(2026, 7, 19, tzinfo=timezone.utc)


def days_ago(now_dt, n):
    from datetime import timedelta

    return now_dt - timedelta(days=n)


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": f"{code} on {operation}"}}, operation)


class FakeELBv2:
    """elbv2 stand-in. `load_balancers` entries are the API shape plus the
    test-only keys "_target_groups" (each with "_targets": list of states)
    and "_listeners" (each with "_rules": list of action-type lists)."""

    def __init__(self, load_balancers=None, fail=None):
        self.lbs = load_balancers or []
        self.fail = fail or {}

    def _maybe_fail(self, method):
        if method in self.fail:
            raise _client_error(self.fail[method], method)

    def _lb(self, arn):
        return next(lb for lb in self.lbs if lb["LoadBalancerArn"] == arn)

    def describe_load_balancers(self, **kwargs):
        self._maybe_fail("describe_load_balancers")
        clean = [{k: v for k, v in lb.items() if not k.startswith("_")} for lb in self.lbs]
        # Marker-style pagination: one LB per page.
        idx = int(kwargs.get("Marker") or 0)
        page = {"LoadBalancers": clean[idx:idx + 1]}
        if idx + 1 < len(clean):
            page["NextMarker"] = str(idx + 1)
        return page

    def describe_target_groups(self, **kwargs):
        self._maybe_fail("describe_target_groups")
        lb = self._lb(kwargs["LoadBalancerArn"])
        groups = []
        for i, tg in enumerate(lb.get("_target_groups", [])):
            groups.append({
                "TargetGroupArn": f"{lb['LoadBalancerArn']}/tg{i}",
                "TargetType": tg.get("TargetType", "instance"),
            })
        return {"TargetGroups": groups}

    def describe_target_health(self, **kwargs):
        self._maybe_fail("describe_target_health")
        arn, _, idx = kwargs["TargetGroupArn"].rpartition("/tg")
        tg = self._lb(arn)["_target_groups"][int(idx)]
        return {
            "TargetHealthDescriptions": [
                {"Target": {"Id": f"i-{n}"}, "TargetHealth": {"State": st}}
                for n, st in enumerate(tg.get("_targets", []))
            ]
        }

    def describe_listeners(self, **kwargs):
        self._maybe_fail("describe_listeners")
        lb = self._lb(kwargs["LoadBalancerArn"])
        return {
            "Listeners": [
                {"ListenerArn": f"{lb['LoadBalancerArn']}/l{i}", "DefaultActions": []}
                for i, _ in enumerate(lb.get("_listeners", []))
            ]
        }

    def describe_rules(self, **kwargs):
        self._maybe_fail("describe_rules")
        arn, _, idx = kwargs["ListenerArn"].rpartition("/l")
        listener = self._lb(arn)["_listeners"][int(idx)]
        return {
            "Rules": [
                {"Actions": [{"Type": t} for t in actions]} for actions in listener["_rules"]
            ]
        }


class FakeELB:
    """Classic ELB stand-in. Entries may carry "_health": list of states."""

    def __init__(self, load_balancers=None, fail=None):
        self.lbs = load_balancers or []
        self.fail = fail or {}

    def describe_load_balancers(self, **kwargs):
        if "describe_load_balancers" in self.fail:
            raise _client_error(self.fail["describe_load_balancers"], "DescribeLoadBalancers")
        return {
            "LoadBalancerDescriptions": [
                {k: v for k, v in lb.items() if not k.startswith("_")} for lb in self.lbs
            ]
        }

    def describe_instance_health(self, **kwargs):
        lb = next(lb for lb in self.lbs if lb["LoadBalancerName"] == kwargs["LoadBalancerName"])
        return {"InstanceStates": [{"State": st} for st in lb.get("_health", [])]}


class FakeCloudWatch:
    """Returns canned daily Sum datapoints keyed by the first dimension value.

    A key mapped to None, or missing, returns no datapoints at all.
    """

    def __init__(self, sums=None, fail=None):
        self.sums = sums or {}
        self.fail = fail
        self.calls: List[Dict[str, Any]] = []

    def get_metric_statistics(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise _client_error(self.fail, "GetMetricStatistics")
        value = self.sums.get(kwargs["Dimensions"][0]["Value"])
        if value is None:
            return {"Datapoints": []}
        return {"Datapoints": [{"Sum": value}]}


def service_factory(elbv2=None, elb=None, cloudwatch=None):
    clients = {
        "elbv2": elbv2 or FakeELBv2(),
        "elb": elb or FakeELB(),
        "cloudwatch": cloudwatch or FakeCloudWatch(),
    }
    return lambda region, service: clients[service]
