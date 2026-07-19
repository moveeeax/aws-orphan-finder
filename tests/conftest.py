from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest


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
    ):
        self.addresses = addresses or []
        self.volumes = volumes or []
        self.enis = enis or []
        self.snapshots = snapshots or []
        self.mutating_calls: List[str] = []

    # --- read-only describe calls -------------------------------------
    def describe_addresses(self, **kwargs):
        return {"Addresses": self.addresses}

    def describe_volumes(self, **kwargs):
        return self._paged("Volumes", self._filter(self.volumes, kwargs, "State"), kwargs)

    def describe_network_interfaces(self, **kwargs):
        return self._paged(
            "NetworkInterfaces", self._filter(self.enis, kwargs, "Status"), kwargs
        )

    def describe_snapshots(self, **kwargs):
        return self._paged("Snapshots", self.snapshots, kwargs)

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
            if flt.get("Name") == "status":
                allowed = set(flt["Values"])
                items = [i for i in items if i.get(field) in allowed]
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
