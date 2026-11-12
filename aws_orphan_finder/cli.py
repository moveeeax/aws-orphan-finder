from __future__ import annotations

import argparse
import re
import sys
from typing import Any, Callable, List, Optional

from . import __version__, output
from .models import ScanError, ScanOptions
from .public_ipv4 import scan_public_ipv4
from .scanner import scan_regions
from .summary import summarize

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([dwm]?)\s*$", re.IGNORECASE)
_DURATION_UNIT_DAYS = {"": 1, "d": 1, "w": 7, "m": 30}

# Matches the AWS region naming scheme, including partitions such as
# us-gov-west-1, cn-north-1, us-iso-east-1 and eusc-de-east-1.
_REGION_RE = re.compile(r"^[a-z]{2,}(-[a-z]+)+-\d+$")

# Exit code used when at least one check could not be completed, so the report
# is partial. Callers that pipe this into cleanup automation must not treat a
# partial scan as an authoritative "nothing else is in use" answer.
EXIT_INCOMPLETE = 2


def parse_duration_days(value: str) -> int:
    """Parse '30d', '2w', '3m' or a bare number of days into an int of days."""
    m = _DURATION_RE.match(value)
    if not m:
        raise argparse.ArgumentTypeError(
            f"invalid duration '{value}' (use e.g. 30d, 2w, 3m or a number of days)"
        )
    return int(m.group(1)) * _DURATION_UNIT_DAYS[m.group(2).lower()]


def parse_regions(value: str) -> List[str]:
    """Parse, validate and de-duplicate a comma-separated region list.

    De-duplication matters for correctness, not just tidiness: scanning the
    same region twice would double every finding and double the reported spend.
    """
    regions: List[str] = []
    for raw in value.split(","):
        region = raw.strip()
        if not region:
            continue
        if not _REGION_RE.match(region):
            raise argparse.ArgumentTypeError(
                f"invalid AWS region '{region}' (expected e.g. eu-west-1, us-east-1)"
            )
        if region not in regions:
            regions.append(region)
    if not regions:
        raise argparse.ArgumentTypeError("no regions provided")
    return regions


def parse_positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        number = -1.0
    if number < 0:
        raise argparse.ArgumentTypeError(f"invalid threshold '{value}' (expected a number >= 0)")
    return number


def parse_lookback_days(value: str) -> int:
    days = parse_duration_days(value)
    if days < 1:
        raise argparse.ArgumentTypeError("lookback must be at least 1 day")
    return days


def _default_client_factory(profile: Optional[str]) -> Callable[..., Any]:
    import boto3
    from botocore.config import Config

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    # Adaptive retries so a throttled Describe* is retried rather than failing
    # the check. A check that gives up reports nothing, which is safe but makes
    # a wide scan of a busy account needlessly incomplete.
    #
    # Bounded connect/read timeouts matter just as much as the retry count: a
    # blackholed endpoint (dropped SYN, VPC misconfiguration, a region that
    # simply never answers) would otherwise hang on botocore's own defaults
    # (60s connect + 60s read) for up to 10 attempts -- tens of minutes stuck
    # on a single region before the check is even reported as skipped. This
    # tool is meant to run unattended (cron/CI), so a slow failure is as bad
    # as no failure at all.
    config = Config(
        retries={"max_attempts": 10, "mode": "adaptive"},
        connect_timeout=10,
        read_timeout=30,
    )

    def factory(region: str, service: str = "ec2") -> Any:
        return session.client(service, region_name=region, config=config)

    return factory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-orphan-finder",
        description="Find orphaned AWS resources and estimate monthly waste (read-only).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan regions for orphaned resources")
    scan.add_argument(
        "--regions",
        type=parse_regions,
        required=True,
        help="comma-separated AWS regions, e.g. eu-west-1,us-east-1",
    )
    scan.add_argument(
        "--older-than",
        dest="older_than",
        type=parse_duration_days,
        default=None,
        help=(
            "only report volumes, snapshots and stopped instances older than this age "
            "(e.g. 30d, 2w)"
        ),
    )
    scan.add_argument(
        "--idle-lookback",
        "--lb-lookback",
        dest="idle_lookback",
        type=parse_lookback_days,
        default=ScanOptions.idle_lookback_days,
        help=(
            "CloudWatch window for load balancer and NAT gateway traffic; younger "
            "resources are not judged (default: 14d)"
        ),
    )
    scan.add_argument(
        "--idle-min-traffic",
        "--lb-min-traffic",
        dest="idle_min_traffic",
        type=parse_positive_float,
        default=ScanOptions.idle_min_traffic,
        help=(
            "traffic over the lookback below which a load balancer or NAT gateway is "
            "idle: requests (ALB, CLB), new flows (NLB, GWLB), packets out (NAT) "
            "(default: 100)"
        ),
    )
    scan.add_argument(
        "--ami-unused",
        dest="ami_unused",
        type=parse_lookback_days,
        default=ScanOptions.ami_unused_days,
        help="report self-owned AMIs not launched within this age (default: 90d)",
    )
    scan.add_argument(
        "--group-by",
        dest="group_by",
        choices=["none", "volume"],
        default="none",
        help="'volume' collapses snapshots into one row per source volume (table, html, json)",
    )
    scan.add_argument(
        "--public-ipv4",
        dest="public_ipv4",
        action="store_true",
        help="also report every public IPv4 address and its cost, grouped by owner",
    )
    scan.add_argument(
        "--output",
        "--format",
        dest="output",
        choices=list(output.FORMATS),
        default="table",
        help=(
            "output format (default: table); 'commands' prints the AWS CLI command for "
            "each finding, commented out"
        ),
    )
    scan.add_argument("--profile", default=None, help="AWS named profile to use")
    scan.add_argument(
        "--ignore-errors",
        dest="ignore_errors",
        action="store_true",
        help=(
            f"exit 0 even if some checks were skipped (default: exit {EXIT_INCOMPLETE} "
            "so a partial scan is not mistaken for a clean one)"
        ),
    )
    return parser


def run_scan(
    args: argparse.Namespace,
    client_factory: Optional[Callable[[str], Any]] = None,
    service_factory: Optional[Callable[[str, str], Any]] = None,
) -> int:
    if client_factory is None:
        factory = _default_client_factory(args.profile)
        client_factory = factory
        service_factory = service_factory or factory
    # An injected EC2-only factory (tests, library use) gets no service
    # clients unless one is passed too; the load balancer and NAT gateway
    # checks then do not run.
    options = ScanOptions(
        idle_lookback_days=getattr(args, "idle_lookback", ScanOptions.idle_lookback_days),
        idle_min_traffic=getattr(args, "idle_min_traffic", ScanOptions.idle_min_traffic),
        ami_unused_days=getattr(args, "ami_unused", ScanOptions.ami_unused_days),
    )
    errors: List[ScanError] = []
    findings = scan_regions(
        client_factory,
        args.regions,
        older_than_days=args.older_than,
        errors=errors,
        service_factory=service_factory,
        options=options,
    )
    public_ipv4 = None
    if getattr(args, "public_ipv4", False):
        public_ipv4 = scan_public_ipv4(client_factory, args.regions, errors)
    summary = summarize(findings)
    group_by = getattr(args, "group_by", "none")
    sys.stdout.write(
        output.render(
            args.output,
            findings,
            summary,
            errors,
            public_ipv4=public_ipv4,
            group_by=None if group_by == "none" else group_by,
        )
        + "\n"
    )

    for e in errors:
        sys.stderr.write(
            f"warning: {e.region}: {e.kind} check skipped "
            f"({e.operation}: {e.code}) - results are incomplete\n"
        )
    if errors and not getattr(args, "ignore_errors", False):
        sys.stderr.write(
            f"error: {len(errors)} check(s) could not be completed; "
            "this report does not list every orphan and must not be treated as "
            "a complete inventory\n"
        )
        return EXIT_INCOMPLETE
    return 0


def main(
    argv: Optional[List[str]] = None,
    client_factory: Optional[Callable[[str], Any]] = None,
    service_factory: Optional[Callable[[str, str], Any]] = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args, client_factory=client_factory, service_factory=service_factory)
    parser.error("no command")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
