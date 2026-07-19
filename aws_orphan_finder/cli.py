from __future__ import annotations

import argparse
import re
import sys
from typing import Any, Callable, List, Optional

from . import __version__, output
from .scanner import scan_regions
from .summary import summarize

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([dwm]?)\s*$", re.IGNORECASE)
_DURATION_UNIT_DAYS = {"": 1, "d": 1, "w": 7, "m": 30}


def parse_duration_days(value: str) -> int:
    """Parse '30d', '2w', '3m' or a bare number of days into an int of days."""
    m = _DURATION_RE.match(value)
    if not m:
        raise argparse.ArgumentTypeError(
            f"invalid duration '{value}' (use e.g. 30d, 2w, 3m or a number of days)"
        )
    return int(m.group(1)) * _DURATION_UNIT_DAYS[m.group(2).lower()]


def parse_regions(value: str) -> List[str]:
    regions = [r.strip() for r in value.split(",") if r.strip()]
    if not regions:
        raise argparse.ArgumentTypeError("no regions provided")
    return regions


def _default_client_factory(profile: Optional[str]) -> Callable[[str], Any]:
    import boto3

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    def factory(region: str) -> Any:
        return session.client("ec2", region_name=region)

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
        help="only report volumes/snapshots older than this age (e.g. 30d, 2w)",
    )
    scan.add_argument(
        "--output",
        "--format",
        dest="output",
        choices=["table", "json", "csv"],
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument("--profile", default=None, help="AWS named profile to use")
    return parser


def run_scan(args: argparse.Namespace, client_factory: Optional[Callable[[str], Any]] = None) -> int:
    factory = client_factory or _default_client_factory(args.profile)
    findings = scan_regions(factory, args.regions, older_than_days=args.older_than)
    summary = summarize(findings)
    sys.stdout.write(output.render(args.output, findings, summary) + "\n")
    return 0


def main(argv: Optional[List[str]] = None, client_factory: Optional[Callable[[str], Any]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args, client_factory=client_factory)
    parser.error("no command")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
