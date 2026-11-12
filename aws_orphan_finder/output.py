from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict, List, Optional

from .models import Finding, ScanError
from .summary import group_snapshots

CSV_FIELDS = ["region", "kind", "resource_id", "monthly_cost", "reason", "detail"]

FORMATS = ("table", "json", "csv", "html", "commands")


def render_json(
    findings: List[Finding],
    summary: Dict[str, Any],
    errors: Optional[List[ScanError]] = None,
    public_ipv4: Optional[Dict[str, Any]] = None,
    group_by: Optional[str] = None,
) -> str:
    payload: Dict[str, Any] = {
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
        # Always present so consumers can assert `errors == []` before acting
        # on the findings. A non-empty list means the scan is incomplete.
        "errors": [e.to_dict() for e in errors or []],
    }
    if group_by == "volume":
        payload["snapshot_groups"] = group_snapshots(findings)
    if public_ipv4 is not None:
        payload["public_ipv4"] = public_ipv4
    return json.dumps(payload, indent=2, default=str)


def render_csv(findings: List[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for f in findings:
        row = f.to_dict()
        row["detail"] = json.dumps(row["detail"], default=str, sort_keys=True)
        writer.writerow(row)
    return buf.getvalue()


def _rows(findings: List[Finding], group_by: Optional[str]) -> List[List[str]]:
    """Finding rows for the table and HTML views: (region, kind, resource, $, reason).

    With group_by="volume" every snapshot chain becomes one row, so 200
    dailies of one volume read as one line.
    """
    shown = findings
    rows: List[List[str]] = []
    if group_by == "volume":
        shown = [f for f in findings if f.kind != "snapshot"]
        for g in group_snapshots(findings):
            reason = f"{g['count']} snapshots"
            if g["oldest_age_days"] is not None:
                reason += f", {g['newest_age_days']}-{g['oldest_age_days']} days old"
            if g["volume_id"] and g["source_volume_exists"] is False:
                reason += "; source volume deleted"
            if g["possible_unpruned_retention"]:
                reason += "; looks like retention that never prunes"
            rows.append(
                [
                    g["region"],
                    "snapshot",
                    g["volume_id"] or "(no source volume)",
                    f"{g['monthly_cost']:,.2f}",
                    reason,
                ]
            )
    for f in shown:
        rows.append([f.region, f.kind, f.resource_id, f"{f.monthly_cost:,.2f}", f.reason])
    return sorted(rows, key=lambda r: (r[0], r[1], r[2]))


def render_table(
    findings: List[Finding],
    summary: Dict[str, Any],
    errors: Optional[List[ScanError]] = None,
    public_ipv4: Optional[Dict[str, Any]] = None,
    group_by: Optional[str] = None,
) -> str:
    """Render a rich table to a string (no terminal required)."""
    from rich.console import Console
    from rich.table import Table

    # markup=False: cell values come from Finding fields, and `render()` is a
    # public function that library callers can feed arbitrary strings (custom
    # resource ids, reasons, ...). Rich's default markup parser treats "[" as
    # the start of a style tag, so any bracketed value -- e.g. a mismatched
    # "[/foo]" -- would otherwise raise rich.errors.MarkupError and crash a
    # function that should never fail on ordinary text content.
    console = Console(file=io.StringIO(), width=120, no_color=True, markup=False)

    table = Table(title="Orphaned AWS resources", show_lines=False)
    table.add_column("Region")
    table.add_column("Kind")
    table.add_column("Resource")
    table.add_column("Monthly $", justify="right")
    table.add_column("Reason")
    for row in _rows(findings, group_by):
        table.add_row(*row)
    console.print(table)

    summary_table = Table(title="Summary by region")
    summary_table.add_column("Region")
    summary_table.add_column("Findings", justify="right")
    summary_table.add_column("Monthly $", justify="right")
    for region, agg in sorted(summary["by_region"].items()):
        summary_table.add_row(region, str(agg["count"]), f"{agg['monthly_cost']:,.2f}")
    summary_table.add_row(
        "TOTAL",
        str(summary["total_findings"]),
        f"{summary['total_monthly_cost']:,.2f}",
    )
    console.print(summary_table)

    if public_ipv4 is not None:
        ipv4 = public_ipv4["summary"]
        ip_table = Table(title="Public IPv4 spend by owner (in use or not)")
        ip_table.add_column("Owner")
        ip_table.add_column("Addresses", justify="right")
        ip_table.add_column("Monthly $", justify="right")
        for owner, agg in sorted(ipv4["by_owner"].items()):
            ip_table.add_row(owner, str(agg["count"]), f"{agg['monthly_cost']:,.2f}")
        ip_table.add_row(
            "TOTAL", str(ipv4["total_addresses"]), f"{ipv4['total_monthly_cost']:,.2f}"
        )
        console.print(ip_table)
        subnets = public_ipv4["auto_assign_subnets"]
        if subnets:
            console.print(
                "Subnets that auto-assign a public IPv4 to every launch: "
                + ", ".join(f"{s['region']}/{s['subnet_id']}" for s in subnets)
            )

    if errors:
        error_table = Table(title="INCOMPLETE SCAN - these checks were skipped")
        error_table.add_column("Region")
        error_table.add_column("Check")
        error_table.add_column("Operation")
        error_table.add_column("Error")
        for e in errors:
            error_table.add_row(e.region, e.kind, e.operation, e.code)
        console.print(error_table)
        console.print(
            "Resources covered by a skipped check are absent from the table above; "
            "absence here does not mean a resource is in use."
        )

    return console.file.getvalue()


def _html_table(caption: str, header: List[str], rows: List[List[str]]) -> str:
    esc = html.escape
    out = [f"<table><caption>{esc(caption)}</caption><thead><tr>"]
    out.extend(f"<th>{esc(h)}</th>" for h in header)
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


_HTML_STYLE = (
    "body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}"
    "table{border-collapse:collapse;margin:1.5rem 0;width:100%}"
    "caption{text-align:left;font-weight:600;padding:.4rem 0}"
    "th,td{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}"
    "td:nth-child(4){text-align:right}"
    ".incomplete{background:#fde8e8;border:1px solid #c33;padding:.6rem 1rem}"
)


def render_html(
    findings: List[Finding],
    summary: Dict[str, Any],
    errors: Optional[List[ScanError]] = None,
    public_ipv4: Optional[Dict[str, Any]] = None,
    group_by: Optional[str] = None,
) -> str:
    """A single self-contained HTML page: no scripts, no external assets."""
    parts = [
        "<!doctype html><html><head><meta charset=\"utf-8\">",
        "<title>aws-orphan-finder report</title>",
        f"<style>{_HTML_STYLE}</style></head><body>",
        "<h1>Orphaned AWS resources</h1>",
    ]
    if errors:
        parts.append(
            "<p class=\"incomplete\">Incomplete scan: "
            f"{len(errors)} check(s) were skipped. Resources they cover are absent "
            "below; absence does not mean a resource is in use.</p>"
        )
    parts.append(
        _html_table(
            "Findings",
            ["Region", "Kind", "Resource", "Monthly $", "Reason"],
            _rows(findings, group_by),
        )
    )
    region_rows = [
        [r, str(a["count"]), f"{a['monthly_cost']:,.2f}"]
        for r, a in sorted(summary["by_region"].items())
    ]
    region_rows.append(
        ["TOTAL", str(summary["total_findings"]), f"{summary['total_monthly_cost']:,.2f}"]
    )
    parts.append(_html_table("Summary by region", ["Region", "Findings", "Monthly $"], region_rows))
    if public_ipv4 is not None:
        ipv4 = public_ipv4["summary"]
        rows = [
            [o, str(a["count"]), f"{a['monthly_cost']:,.2f}"]
            for o, a in sorted(ipv4["by_owner"].items())
        ]
        rows.append(["TOTAL", str(ipv4["total_addresses"]), f"{ipv4['total_monthly_cost']:,.2f}"])
        parts.append(
            _html_table("Public IPv4 spend by owner", ["Owner", "Addresses", "Monthly $"], rows)
        )
        subnet_rows = [[s["region"], s["subnet_id"], s["vpc_id"]] for s in public_ipv4["auto_assign_subnets"]]
        if subnet_rows:
            parts.append(
                _html_table(
                    "Subnets with MapPublicIpOnLaunch", ["Region", "Subnet", "VPC"], subnet_rows
                )
            )
    if errors:
        parts.append(
            _html_table(
                "Skipped checks",
                ["Region", "Check", "Operation", "Error"],
                [[e.region, e.kind, e.operation, e.code] for e in errors],
            )
        )
    parts.append("</body></html>")
    return "\n".join(parts)


def _command(f: Finding) -> List[str]:
    """AWS CLI command(s) that would remove one finding. Never executed here."""
    r = f"--region {f.region}"
    rid = f.resource_id
    d = f.detail
    if f.kind == "eip":
        if rid.startswith("eipalloc-"):
            return [f"aws ec2 release-address {r} --allocation-id {rid}"]
        return [f"aws ec2 release-address {r} --public-ip {rid}"]
    if f.kind == "eip_stopped_instance":
        cmds = []
        if d.get("association_id"):
            cmds.append(f"aws ec2 disassociate-address {r} --association-id {d['association_id']}")
        cmds.append(f"aws ec2 release-address {r} --allocation-id {rid}")
        return cmds
    if f.kind == "ebs_volume":
        return [f"aws ec2 delete-volume {r} --volume-id {rid}"]
    if f.kind == "eni":
        return [f"aws ec2 delete-network-interface {r} --network-interface-id {rid}"]
    if f.kind == "snapshot":
        return [f"aws ec2 delete-snapshot {r} --snapshot-id {rid}"]
    if f.kind == "ami":
        cmds = [f"aws ec2 deregister-image {r} --image-id {rid}"]
        cmds.extend(f"aws ec2 delete-snapshot {r} --snapshot-id {s}" for s in d.get("snapshot_ids", []))
        return cmds
    if f.kind == "stopped_instance":
        # Terminating also deletes volumes marked DeleteOnTermination; snapshot
        # first if the data matters.
        return [f"aws ec2 terminate-instances {r} --instance-ids {rid}"]
    if f.kind == "load_balancer":
        cmds = [f"aws ec2 delete-vpc-endpoints {r} --vpc-endpoint-ids {e}" for e in d.get("gwlb_endpoints", [])]
        if d.get("type") == "classic":
            cmds.append(f"aws elb delete-load-balancer {r} --load-balancer-name {rid}")
        else:
            cmds.append(f"aws elbv2 delete-load-balancer {r} --load-balancer-arn {d.get('arn')}")
        return cmds
    if f.kind == "nat_gateway":
        cmds = [f"aws ec2 delete-nat-gateway {r} --nat-gateway-id {rid}"]
        cmds.extend(f"aws ec2 release-address {r} --allocation-id {a}" for a in d.get("allocation_ids", []))
        return cmds
    return []


def render_commands(findings: List[Finding], errors: Optional[List[ScanError]] = None) -> str:
    """The deletion candidate list as AWS CLI commands, every line commented out.

    Commented so that piping the output into a shell does nothing: each
    command is a decision for a person to make, one line at a time.
    """
    lines = [
        "# aws-orphan-finder deletion candidates. Nothing below has been run.",
        "# Every command is commented out: review each one, then uncomment what you mean to delete.",
    ]
    if errors:
        lines.append(
            f"# INCOMPLETE SCAN: {len(errors)} check(s) were skipped; this is not a full inventory."
        )
    for f in sorted(findings, key=lambda x: (x.region, x.kind, x.resource_id)):
        cmds = _command(f)
        if not cmds:
            continue
        lines.append("")
        lines.append(f"# {f.region} {f.kind} {f.resource_id} (${f.monthly_cost:,.2f}/month): {f.reason}")
        lines.extend(f"# {c}" for c in cmds)
    return "\n".join(lines)


def render(
    fmt: str,
    findings: List[Finding],
    summary: Dict[str, Any],
    errors: Optional[List[ScanError]] = None,
    public_ipv4: Optional[Dict[str, Any]] = None,
    group_by: Optional[str] = None,
) -> str:
    if fmt == "json":
        return render_json(findings, summary, errors, public_ipv4, group_by)
    if fmt == "csv":
        return render_csv(findings)
    if fmt == "table":
        return render_table(findings, summary, errors, public_ipv4, group_by)
    if fmt == "html":
        return render_html(findings, summary, errors, public_ipv4, group_by)
    if fmt == "commands":
        return render_commands(findings, errors)
    raise ValueError(f"unknown output format: {fmt}")
