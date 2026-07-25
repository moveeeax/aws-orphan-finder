from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional

from .models import Finding, ScanError

CSV_FIELDS = ["region", "kind", "resource_id", "monthly_cost", "reason", "detail"]


def render_json(
    findings: List[Finding], summary: Dict[str, Any], errors: Optional[List[ScanError]] = None
) -> str:
    payload = {
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
        # Always present so consumers can assert `errors == []` before acting
        # on the findings. A non-empty list means the scan is incomplete.
        "errors": [e.to_dict() for e in errors or []],
    }
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


def render_table(
    findings: List[Finding], summary: Dict[str, Any], errors: Optional[List[ScanError]] = None
) -> str:
    """Render a rich table to a string (no terminal required)."""
    from rich.console import Console
    from rich.table import Table

    console = Console(file=io.StringIO(), width=120, no_color=True)

    table = Table(title="Orphaned AWS resources", show_lines=False)
    table.add_column("Region")
    table.add_column("Kind")
    table.add_column("Resource")
    table.add_column("Monthly $", justify="right")
    table.add_column("Reason")

    for f in sorted(findings, key=lambda x: (x.region, x.kind, x.resource_id)):
        table.add_row(
            f.region,
            f.kind,
            f.resource_id,
            f"{f.monthly_cost:,.2f}",
            f.reason,
        )
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


def render(
    fmt: str,
    findings: List[Finding],
    summary: Dict[str, Any],
    errors: Optional[List[ScanError]] = None,
) -> str:
    if fmt == "json":
        return render_json(findings, summary, errors)
    if fmt == "csv":
        return render_csv(findings)
    if fmt == "table":
        return render_table(findings, summary, errors)
    raise ValueError(f"unknown output format: {fmt}")
