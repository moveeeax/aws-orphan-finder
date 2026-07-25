# aws-orphan-finder

[![CI](https://github.com/moveeeax/aws-orphan-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-orphan-finder/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Find the AWS resources quietly billing you for nothing — and see the monthly savings.

`aws-orphan-finder` scans your AWS account for **orphaned resources** and estimates
how much they cost you every month. It is **read-only**: it never deletes, releases,
or modifies anything.

## What it finds

| Category | AWS API | Orphan rule |
| --- | --- | --- |
| Unattached Elastic IPs | `DescribeAddresses` | no `AssociationId`, `InstanceId` or `NetworkInterfaceId` |
| Available EBS volumes | `DescribeVolumes` (`status=available`) | no `Attachments` entry |
| Detached network interfaces | `DescribeNetworkInterfaces` (`status=available`) | no `Attachment` record |
| Stale EBS snapshots | `DescribeSnapshots` (`owner=self`) + `DescribeImages` | `completed`, **not referenced by any self-owned AMI**, older than `--older-than` |

Each finding gets a **monthly $ estimate** derived from region-aware pricing, and the
tool prints per-region and grand totals so you can see the whole bill you're wasting.

## Avoiding false positives

The expensive mistake this tool could make is telling you to delete something that
is actually in use. The predicates are therefore deliberately conservative:

- **Snapshots are cross-referenced against your AMIs.** A snapshot that backs a
  registered image is not waste, and is never reported. If `DescribeImages` fails,
  the entire snapshot check is skipped rather than falling back to "no AMIs exist"
  — that fallback would flag every image-backing snapshot as deletable.
- **An in-use resource is recognised by more than one signal.** An Elastic IP with
  an `InstanceId` but no `AssociationId` is in use; a volume or ENI mid-detach still
  carries an attachment record while its status already reads `available`. All of
  those are excluded.
- **Pagination is all-or-nothing.** If page 2 of a listing fails, the check reports
  nothing instead of the first page. A truncated listing is how a resource whose
  attachment was never seen becomes a "finding".
- **Failed calls are never rendered as empty results.** Throttling and `AccessDenied`
  are reported as skipped checks, listed in the output, and make the command exit
  `2`. Absence from the report never means "verified in use".
- Snapshots shared with, and registered as AMIs by, **another account** cannot be
  seen from yours. That is an inherent API limit, not something the tool can check.

## Install

```bash
pip install aws-orphan-finder
```

Or from source:

```bash
git clone https://github.com/moveeeax/aws-orphan-finder.git
cd aws-orphan-finder
pip install -e ".[dev]"
```

## Usage

Uses your standard AWS credential chain (env vars, `~/.aws/credentials`, SSO, or
`--profile`). It only needs read permissions (`ec2:Describe*`) — note that
`ec2:DescribeImages` is required, because the snapshot check refuses to run without
it.

```bash
# Scan two regions, only volumes/snapshots older than 30 days
aws-orphan-finder scan --regions eu-west-1,us-east-1 --older-than 30d

# JSON output (great for piping into jq or a dashboard)
aws-orphan-finder scan --regions us-east-1 --output json

# CSV output
aws-orphan-finder scan --regions us-east-1 --format csv
```

### Options

| Flag | Description |
| --- | --- |
| `--regions` | Comma-separated regions to scan (required) |
| `--older-than` | Age filter for volumes/snapshots: `30d`, `2w`, `3m`, or a number of days |
| `--output` / `--format` | `table` (default), `json`, or `csv` |
| `--profile` | AWS named profile |
| `--ignore-errors` | Exit `0` even if some checks were skipped |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; every check ran |
| `2` | Scan is **incomplete** — at least one check was skipped (see `errors` in the JSON output and the warnings on stderr), or the arguments were invalid |

If you drive cleanup from this tool, gate it on exit `0` and on `errors == []` in the
JSON output. A partial scan is not a complete inventory.

### Example output

```
                          Orphaned AWS resources
┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Region    ┃ Kind       ┃ Resource      ┃ Monthly $ ┃ Reason                ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ eu-west-1 │ ebs_volume │ vol-0abc      │     16.80 │ available             │
│ eu-west-1 │ eip        │ eipalloc-0a1b │      3.83 │ not associated        │
│ eu-west-1 │ snapshot   │ snap-0xy      │     10.50 │ retained, no AMI      │
└───────────┴────────────┴───────────────┴───────────┴───────────────────────┘
```

Run the offline demo (no AWS account needed):

```bash
python examples/demo.py table
```

A captured JSON run lives in [`examples/sample_scan.json`](examples/sample_scan.json).

## How it works

- Resources are discovered per region using the corresponding `Describe*` EC2 API,
  with `NextToken` pagination handled transparently. Region names are validated and
  de-duplicated, so a repeated `--regions` entry cannot double the reported spend.
- Throttled calls are retried by botocore in `adaptive` mode; a check that still
  fails is recorded as a skipped check rather than an empty result.
- Cost is estimated from a small, region-aware price book (`aws_orphan_finder/pricing.py`):
  idle EIPs at the hourly idle rate, EBS volumes by type and size, snapshots by size.
  Estimates are deliberately conservative approximations, not a billing source of truth.
- Multi-region results are aggregated into per-region, per-kind, and total summaries.

## Read-only guarantee

The tool only ever calls `Describe*` APIs. There is no code path that deletes,
releases, or modifies a resource, and a test asserts that no mutating call is made.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

[MIT](LICENSE)
