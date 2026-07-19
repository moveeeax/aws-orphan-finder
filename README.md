# aws-orphan-finder

[![CI](https://github.com/cybercapybara/aws-orphan-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/cybercapybara/aws-orphan-finder/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Find the AWS resources quietly billing you for nothing — and see the monthly savings.

`aws-orphan-finder` scans your AWS account for **orphaned resources** and estimates
how much they cost you every month. It is **read-only**: it never deletes, releases,
or modifies anything.

## What it finds

| Category | AWS API | Orphan rule |
| --- | --- | --- |
| Unattached Elastic IPs | `DescribeAddresses` | no `AssociationId` |
| Available EBS volumes | `DescribeVolumes` (`status=available`) | not attached to an instance |
| Detached network interfaces | `DescribeNetworkInterfaces` (`status=available`) | not attached |
| Stale EBS snapshots | `DescribeSnapshots` (`owner=self`) | older than `--older-than` |

Each finding gets a **monthly $ estimate** derived from region-aware pricing, and the
tool prints per-region and grand totals so you can see the whole bill you're wasting.

## Install

```bash
pip install aws-orphan-finder
```

Or from source:

```bash
git clone https://github.com/cybercapybara/aws-orphan-finder.git
cd aws-orphan-finder
pip install -e ".[dev]"
```

## Usage

Uses your standard AWS credential chain (env vars, `~/.aws/credentials`, SSO, or
`--profile`). It only needs read permissions (`ec2:Describe*`).

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

### Example output

```
                          Orphaned AWS resources
┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Region    ┃ Kind       ┃ Resource      ┃ Monthly $ ┃ Reason                ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ eu-west-1 │ ebs_volume │ vol-0abc      │     16.80 │ available             │
│ eu-west-1 │ eip        │ eipalloc-0a1b │      3.83 │ not associated        │
│ eu-west-1 │ snapshot   │ snap-0xy      │     10.50 │ retained for 400 days │
└───────────┴────────────┴───────────────┴───────────┴───────────────────────┘
```

Run the offline demo (no AWS account needed):

```bash
python examples/demo.py table
```

A captured JSON run lives in [`examples/sample_scan.json`](examples/sample_scan.json).

## How it works

- Resources are discovered per region using the corresponding `Describe*` EC2 API,
  with `NextToken` pagination handled transparently.
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
