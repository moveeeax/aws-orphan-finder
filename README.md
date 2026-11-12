# aws-orphan-finder

[![CI](https://github.com/moveeeax/aws-orphan-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-orphan-finder/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
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
| Stale EBS snapshots | `DescribeSnapshots` (`owner=self`) + `DescribeImages` + `DescribeVolumes` | `completed`, **not referenced by any self-owned AMI**, older than `--older-than`; the reason says when the source volume is gone or the snapshot is a cross-region copy |
| Unused AMIs (`ami`) | `DescribeImages` (`owner=self`) + `DescribeLaunchTemplateVersions` | not launched within `--ami-unused` (default 90 days; creation date if never launched), **not named by the default or latest version of any launch template** |
| Stopped instances (`stopped_instance`) | `DescribeInstances` (`state=stopped`) + `DescribeVolumes` | stopped longer than `--older-than` (stop time read from `StateTransitionReason`); priced at the attached EBS volumes |
| Elastic IPs on stopped instances (`eip_stopped_instance`) | `DescribeAddresses` | the address's `InstanceId` is a stopped instance from the row above; priced at the public IPv4 rate |
| Idle load balancers (`load_balancer`) | `elbv2:Describe*`, `elb:DescribeLoadBalancers`, `elb:DescribeInstanceHealth`, CloudWatch `GetMetricStatistics` | ALB, NLB, GWLB and Classic: no registered targets, or traffic below `--lb-min-traffic` over `--lb-lookback` (see below) |
| Idle NAT gateways (`nat_gateway`) | `DescribeNatGateways` + CloudWatch `PacketsOutToDestination` | `available`, fewer than `--idle-min-traffic` packets out over `--idle-lookback` |

Each finding gets a **monthly $ estimate** derived from region-aware pricing, and the
tool prints per-region and grand totals so you can see the whole bill you're wasting.

A stopped instance and its Elastic IP are two rows on purpose: releasing an
address and terminating an instance are separate decisions, and each dollar is
counted once.

### Load balancer rules

Traffic is the CloudWatch `Sum` over the lookback window: `RequestCount` for
ALB and Classic, `NewFlowCount` for NLB and GWLB.

1. A balancer younger than `--lb-lookback` is not judged.
2. An ALB whose every listener action is `redirect` or `fixed-response` (an
   HTTP-to-HTTPS redirector, a maintenance page) is judged by traffic only, never
   by its empty target list.
3. No registered targets at all: idle.
4. Otherwise traffic below `--lb-min-traffic` is idle, whether or not the targets
   are healthy. All-unhealthy targets alone are not enough: that is an outage as
   often as it is waste.
5. No CloudWatch datapoints is "unknown" and not reported. ALB, Classic and GWLB
   metrics are only published while traffic flows, so an idle balancer of those
   types with registered targets is found by rule 3 or not at all. NLB publishes
   `NewFlowCount` even at zero.

Lambda target groups count as targets (their health reads `unavailable` unless
health checks are on), and so do targets whose health checks are disabled. A
Gateway Load Balancer is priced per enabled Availability Zone; this account's
GWLB endpoints on it are listed in the reason, but their hourly charge is not in
the estimate.

A regional NAT gateway (`AvailabilityMode=regional`) publishes its metrics per
Availability Zone and is not judged.

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
- **An AMI in a launch template is in use**, however long ago it was last launched.
  Templates that resolve their AMI through an SSM parameter, and legacy launch
  configurations, are not checked.
- **Idleness needs evidence.** A load balancer or NAT gateway with no CloudWatch
  datapoints, or younger than the lookback window, is never reported.
- **A stopped instance with an unreadable stop time is not "old".** With
  `--older-than`, it is skipped.

## Install

The package is not published on PyPI; install it straight from GitHub:

```bash
pip install git+https://github.com/moveeeax/aws-orphan-finder
```

Or from source:

```bash
git clone https://github.com/moveeeax/aws-orphan-finder.git
cd aws-orphan-finder
pip install -e ".[dev]"
```

## Usage

Uses your standard AWS credential chain (env vars, `~/.aws/credentials`, SSO, or
`--profile`). It only needs read permissions: `ec2:Describe*`,
`elasticloadbalancing:Describe*` and `cloudwatch:GetMetricStatistics`. Note that
`ec2:DescribeImages` is required, because the snapshot check refuses to run without
it. A missing permission skips only the checks that need it.

```bash
# Scan two regions, only volumes/snapshots older than 30 days
aws-orphan-finder scan --regions eu-west-1,us-east-1 --older-than 30d

# JSON output (great for piping into jq or a dashboard)
aws-orphan-finder scan --regions us-east-1 --output json

# CSV output
aws-orphan-finder scan --regions us-east-1 --format csv

# Idle load balancers and NAT gateways over 30 days, stricter threshold
aws-orphan-finder scan --regions eu-west-1 --lb-lookback 30d --lb-min-traffic 10

# One row per snapshot chain instead of one per snapshot
aws-orphan-finder scan --regions eu-west-1 --group-by volume

# Where the public IPv4 bill comes from, in use or not
aws-orphan-finder scan --regions eu-west-1,us-east-1 --public-ipv4

# HTML report, and the deletion candidates as (commented-out) AWS CLI commands
aws-orphan-finder scan --regions us-east-1 --format html > report.html
aws-orphan-finder scan --regions us-east-1 --format commands > candidates.sh
```

### Options

| Flag | Description |
| --- | --- |
| `--regions` | Comma-separated regions to scan (required) |
| `--older-than` | Age filter for volumes, snapshots and stopped instances: `30d`, `2w`, `3m`, or a number of days |
| `--lb-lookback` / `--idle-lookback` | CloudWatch window for load balancers and NAT gateways (default `14d`) |
| `--lb-min-traffic` / `--idle-min-traffic` | Traffic over the window below which they are idle: requests (ALB, CLB), new flows (NLB, GWLB), packets out (NAT). Default `100` |
| `--ami-unused` | Report AMIs not launched within this age (default `90d`) |
| `--group-by volume` | Collapse snapshots into one row per source volume (table, HTML) and add `snapshot_groups` to JSON |
| `--public-ipv4` | Add the public IPv4 spend report (see below) |
| `--output` / `--format` | `table` (default), `json`, `csv`, `html`, or `commands` |
| `--profile` | AWS named profile |
| `--ignore-errors` | Exit `0` even if some checks were skipped |

### Output formats

- `json` carries `findings`, `summary` and `errors`, plus `snapshot_groups` with
  `--group-by volume` and `public_ipv4` with `--public-ipv4`.
- `csv` is the findings only, one row per resource.
- `html` is one self-contained page (no scripts, no external assets).
- `commands` is the deletion candidate list as AWS CLI commands. Every line is
  commented out, so piping it into a shell does nothing; uncomment what you have
  decided to delete. The tool itself never runs any of them.

With `--group-by volume`, a group of 30 or more snapshots whose oldest is 90+
days old is marked `possible_unpruned_retention`: it looks like a schedule that
creates and never deletes. That is a heuristic; the API does not say whether a
retention rule exists.

### Public IPv4 report

Since 2024-02-01 AWS charges $0.005/hour for every public IPv4 address, attached
or idle ([VPC pricing](https://aws.amazon.com/vpc/pricing/)). `--public-ipv4`
lists every public address on a network interface plus every Elastic IP on none,
grouped by owner (`instance`, `nat_gateway`, `load_balancer`, `rds`,
`unattached_eip`, ...), and lists subnets with `MapPublicIpOnLaunch=true`, which
hand a billed address to every instance launched in them. Addresses from a BYOIP
pool are counted at $0. This is spend, not waste: it stays out of the findings
and their totals.

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
│ eu-west-1 │ eip        │ eipalloc-0a1b │      3.65 │ not associated        │
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
  public IPv4 at the flat $0.005/hour, EBS volumes by type and size, snapshots and
  AMIs by size (at full size, so an upper bound for incremental snapshots), load
  balancers and NAT gateways at their hourly charge without usage units.
  Estimates are deliberately conservative approximations, not a billing source of truth.
- Multi-region results are aggregated into per-region, per-kind, and total summaries.

## Read-only guarantee

The tool only ever calls `Describe*` APIs and CloudWatch `GetMetricStatistics`. There is no code path that deletes,
releases, or modifies a resource, and a test asserts that no mutating call is made.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

[MIT](LICENSE)
