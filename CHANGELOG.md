# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-04

### Fixed

- Snapshots that back a registered self-owned AMI are no longer reported as
  orphans; snapshots that are not yet `completed` are skipped.
- An Elastic IP bound through `InstanceId` or `NetworkInterfaceId` is no longer
  reported as unattached.
- EBS volumes and ENIs that still carry an attachment record (for example,
  mid-detach) are no longer reported as idle.
- A repeated `--regions` entry no longer doubles findings and reported spend;
  region names are validated.
- boto3 clients use explicit connect/read timeouts (10 s / 30 s), so a
  blackholed region endpoint cannot hang a scan for tens of minutes.
- `render()` treats field values as plain text, so bracketed strings no longer
  raise `rich.errors.MarkupError` or get reformatted.

### Changed

- AWS errors no longer crash the scan. A failed call skips only the affected
  check; skipped checks are listed in the JSON payload and the table, warned
  about on stderr, and make the CLI exit with code 2 unless `--ignore-errors`
  is passed.
- Pagination is all-or-nothing and detects a repeated `NextToken`; clients use
  adaptive retries for throttling.
- Python 3.11 or newer is required (3.9 and 3.10 are end-of-life). CI tests
  3.11 through 3.15.
- Minimum dependency versions raised: `boto3>=1.35`, `rich>=14.0`; the build
  requires `setuptools>=77` for the SPDX license expression.
- README install instructions now point at GitHub: the package is not
  published on PyPI.

## [0.1.0] - 2026-07-19

### Added

- First release: scanner for unattached Elastic IPs, available EBS volumes,
  unattached ENIs and stale snapshots across regions, with monthly cost
  estimates and table/JSON output.

[0.2.0]: https://github.com/moveeeax/aws-orphan-finder/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/moveeeax/aws-orphan-finder/releases/tag/v0.1.0
