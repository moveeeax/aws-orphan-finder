# aws-orphan-finder

> Find the AWS resources quietly billing you for nothing — and see the monthly savings.

**Status:** 🚧 In development

## Overview

CLI that finds orphaned AWS resources (unattached EIPs, EBS volumes, ENIs, old snapshots) and estimates monthly waste.

## Features

- Scan for unattached Elastic IPs, available EBS volumes, detached ENIs and stale snapshots
- Estimate monthly $ waste per finding using region pricing
- Multi-region scan with account/region summary
- Output as table, JSON or CSV; read-only by default
- Optional `--older-than` filter for snapshots/volumes

## Stack

Python 3.11, `boto3`, `rich` tables, AWS pricing data.

## Usage

```bash
pip install aws-orphan-finder
aws-orphan-finder scan --regions eu-west-1,us-east-1 --older-than 30d
```

## License

MIT
