#!/usr/bin/env python3
"""
Prune old events and alerts from data/siem.db.

Usage:
    python scripts/prune_db.py
    python scripts/prune_db.py --days 14

Schedule via cron (daily at 03:00):
    0 3 * * * cd /path/to/Homelab_SIEM && .venv/bin/python scripts/prune_db.py
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from siem.storage import prune_old_data, RETENTION_DAYS  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Prune old SIEM database rows")
    parser.add_argument(
        "--days", type=int, default=None,
        help=f"Retention window in days (default: SIEM_RETENTION_DAYS={RETENTION_DAYS})",
    )
    args = parser.parse_args()
    result = prune_old_data(retention_days=args.days)
    print(result)


if __name__ == "__main__":
    main()
