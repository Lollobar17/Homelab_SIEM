"""
Create timestamped SQLite backups with retention cleanup.

Usage:
  python scripts/backup_db.py
  python scripts/backup_db.py --db data/siem.db --out backups --keep-days 14
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


def make_backup(db_path: Path, out_dir: Path) -> Path:
    if not db_path.exists():
        raise FileNotFoundError(f"Database file not found: {db_path}")

    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = out_dir / f"siem-{ts}.db"

    src = sqlite3.connect(str(db_path))
    dst = sqlite3.connect(str(backup_path))
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()
    return backup_path


def cleanup_old_backups(out_dir: Path, keep_days: int) -> int:
    if keep_days <= 0 or not out_dir.exists():
        return 0
    threshold = datetime.now(timezone.utc) - timedelta(days=keep_days)
    removed = 0
    for file_path in out_dir.glob("siem-*.db"):
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
        if mtime < threshold:
            file_path.unlink(missing_ok=True)
            removed += 1
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description="Backup SIEM SQLite database.")
    parser.add_argument("--db", default="data/siem.db", help="Path to source SQLite DB.")
    parser.add_argument("--out", default="backups", help="Directory for backups.")
    parser.add_argument(
        "--keep-days",
        type=int,
        default=14,
        help="Delete backups older than N days (<=0 disables cleanup).",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    out_dir = Path(args.out)

    backup_path = make_backup(db_path, out_dir)
    removed = cleanup_old_backups(out_dir, args.keep_days)

    print(f"Backup created: {backup_path}")
    print(f"Retention cleanup removed: {removed} old backup(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
