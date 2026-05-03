"""
Restore SIEM SQLite database from a backup file.

Usage:
  python scripts/restore_db.py --from backups/siem-YYYYMMDD-HHMMSS.db
  python scripts/restore_db.py --from backups/siem-YYYYMMDD-HHMMSS.db --force
"""

from __future__ import annotations

import argparse
import shutil
from datetime import datetime, timezone
from pathlib import Path


def restore_backup(src_backup: Path, db_path: Path, force: bool) -> Path:
    if not src_backup.exists():
        raise FileNotFoundError(f"Backup file not found: {src_backup}")

    db_path.parent.mkdir(parents=True, exist_ok=True)

    if db_path.exists() and not force:
        raise FileExistsError(
            f"Destination DB already exists: {db_path} (use --force to overwrite)"
        )

    pre_restore = None
    if db_path.exists():
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        pre_restore = db_path.parent / f"siem-pre-restore-{ts}.db"
        shutil.copy2(db_path, pre_restore)

    shutil.copy2(src_backup, db_path)
    return pre_restore


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore SIEM SQLite database backup.")
    parser.add_argument("--from", dest="source", required=True, help="Path to backup DB file.")
    parser.add_argument("--db", default="data/siem.db", help="Destination DB path.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite destination DB if it already exists.",
    )
    args = parser.parse_args()

    src = Path(args.source)
    dst = Path(args.db)
    pre_restore = restore_backup(src, dst, force=args.force)

    if pre_restore:
        print(f"Previous DB snapshot saved: {pre_restore}")
    print(f"Restore completed: {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
