# Backup and Recovery Guide

## Overview

This project includes two utility scripts:

- `scripts/backup_db.py` - creates timestamped backups of `data/siem.db`
- `scripts/restore_db.py` - restores a selected backup into `data/siem.db`

---

## Create a Backup

```bash
python scripts/backup_db.py
```

Default behavior:

- source DB: `data/siem.db`
- output folder: `backups/`
- retention: remove backups older than 14 days

Custom example:

```bash
python scripts/backup_db.py --db data/siem.db --out backups --keep-days 30
```

---

## Restore a Backup

```bash
python scripts/restore_db.py --from backups/siem-YYYYMMDD-HHMMSS.db --force
```

Notes:

- `--force` is required if `data/siem.db` already exists.
- On restore with `--force`, a pre-restore snapshot is automatically created:
  - `data/siem-pre-restore-YYYYMMDD-HHMMSS.db`

---

## Recommended Operations Schedule

- Daily backup (at least once per day)
- Retention: 14-30 days
- Monthly restore drill to verify backups are usable

---

## Windows Task Scheduler (example)

Program/script:

```text
python
```

Arguments:

```text
scripts/backup_db.py --keep-days 30
```

Start in:

```text
C:\Users\MPC\Desktop\Python\Homelab_SIEM
```
