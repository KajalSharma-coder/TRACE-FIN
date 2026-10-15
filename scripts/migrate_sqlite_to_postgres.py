"""
TRACE//FIN — SQLite to Neon PostgreSQL Data Migration Utility
Migrates legacy SQLite records (data/tracefin.db) to Neon-hosted PostgreSQL.
Safe, transactional, idempotent (avoids duplicates), and never leaks credentials.

Usage:
    python scripts/migrate_sqlite_to_postgres.py [--dry-run] [--source PATH]
"""

import argparse
import logging
from pathlib import Path
import sqlite3
import sys

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import DB_PATH
from src.database import (
    advertisements_table,
    check_database_connection,
    get_database_url,
    get_engine,
    init_db,
    mask_db_url,
    select,
    text,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("tracefin.migrate")


def migrate_sqlite_to_postgres(source_sqlite_path: Path, dry_run: bool = False) -> dict:
    """
    Safely migrate advertisement records from SQLite into PostgreSQL.
    Returns migration report summary.
    """
    if not source_sqlite_path.exists():
        logger.error("Source SQLite database not found at: %s", source_sqlite_path)
        return {"success": False, "error": f"Source database not found: {source_sqlite_path}"}

    # Verify PostgreSQL target is configured
    pg_url = get_database_url()
    if not pg_url or "postgres" not in pg_url.lower():
        logger.error("Target database is not configured as PostgreSQL. Set DATABASE_URL.")
        return {"success": False, "error": "Target DATABASE_URL is not configured for PostgreSQL."}

    logger.info("Target PostgreSQL: %s", mask_db_url(pg_url))
    logger.info("Source SQLite:     %s", source_sqlite_path)
    if dry_run:
        logger.info("[DRY RUN MODE] No changes will be committed to PostgreSQL.")

    # 1. Initialize PostgreSQL schema idempotently
    if not dry_run:
        init_db()

    target_engine = get_engine()

    # 2. Read all records from SQLite
    sqlite_conn = sqlite3.connect(str(source_sqlite_path))
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cursor = sqlite_conn.cursor()

    sqlite_cursor.execute("SELECT * FROM advertisements ORDER BY submitted_at ASC")
    sqlite_rows = sqlite_cursor.fetchall()
    total_sqlite_count = len(sqlite_rows)
    logger.info("Found %d record(s) in SQLite source database.", total_sqlite_count)

    if total_sqlite_count == 0:
        logger.info("SQLite database contains 0 records. Nothing to migrate.")
        sqlite_conn.close()
        return {"success": True, "total": 0, "inserted": 0, "skipped": 0, "failed": 0}

    # 3. Fetch existing record IDs from PostgreSQL to guarantee idempotency
    existing_pg_ids = set()
    with target_engine.connect() as conn:
        stmt = select(advertisements_table.c.record_id)
        existing_pg_ids = set(conn.execute(stmt).scalars().all())

    logger.info("Found %d existing record(s) in target PostgreSQL database.", len(existing_pg_ids))

    inserted = 0
    skipped = 0
    failed = 0
    errors = []

    # 4. Migrate records using transactions
    with target_engine.connect() as pg_conn:
        trans = pg_conn.begin()
        try:
            for row in sqlite_rows:
                r_dict = dict(row)
                rec_id = r_dict.get("record_id")
                if not rec_id:
                    continue

                if rec_id in existing_pg_ids:
                    skipped += 1
                    continue

                # Ensure non-null values for required fields
                cleaned_record = {
                    "record_id": rec_id,
                    "ad_text": r_dict.get("ad_text", ""),
                    "submitted_at": r_dict.get("submitted_at") or "",
                    "analysis_mode": r_dict.get("analysis_mode", "rule_based"),
                    "risk_score": float(r_dict.get("risk_score", 0.0) or 0.0),
                    "risk_level": r_dict.get("risk_level", "Low"),
                    "matched_categories": r_dict.get("matched_categories", "[]"),
                    "evidence": r_dict.get("evidence", "[]"),
                    "urls": r_dict.get("urls", "[]"),
                    "emails": r_dict.get("emails", "[]"),
                    "phone_numbers": r_dict.get("phone_numbers", "[]"),
                    "payment_identifiers": r_dict.get("payment_identifiers", "[]"),
                    "review_required": int(r_dict.get("review_required", 0) or 0),
                    "review_recommendation": r_dict.get("review_recommendation", "No Immediate Review Indicated"),
                    "investigation_status": r_dict.get("investigation_status", "Open"),
                    "is_synthetic": int(r_dict.get("is_synthetic", 0) or 0),
                    "ml_prediction": r_dict.get("ml_prediction"),
                    "ml_confidence": float(r_dict["ml_confidence"]) if r_dict.get("ml_confidence") is not None else None,
                    "ml_high_risk_score": float(r_dict["ml_high_risk_score"]) if r_dict.get("ml_high_risk_score") is not None else None,
                    "ml_model_version": r_dict.get("ml_model_version"),
                    "hf_prediction": r_dict.get("hf_prediction"),
                    "hf_confidence": float(r_dict["hf_confidence"]) if r_dict.get("hf_confidence") is not None else None,
                    "hf_model_version": r_dict.get("hf_model_version"),
                }

                if not dry_run:
                    pg_conn.execute(advertisements_table.insert().values(**cleaned_record))
                existing_pg_ids.add(rec_id)
                inserted += 1

            if dry_run:
                trans.rollback()
                logger.info("[DRY RUN] Rolled back transaction successfully.")
            else:
                trans.commit()
                logger.info("Successfully committed transaction to PostgreSQL.")

        except Exception as exc:
            trans.rollback()
            logger.error("Migration transaction failed and was rolled back: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "total": total_sqlite_count,
                "inserted": 0,
                "skipped": skipped,
                "failed": total_sqlite_count - skipped,
            }
        finally:
            sqlite_conn.close()

    # Verify final count in target
    health = check_database_connection()
    logger.info(
        "Migration Complete: %d inserted, %d skipped (duplicates), %d failed. Total target records: %d",
        inserted,
        skipped,
        failed,
        health.get("record_count", 0),
    )

    return {
        "success": True,
        "total": total_sqlite_count,
        "inserted": inserted,
        "skipped": skipped,
        "failed": failed,
        "target_total": health.get("record_count", 0),
    }


def main():
    parser = argparse.ArgumentParser(description="Migrate TRACE//FIN SQLite records to Neon PostgreSQL")
    parser.add_argument(
        "--source",
        type=Path,
        default=DB_PATH,
        help="Path to source SQLite database (default: data/tracefin.db)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate migration without committing changes",
    )
    args = parser.parse_args()

    report = migrate_sqlite_to_postgres(args.source, dry_run=args.dry_run)
    if not report.get("success"):
        logger.error("Migration failed: %s", report.get("error"))
        sys.exit(1)

    print("\n" + "=" * 50)
    print("✓ TRACE//FIN DATA MIGRATION SUMMARY")
    print("=" * 50)
    print(f"Source records in SQLite:  {report['total']}")
    print(f"Records migrated to Neon:  {report['inserted']}")
    print(f"Records skipped (already): {report['skipped']}")
    print(f"Current Neon record count: {report.get('target_total', 'N/A')}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
