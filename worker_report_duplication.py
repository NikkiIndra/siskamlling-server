# worker_report_duplication.py
import os
import sys
import time
from datetime import datetime

# pastikan path project ada
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from models import db, Reports, ReportDuplicationCheck
from database_config import get_connection
from utils import check_similarity

# This function name should match the string enqueued in main.py
def process_report_duplication(report_id, jenis_laporan, latitude, longitude, deskripsi, desa_id):
    """
    Background job: compute similarity vs other reports and update DB.
    """
    try:
        # load app context if needed (depending on how models/db are configured)
        # Here we use direct DB connection to query older reports in the same desa
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Load other recent reports in same desa (limit to last N to limit work)
        # We limit to last 500 reports (tuneable), and exclude the new report_id
        cursor.execute("""
            SELECT id, jenis_laporan, latitude, longitude, deskripsi
            FROM reports
            WHERE desa_id = %s AND id != %s
            ORDER BY created_at DESC
            LIMIT 500
        """, (desa_id, report_id))
        all_reports = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert to ORM-like objects expected by check_similarity (if your check expects model objects,
        # you can adapt check_similarity to accept dicts, or re-query with ORM here)
        # For simplicity, let's create lightweight objects
        class SimpleReport:
            def __init__(self, d):
                self.id = d['id']
                self.jenis_laporan = d.get('jenis_laporan')
                self.latitude = d.get('latitude')
                self.longitude = d.get('longitude')
                self.deskripsi = d.get('deskripsi')

        wrapped_reports = [SimpleReport(r) for r in all_reports]

        # Now call check_similarity (assumes this function can accept this shape)
        similarity_score, classification = check_similarity(
            jenis_laporan, latitude, longitude, deskripsi, wrapped_reports, report_id
        )

        # Update Reports table via SQLAlchemy ORM for the specific report
        # Use app's db session
        r = Reports.query.get(report_id)
        if not r:
            # might be deleted — nothing to do
            return {"success": False, "message": "Report not found"}

        r.status = classification
        r.similarity_score = similarity_score
        r.updated_at = datetime.utcnow()
        db.session.commit()

        # Optionally: insert details into ReportDuplicationCheck table
        # check_similarity might return per-comparison results; if not, adapt accordingly.
        # For now, create a simple check record with overall fields
        check = ReportDuplicationCheck(
            report_id=report_id,
            compared_with_id=None,
            jenis_score=None,
            lokasi_score=None,
            deskripsi_score=None,
            total_score=similarity_score,
            classification=classification,
            checked_at=datetime.utcnow()
        )
        db.session.add(check)
        db.session.commit()

        return {"success": True, "similarity_score": similarity_score, "classification": classification}

    except Exception as e:
        try:
            db.session.rollback()
        except:
            pass
        print("❌ Worker error:", str(e))
        return {"success": False, "error": str(e)}
