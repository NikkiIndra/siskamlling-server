import math
from datetime import datetime
from difflib import SequenceMatcher
from models import ReportDuplicationCheck  # pastikan import ini sesuai struktur kamu
from models import db

def haversine(lat1, lon1, lat2, lon2):
    """Hitung jarak dalam meter menggunakan rumus Haversine"""
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def check_similarity(jenis, lat, lon, desc, all_reports, temp_report_id=None):
    """Cek duplikasi laporan dengan logika bertingkat dan simpan hasil ke tabel check"""
    best_score = 0
    best_status = "baru"

    for report in all_reports:
        jenis_score = 0
        lokasi_score = 0
        deskripsi_score = 0
        total_score = 0
        classification = "unique"

        # Tahap 1: cek jenis
        if report.jenis_laporan.lower() == jenis.lower():
            jenis_score = 33
        else:
            # langsung skip, simpan hasil "unique"
            _save_dup_check(temp_report_id, report.id, jenis_score, lokasi_score,
                            deskripsi_score, total_score, classification)
            continue

        # Tahap 2: cek lokasi
        distance = haversine(lat, lon, report.latitude, report.longitude)
        if distance <= 50:
            lokasi_score = 33
        else:
            # lokasi jauh, stop di sini
            total_score = jenis_score
            _save_dup_check(temp_report_id, report.id, jenis_score, lokasi_score,
                            deskripsi_score, total_score, "unique")
            continue

        # Tahap 3: cek deskripsi
        desc_ratio = SequenceMatcher(None, desc.lower(), report.deskripsi.lower()).ratio()
        deskripsi_score = desc_ratio * 33
        total_score = jenis_score + lokasi_score + deskripsi_score

        # Tentukan klasifikasi
        if total_score > 85:
            classification = "duplicate"
        elif total_score >= 65:
            classification = "indication"
        else:
            classification = "unique"

        # Simpan hasil perbandingan ke DB
        _save_dup_check(temp_report_id, report.id, jenis_score, lokasi_score,
                        deskripsi_score, total_score, classification)

        # Simpan hasil terbaik untuk laporan utama
        if total_score > best_score:
            best_score = total_score
            best_status = (
                "duplikasi" if classification == "duplicate"
                else "indikasi_duplikasi" if classification == "indication"
                else "baru"
            )

    return best_score, best_status


def _save_dup_check(report_id, compared_id, jenis_score, lokasi_score,
                    deskripsi_score, total_score, classification):
    """Helper untuk menyimpan hasil ke tabel siskamling_digital_report_duplication_check"""
    dup_check = ReportDuplicationCheck(
        report_id=report_id,
        compared_with_id=compared_id,
        jenis_score=jenis_score,
        lokasi_score=lokasi_score,
        deskripsi_score=deskripsi_score,
        total_score=total_score,
        classification=classification,
        checked_at=datetime.utcnow()
    )
    db.session.add(dup_check)
    db.session.flush()  # flush supaya bisa dipakai sebelum commit
