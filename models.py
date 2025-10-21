from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class Reports(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    desa_id = db.Column(db.Integer, nullable=False)
    jenis_laporan = db.Column(db.String(100))
    nama_pelapor = db.Column(db.String(100))
    alamat = db.Column(db.Text)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    tanggal = db.Column(db.DateTime)
    deskripsi = db.Column(db.Text)
    foto_url = db.Column(db.String(255))
    status = db.Column(db.Enum('baru', 'indikasi_duplikasi', 'duplikasi'))
    similarity_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime)

class ReportDuplicationCheck(db.Model):
    __tablename__ = 'report_duplication_check'
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer)
    compared_with_id = db.Column(db.Integer)
    jenis_score = db.Column(db.Float)
    lokasi_score = db.Column(db.Float)
    deskripsi_score = db.Column(db.Float)
    total_score = db.Column(db.Float)
    classification = db.Column(db.Enum('unique','indication','duplicate'))
    checked_at = db.Column(db.DateTime)
