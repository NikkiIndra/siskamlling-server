from datetime import datetime, timezone
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ReportDuplicationCheck(db.Model):
    __tablename__ = 'report_duplication_check'
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, nullable=False)
    compared_with_id = db.Column(db.Integer, nullable=False)
    jenis_score = db.Column(db.Float, nullable=True)
    lokasi_score = db.Column(db.Float, nullable=True)
    deskripsi_score = db.Column(db.Float, nullable=True)
    total_score = db.Column(db.Float, nullable=True)
    classification = db.Column(db.Enum('unique', 'indication', 'duplicate'))
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)


class Messages(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    desa_id = db.Column(db.Integer, nullable=False)
    # device_id = db.Column(db.Integer, db.ForeignKey('iot_device.id'), nullable=True)
    user_id = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    tts_url = db.Column(db.String(255), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class IoTDevice(db.Model):
    __tablename__ = 'iot_device'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50))
    device_ip = db.Column(db.String(100))
    desa_id = db.Column(db.Integer)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime)
