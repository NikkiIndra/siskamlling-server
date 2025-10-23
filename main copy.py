# app.py
import os
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
import eventlet
eventlet.monkey_patch()  # HARUS di paling atas sebelum import Flask, requests, dll

from dotenv import load_dotenv
load_dotenv()  # baca file .env lebih awal

import json
import time
import traceback
import requests
import uuid
import paho.mqtt.publish as publish  
import redis
from flask_caching import Cache
from rq import Queue
from rq.job import Job
from gtts import gTTS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
from flask import Flask, request, jsonify, send_file, send_from_directory, g
from flask_cors import CORS
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from models import Reports, ReportDuplicationCheck
from flask_sqlalchemy import SQLAlchemy
#import file utils
from utils import check_similarity

from database_config import get_connection
from tts_utils import generate_mp3

import eventlet.wsgi
import inspect

# ==========================
# APP & CONFIG INIT
# ==========================
app = Flask(__name__)
# keep original CORS config from your file
CORS(app, supports_credentials=True)

# ====== Redis config (env-overridable) ======
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
redis_conn = redis.from_url(REDIS_URL)
# Initialize Flask-Caching
cache_config = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_REDIS_URL": REDIS_URL,
    "CACHE_DEFAULT_TIMEOUT": 30  # default 30s (tuneable)
}
app.config.from_mapping(cache_config)
cache = Cache(app)
# RQ queue for background tasks
rq_queue = Queue("reports", connection=redis_conn)

DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "siskamling_digital")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


from models import db, Reports, ReportDuplicationCheck
db.init_app(app)


# SocketIO pakai eventlet mode
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    message_queue=os.environ.get("REDIS_URL")
)

# @socketio.on("join_room")
# def handle_join_room(data):
#     desa_id = data.get("desa_id")
#     join_room(f"desa_{desa_id}")


# ==========================
# GLOBAL REQUESTS SESSION
# ==========================
requests_session = requests.Session()
retry_strategy = Retry(
    total=2,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
requests_session.mount("http://", adapter)
requests_session.mount("https://", adapter)

# Store connected admin clients
admin_clients = {}

# ==========================
# Konfigurasi Upload 
# ==========================
UPLOAD_FOLDER = 'uploads'
PROFILE_IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'profile_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(PROFILE_IMAGES_FOLDER, exist_ok=True)

print("DB_HOST:", os.environ.get("DB_HOST"))

# folder untuk menyimpan file audio
# AUDIO_FOLDER = 'audio'
# if not os.path.exists(AUDIO_FOLDER):
#     os.makedirs(AUDIO_FOLDER)

AUDIO_DIR = "audio"
# ESP32_IP = "http://10.234.3.57:8080"  # Ganti dengan IP ESP32 
ESP32_IP = "http://10.12.114.191:8080"  # Ganti dengan IP ESP32 

if not os.path.exists(AUDIO_DIR):
    os.makedirs(AUDIO_DIR)

# untuk tracking berapa kali file sudah diakses
# setelah 3 kali diakses, file akan dihapus
play_count = defaultdict(int)

# konfigurasi MQTT
MQTT_BROKER = "localhost"  # atau IP VPS kamu
MQTT_PORT = 1883

# ==========================
# HELPERS & AUTH REPLACEMENT
# ==========================
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_exc(prefix=""):
    print(prefix)
    traceback.print_exc()

def publish_mqtt(code_desa, message):
    topic = f"desa/{code_desa}"
    publish.single(topic, message, hostname=MQTT_BROKER, port=MQTT_PORT)

@app.route('/api/report/create', methods=['POST'])
def create_report():
    """
    Fast path: save report record quickly with status 'pending',
    then enqueue background job to run check_similarity and update the record.
    """
    try:
        jenis_laporan = request.form.get('jenis_laporan')
        nama_pelapor = request.form.get('nama_pelapor')
        alamat = request.form.get('alamat')
        deskripsi = request.form.get('deskripsi')
        tanggal_str = request.form.get('tanggal')  # 'YYYY-MM-DD'
        tanggal = datetime.strptime(tanggal_str, '%Y-%m-%d') if tanggal_str else None
        latitude = float(request.form.get('latitude')) if request.form.get('latitude') else None
        longitude = float(request.form.get('longitude')) if request.form.get('longitude') else None
        desa_id = int(request.form.get('desa_id'))
        user_id = int(request.form.get('user_id'))

        if not desa_id or not user_id:
            return jsonify({"status": "error", "message": "desa_id atau user_id kosong"}), 400

        # Upload photo(s) as before (kept)
        fotos = request.files.getlist('images')
        foto_url = None
        if fotos:
            for foto in fotos:
                filename = f"{uuid.uuid4().hex}_{secure_filename(foto.filename)}"
                foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                foto_url = f"/static/uploads/{filename}"

        # Create temporary report quick
        # ly with status 'pending'
        temp_report = Reports(
            user_id=user_id,
            desa_id=desa_id,
            jenis_laporan=jenis_laporan,
            nama_pelapor=nama_pelapor,
            alamat=alamat,
            latitude=latitude,
            longitude=longitude,
            tanggal=tanggal,
            deskripsi=deskripsi,
            foto_url=foto_url,
            created_at=datetime.utcnow(),
            status='pending',           # immediately mark pending
            similarity_score=None
        )
        db.session.add(temp_report)
        db.session.commit()

        # ENQUEUE background job to compute similarity
        # We will pass the necessary minimal info: report_id and desa_id and the text fields
        job = rq_queue.enqueue(
            'worker_report_duplication.process_report_duplication',
            temp_report.id,
            jenis_laporan,
            latitude,
            longitude,
            deskripsi,
            desa_id,
            job_timeout=120  # seconds, tuneable
        )

        return jsonify({
            "status": "success",
            "message": "Laporan disimpan (diproses background)",
            "report_id": temp_report.id,
            "job_id": job.get_id()
        }), 202

    except Exception as e:
        db.session.rollback()
        log_exc("=== ERROR create_report (fast path) ===")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/report/list', methods=['GET'])
def get_reports_by_desa():
    try:
        desa_id = request.headers.get("X-Desa-Id")
        role = request.headers.get("X-User-Role")
        if not desa_id:
            return jsonify({"status": "error", "message": "Desa ID tidak ditemukan di header"}), 400

        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        offset = (page - 1) * per_page
        cache_key = f"reports:{desa_id}:{role}:page{page}:per{per_page}"
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)

        # use raw SQL with LIMIT/OFFSET to avoid loading all into memory
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, jenis_laporan, nama_pelapor, alamat, deskripsi, latitude, longitude,
            tanggal, foto_url, status, similarity_score, created_at
            FROM reports
            WHERE desa_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (desa_id, per_page, offset))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "jenis_laporan": r["jenis_laporan"],
                "nama_pelapor": r["nama_pelapor"],
                "alamat": r["alamat"],
                "deskripsi": r["deskripsi"],
                "latitude": r["latitude"],
                "longitude": r["longitude"],
                "tanggal": r["tanggal"].strftime("%Y-%m-%d %H:%M:%S") if r["tanggal"] else None,
                "foto_url": r["foto_url"],
                "status": r["status"],
                "similarity_score": r["similarity_score"],
                "created_at": r["created_at"].strftime("%Y-%m-%d %H:%M:%S") if r["created_at"] else None,
            })

        resp = {"status": "success", "page": page, "per_page": per_page, "count": len(result), "data": result}
        cache.set(cache_key, resp, timeout=30)
        return jsonify(resp)

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/report/detail/<int:report_id>', methods=['GET'])
def get_report_detail(report_id):
    try:
        desa_id = request.headers.get("X-Desa-Id")

        if not desa_id:
            return jsonify({"status": "error", "message": "Desa ID tidak ditemukan di header"}), 400

        report = Reports.query.filter_by(id=report_id, desa_id=desa_id).first()

        if not report:
            return jsonify({"status": "error", "message": "Laporan tidak ditemukan atau tidak sesuai desa"}), 404

        # Ambil semua hasil perbandingan duplikasi dari tabel check
        dup_checks = ReportDuplicationCheck.query.filter_by(report_id=report.id).all()
        comparisons = [
            {
                "compared_with_id": c.compared_with_id,
                "jenis_score": c.jenis_score,
                "lokasi_score": c.lokasi_score,
                "deskripsi_score": c.deskripsi_score,
                "total_score": c.total_score,
                "classification": c.classification,
                "checked_at": c.checked_at.strftime("%Y-%m-%d %H:%M:%S")
            } for c in dup_checks
        ]

        return jsonify({
            "status": "success",
            "data": {
                "id": report.id,
                "jenis_laporan": report.jenis_laporan,
                "nama_pelapor": report.nama_pelapor,
                "alamat": report.alamat,
                "deskripsi": report.deskripsi,
                "latitude": report.latitude,
                "longitude": report.longitude,
                "tanggal": report.tanggal.strftime("%Y-%m-%d %H:%M:%S") if report.tanggal else None,
                "foto_url": report.foto_url,
                "status": report.status,
                "similarity_score": report.similarity_score,
                "created_at": report.created_at.strftime("%Y-%m-%d %H:%M:%S") if report.created_at else None,
                "duplication_checks": comparisons
            }
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/report/list/<status>', methods=['GET'])
def get_reports_by_status(status):
    try:
        desa_id = request.headers.get("X-Desa-Id")
        if not desa_id:
            return jsonify({"status": "error", "message": "Desa ID tidak ditemukan di header"}), 400

        valid_status = ['baru', 'indikasi_duplikasi', 'duplikasi']
        if status not in valid_status:
            return jsonify({"status": "error", "message": "Status tidak valid"}), 400

        reports = Reports.query.filter_by(desa_id=desa_id, status=status).order_by(Reports.created_at.desc()).all()

        result = [{
            "id": r.id,
            "jenis_laporan": r.jenis_laporan,
            "nama_pelapor": r.nama_pelapor,
            "alamat": r.alamat,
            "deskripsi": r.deskripsi,
            "foto_url": r.foto_url,
            "status": r.status,
            "similarity_score": r.similarity_score
        } for r in reports]

        return jsonify({"status": "success", "count": len(result), "data": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Simple auth replacement for JWT:
# - Reads user_id, role, desa_id from headers or query params.
# - Sets them on flask.g for handlers to use.
from functools import wraps
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Try headers first
        user_id = request.headers.get('X-User-Id') 
        role = request.headers.get('X-User-Role') 
        desa_id = request.headers.get('X-Desa-Id')
        
        # Jika tidak ada di header, coba dari form data (untuk multipart)
        if not user_id:
            user_id = request.form.get('user_id')
        if not role:
            role = request.form.get('role') 
        if not desa_id:
            desa_id = request.form.get('desa_id')
            
        # Jika masih tidak ada, coba dari query params
        if not user_id:
            user_id = request.args.get('user_id')
        if not role:
            role = request.args.get('role')
        if not desa_id:
            desa_id = request.args.get('desa_id')

        # Debug logging
        print(f"🔐 Auth Debug - Headers: {dict(request.headers)}")
        print(f"🔐 Auth Debug - Form: {dict(request.form)}")
        print(f"🔐 Auth Debug - Found: user_id={user_id}, role={role}, desa_id={desa_id}")

        # normalize types
        try:
            if user_id is not None:
                user_id = int(user_id)
            if desa_id is not None:
                desa_id = int(desa_id)
        except Exception:
            return jsonify({"success": False, "message": "user_id/desa_id harus berupa integer"}), 400

        if not user_id or not role:
            # unauthorized - missing auth info
            return jsonify({"success": False, "message": "Unauthorized: user_id dan role dibutuhkan (header atau query param)"}), 401

        # set to flask.g
        g.user_id = user_id
        g.role = role
        g.desa_id = desa_id

        return f(*args, **kwargs)
    return decorated
# =====================================================
# ROUTES (only JWT-related logic removed; rest preserved)
# =====================================================

@app.route("/users", methods=["GET"])
@require_auth
def get_users():
    try:
        current_user_id = g.user_id  # sekarang berisi ID user
        role = g.role
        desa_id = g.desa_id

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Validasi user
        cursor.execute("SELECT id FROM user WHERE id=%s", (current_user_id,))
        user_login = cursor.fetchone()
        if not user_login:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

        # Ambil fields
        fields = request.args.get("fields")
        allowed_columns = {
            "id", "nama_lengkap", "email", "rt", "rw", "blok",
            "latlong", "role", "desa_id", "profile_image, createdAt"
        }
        if fields:
            selected_fields = [f for f in fields.split(",") if f in allowed_columns]
            if not selected_fields:
                cursor.close()
                conn.close()
                return jsonify({"success": False, "message": "Field tidak valid"}), 400
        else:
            selected_fields = list(allowed_columns)

        sql = f"SELECT {', '.join(selected_fields)} FROM user"

        # Filter berdasarkan role
        conditions = []
        params = []
        if role == "admin":
            conditions.append("desa_id = %s")
            params.append(desa_id)
        elif role == "user":
            conditions.append("id = %s")
            params.append(current_user_id)

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        cursor.execute(sql, params)
        users = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify({"success": True, "data": users}), 200

    except Exception as e:
        print("❌ Error:", e)
        return jsonify({"success": False, "message": str(e)}), 500

# -------------------------
# GET MESSAGES FOR ADMIN/USER (based on desa_id)
# -------------------------
@app.route("/messages", methods=["GET"])
@require_auth
def get_messages():
    try:
        desa_id = g.desa_id
        role = g.role
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))  # default 50, tuneable
        cache_key = f"messages:{desa_id}:{role}:page{page}:per{per_page}"

        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        offset = (page - 1) * per_page

        if role == "superadmin":
            cursor.execute(f"""
                SELECT 
                    m.id, m.desa_id, m.description, m.category, m.tts_url,
                    m.latitude, m.longitude, m.created_at,
                    u.nama_lengkap AS reporter_name, u.email AS reporter_email,
                    u.rt, u.rw, u.blok
                FROM messages m
                JOIN user u ON m.user_id = u.id
                ORDER BY m.created_at DESC
                LIMIT %s OFFSET %s
            """, (per_page, offset))
        else:
            cursor.execute(f"""
                SELECT 
                    m.id, m.desa_id, m.description, m.category, m.tts_url,
                    m.latitude, m.longitude, m.created_at,
                    u.nama_lengkap AS reporter_name, u.email AS reporter_email,
                    u.rt, u.rw, u.blok
                FROM messages m
                JOIN user u ON m.user_id = u.id
                WHERE u.desa_id = %s
                ORDER BY m.created_at DESC
                LIMIT %s OFFSET %s
            """, (desa_id, per_page, offset))

        messages = cursor.fetchall()
        cursor.close()
        conn.close()

        formatted = []
        for msg in messages:
            formatted.append({
                "id": msg["id"],
                "desa_id": msg["desa_id"],
                "description": msg["description"],
                "category": msg["category"],
                "tts_url": msg["tts_url"],
                "latitude": msg["latitude"],
                "longitude": msg["longitude"],
                "created_at": str(msg["created_at"]),
                "reporter": {
                    "name": msg["reporter_name"],
                    "email": msg["reporter_email"],
                    "rt": msg["rt"],
                    "rw": msg["rw"],
                    "blok": msg["blok"]
                },
                "tts_url_full": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{msg['tts_url']}" if msg["tts_url"] else None
            })

        resp = {
            "success": True,
            "desa_id": desa_id,
            "role": role,
            "page": page,
            "per_page": per_page,
            "count": len(formatted),
            "data": formatted
        }

        # Cache short time (30s default) — tune if necessary
        cache.set(cache_key, resp, timeout=30)
        return jsonify(resp), 200

    except Exception as e:
        print("❌ ERROR get_messages:", e)
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

# -------------------------
# GET ONLY COORDINATES (for map / trend report)
# -------------------------
@app.route("/messages/coords", methods=["GET"])
@require_auth
def get_message_coords():
    try:
        desa_id = g.desa_id
        role = g.role

        print(f"📨 Fetching coordinates for desa_id: {desa_id} | role: {role}")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if role == "superadmin":
            cursor.execute("""
                SELECT m.id, m.latitude, m.longitude, m.desa_id
                FROM messages m
                WHERE m.latitude IS NOT NULL AND m.longitude IS NOT NULL
            """)
        else:
            cursor.execute("""
                SELECT m.id, m.latitude, m.longitude, m.desa_id
                FROM messages m
                JOIN user u ON m.user_id = u.id
                WHERE u.desa_id = %s
                AND m.latitude IS NOT NULL AND m.longitude IS NOT NULL
            """, (desa_id,))

        messages = cursor.fetchall()
        cursor.close()
        conn.close()

        print(f"📊 Found {len(messages)} coordinates for desa_id {desa_id}")

        return jsonify({
            "success": True,
            "data": messages
        }), 200

    except Exception as e:
        print("❌ ERROR get_message_coords:", e)
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

# -------------------------
# 1. SIGNUP ADMIN
# -------------------------
@app.route("/signup-admin", methods=["POST"])
def signup_admin():
    data = request.get_json()
    email = data.get("email")
    katasandi = data.get("katasandi")
    code_desa = data.get("code_desa")

    if not all([email, katasandi, code_desa]):
        return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True, buffered=True)

    try:
        cursor.execute("SELECT id FROM desa WHERE code_desa=%s", (code_desa,))
        desa = cursor.fetchone()
        if not desa:
            return jsonify({"success": False, "message": "Kode desa tidak ditemukan"}), 400
        desa_id = desa["id"]

        cursor.execute("SELECT * FROM iot_device WHERE desa_id=%s", (desa_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "message": "Belum ada iot device terdaftar untuk kode desa ini"}), 400

        cursor.execute("SELECT * FROM user WHERE role='admin' AND desa_id=%s", (desa_id,))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "Admin sudah ada untuk desa ini"}), 400

        pw_hash = generate_password_hash(katasandi)
        cursor.execute("""
            INSERT INTO user (nama_lengkap, email, katasandi, role, desa_id)
            VALUES (%s,%s,%s,'admin',%s)
        """, ("Admin", email, pw_hash, desa_id))

        conn.commit()
        return jsonify({"success": True, "message": "Admin berhasil dibuat"})
    except Exception as e:
        conn.rollback()
        log_exc("=== ERROR signup_admin ===")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------------------------
# 2. SIGNUP USER
# -------------------------
@app.route("/signup-user", methods=["POST"])
def signup_user():
    data = request.get_json()
    nama_lengkap = data.get("nama_lengkap")
    rt = data.get("rt")
    rw = data.get("rw")
    blok = data.get("blok")
    desa_nama = data.get("desa")
    code_desa = data.get("code_desa")
    email = data.get("email")
    katasandi = data.get("katasandi")

    if not all([nama_lengkap, rt, rw, blok, desa_nama, code_desa, email, katasandi]):
        return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400

    if not email or not katasandi:
        return jsonify({"success": False, "message": "Email dan password wajib"}), 400

    pw_hash = generate_password_hash(katasandi)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True, buffered=True)

    try:
        cursor.execute("SELECT id FROM user WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "Email sudah terdaftar"}), 400

        cursor.execute("SELECT id FROM desa WHERE code_desa=%s", (code_desa,))
        desa = cursor.fetchone()
        if not desa:
            return jsonify({"success": False, "message": "Kode desa tidak ditemukan"}), 400
        desa_id = desa["id"]

        cursor.execute("SELECT * FROM user WHERE role='admin' AND desa_id=%s", (desa_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "message": "Belum ada admin untuk desa ini"}), 400

        cursor.execute("SELECT * FROM user WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "Email sudah terdaftar"}), 400

        cursor.execute("""
            INSERT INTO user (nama_lengkap, rt, rw, blok, email, katasandi, role, desa_id)
            VALUES (%s,%s,%s,%s,%s,%s,'user',%s)
        """, (nama_lengkap, rt, rw, blok, email, pw_hash, desa_id))

        conn.commit()
        return jsonify({"success": True, "message": "User berhasil dibuat"}), 201
    except Exception as e:
        conn.rollback()
        log_exc("=== ERROR signup_user ===")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------------------------
# 3. LOGIN (user/admin) - modifikasi: tidak membuat JWT, return user info
# -------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    katasandi = data.get("katasandi")
    if not email or not katasandi:
        return jsonify({"success": False, "message": "Email dan kata sandi wajib"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True, buffered=True)

    try:
        cursor.execute("""
            SELECT u.id, u.nama_lengkap, u.email, u.katasandi, u.role, d.code_desa, d.nama_desa, u.desa_id
            FROM user u
            JOIN desa d ON u.desa_id = d.id
            WHERE u.email=%s
        """, (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "message": "Login gagal"}), 401

        if not check_password_hash(user["katasandi"], katasandi):
            return jsonify({"success": False, "message": "Login gagal"}), 401

        # Return user info (no JWT)
        return jsonify({"success": True, "message": "Login berhasil", "user": {
            "id": user["id"],
            "nama_lengkap": user["nama_lengkap"],
            "email": user["email"],
            "role": user["role"],
            "desa_id": user["desa_id"],
            "code_desa": user["code_desa"],
            "nama_desa": user["nama_desa"]
        }}), 200

    except Exception as e:
        log_exc("=== ERROR login ===")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------------------------
# 4. forgot_password (user)
# -------------------------
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    new_pass = data.get("new_password")

    if not all([email, new_pass]):
        return jsonify({"success": False, "message": "Email & password baru wajib"}), 400

    pw_hash = generate_password_hash(new_pass)

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE user SET katasandi=%s WHERE email=%s", (pw_hash, email))

        if cursor.rowcount == 0:
            return jsonify({"success": False, "message": "Email tidak ditemukan"}), 404
        conn.commit()
        return jsonify({"success": True, "message": "Password berhasil diubah"})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------------------------
# 5. update_user (user)
# -------------------------
@app.route("/update-user/<int:user_id>", methods=["PUT"])
@require_auth
def update_user(user_id):
    data = request.get_json()
    nama_lengkap = data.get("nama_lengkap")
    email = data.get("email")
    katasandi = data.get("katasandi")
    rt = data.get("rt")
    rw = data.get("rw")
    blok = data.get("blok")
    image_profile = data.get("image_profile")  # base64 / url

    # Simple authorization: ensure the authenticated user updates only their record
    if g.user_id != user_id and g.role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # If password provided, hash it; else keep existing
        if katasandi:
            pw_to_store = generate_password_hash(katasandi)
        else:
            # fetch existing password
            cursor.execute("SELECT katasandi FROM user WHERE id=%s", (user_id,))
            row = cursor.fetchone()
            pw_to_store = row[0] if row else None

        cursor.execute("""
            UPDATE user 
            SET nama_lengkap=%s, email=%s, katasandi=%s, rt=%s, rw=%s, blok=%s
            WHERE id=%s
        """, (nama_lengkap, email, pw_to_store, rt, rw, blok, user_id))
        conn.commit()
        return jsonify({"success": True, "message": "User berhasil diupdate"})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------------------------
# 6. get profile (user)
# -------------------------
@app.route("/profile", methods=["GET"])
@require_auth
def get_profile():
    try:
        user_id = g.user_id

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT 
                u.id,
                u.nama_lengkap,
                u.email,
                u.rt,
                u.rw,
                u.blok,
                u.latlong,
                u.role,
                u.desa_id,
                u.profile_image,
                d.nama_desa,
                d.code_desa
            FROM user u
            LEFT JOIN desa d ON u.desa_id = d.id
            WHERE u.id = %s
        """, (user_id,))

        user_data = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user_data:
            return jsonify({
                "success": False,
                "message": "User tidak ditemukan"
            }), 404

        profile_data = {
            "id": user_data["id"],
            "nama_lengkap": user_data["nama_lengkap"],
            "rt": user_data["rt"],
            "rw": user_data["rw"],
            "blok": user_data["blok"],
            "latlong": user_data["latlong"],
            "email": user_data["email"],
            "role": user_data["role"],
            "desa_id": user_data["desa_id"],
            "profile_image": user_data["profile_image"],
            "desa": {
                "nama_desa": user_data["nama_desa"],
                "code_desa": user_data["code_desa"]
            }
        }

        return jsonify({
            "success": True,
            "data": profile_data
        })

    except Exception as e:
        log_exc("=== ERROR get_profile ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

# -------------------------
# 7. update profile (user)
# -------------------------
@app.route("/profile", methods=["PUT"])
@require_auth
def update_profile():
    try:
        user_id = g.user_id

        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Data tidak boleh kosong"
            }), 400

        allowed_fields = [
            'nama_lengkap', 'email', 'rt', 'rw', 'blok', 
            'latlong'
        ]

        update_data = {}
        for field in allowed_fields:
            if field in data and data[field] is not None:
                update_data[field] = data[field]

        if not update_data:
            return jsonify({
                "success": False,
                "message": "Tidak ada data yang diupdate"
            }), 400

        if 'email' in update_data:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT id FROM user WHERE email = %s AND id != %s", 
                (update_data['email'], user_id)
            )
            existing_user = cursor.fetchone()
            cursor.close()
            conn.close()

            if existing_user:
                return jsonify({
                    "success": False,
                    "message": "Email sudah digunakan oleh user lain"
                }), 400

        set_clause = ", ".join([f"{key} = %s" for key in update_data.keys()])
        values = list(update_data.values())
        values.append(user_id)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(f"""
            UPDATE user 
            SET {set_clause}
            WHERE id = %s
        """, values)

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Profile berhasil diupdate"
        })

    except Exception as e:
        log_exc("=== ERROR update_profile ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

# -------------------------
# upload profile image (user)
# -------------------------
@app.route("/upload-profile-image", methods=["POST"])
def upload_profile_image():
    try:
        # ✅ Ambil user info dari header (bukan JWT)
        user_id = request.headers.get("X-User-Id")
        role = request.headers.get("X-User-Role")
        desa_id = request.headers.get("X-Desa-Id")

        # Validasi wajib
        if not user_id or not role:
            return jsonify({
                "success": False,
                "message": "Unauthorized: user_id dan role dibutuhkan (header)"
            }), 401

        # Pastikan file dikirim
        if 'file' not in request.files:
            return jsonify({
                "success": False,
                "message": "Tidak ada file yang diupload"
            }), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({
                "success": False,
                "message": "Tidak ada file yang dipilih"
            }), 400

        # Validasi ekstensi file
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        def allowed_file(filename):
            return '.' in filename and \
                filename.rsplit('.', 1)[1].lower() in allowed_extensions

        if not allowed_file(file.filename):
            return jsonify({
                "success": False,
                "message": "Tipe file tidak diizinkan (PNG, JPG, JPEG, GIF)"
            }), 400

        # ✅ Simpan file
        filename = secure_filename(file.filename)
        timestamp = str(int(time.time()))
        file_extension = filename.rsplit('.', 1)[1].lower()
        new_filename = f"profile_{user_id}_{timestamp}.{file_extension}"

        PROFILE_IMAGES_FOLDER = os.path.join(os.getcwd(), "uploads", "profile_images")
        os.makedirs(PROFILE_IMAGES_FOLDER, exist_ok=True)

        filepath = os.path.join(PROFILE_IMAGES_FOLDER, new_filename)
        file.save(filepath)

        # Simpan path relatif ke DB
        relative_path = f"profile_images/{new_filename}"

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user SET profile_image = %s WHERE id = %s",
            (relative_path, user_id)
        )
        conn.commit()
        cursor.close()
        conn.close()

        print(f"✅ [UPLOAD] User {user_id} upload {relative_path}")

        return jsonify({
            "success": True,
            "message": "Foto profil berhasil diupload",
            "profile_image": relative_path
        }), 200

    except Exception as e:
        print("❌ ERROR upload_profile_image:", e)
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

# -------------------------
# SERVE UPLOADS
# -------------------------
@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# -------------------------
# verify password (user)
# -------------------------
@app.route("/verify-password", methods=["POST"])
@require_auth
def verify_password():
    try:
        user_id = g.user_id

        data = request.get_json()
        password = data.get("katasandi")

        if not password:
            return jsonify({
                "success": False,
                "message": "katasandi wajib diisi"
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT katasandi FROM user WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return jsonify({
                "success": False,
                "message": "User tidak ditemukan"
            }), 404

        if check_password_hash(user["katasandi"], password):
            return jsonify({
                "success": True,
                "message": "Password benar"
            })
        else:
            return jsonify({
                "success": False,
                "message": "Password salah"
            }), 401

    except Exception as e:
        log_exc("=== ERROR verify_password ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

# -------------------------
# LAPOR (generate TTS + trigger specific ESP)
# -------------------------
def _save_and_trigger(desa_id, user_id, text, filename, code_desa):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True, buffered=True)
    cursor.execute("""
        INSERT INTO messages (desa_id, user_id, description, tts_url)
        VALUES (%s,%s,%s,%s)
    """, (desa_id, user_id, text, filename))
    conn.commit()

    cursor.execute("SELECT * FROM iot_device WHERE desa_id=%s", (desa_id,))
    iot_device = cursor.fetchall()
    cursor.close()
    conn.close()

    if not iot_device:
        return {
            "success": True,
            "message": "File dibuat & pesan tersimpan, tapi tidak ada iot device untuk desa ini",
            "file": filename
        }

    trigger_results = []
    for dev in iot_device:
        device_ip = dev.get("device_ip")
        trigger_url = f"http://{device_ip}/trigger"
        try:
            r = requests.post(trigger_url, json={"file": filename}, timeout=3)
            trigger_results.append({"iot_device": device_ip, "status": r.status_code, "text": r.text})
        except Exception as e:
            trigger_results.append({"iot_device": device_ip, "error": str(e)})

    return {
        "success": True,
        "message": "Pesan tersimpan & trigger dikirim",
        "file": filename,
        "triggers": trigger_results
    }

# -------------------------
# ESP32 NOTIFICATION ENDPOINT
# -------------------------
@app.route("/report", methods=["POST"])
def receive_report():
    data = request.get_json()

    # Validasi data
    required_fields = ["nama", "rt", "rw", "blok", "kategori"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Data tidak lengkap"}), 400

    # Format teks
    text = (
        f"Telah terjadi {data['kategori']}. "
        f"Di rumah {data['nama']}, RT {data['rt']}, RW {data['rw']}, Blok {data['blok']}. "
        "Mohon bantuan segera."
    )

    # Buat file nama unik
    # timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"temp.mp3"
    filepath = os.path.join(AUDIO_DIR, filename)

    # Generate suara dengan gTTS
    tts = gTTS(text=text, lang="id")
    tts.save(filepath)

    # Kirim notifikasi ke ESP32
    try:
        notify_data = {"filename": filename, "url": f"http://{request.host}/audio/{filename}"}
        response = requests.post(f"{ESP32_IP}/notify", json=notify_data, timeout=5)
        if response.status_code == 200:
            print(f"ESP32 notified successfully for file: {filename}")
        else:
            print(f"ESP32 notification failed with code {response.status_code}")
    except requests.RequestException as e:
        print(f"Gagal menghubungi ESP32: {e}")

    return jsonify({"status": "success", "filename": filename})

@app.route("/audio/<path:filename>")
def serve_audio(filename):
    """Serve file mp3 untuk diunduh ESP32"""
    return send_from_directory(AUDIO_DIR, filename)

@app.route("/notify-esp", methods=["POST"])
def notify_esp():
    try:
        data = request.get_json()
        code_desa = data.get("code_desa")
        filename = data.get("filename")
        play_count = data.get("play_count", 3)
        
        if not code_desa or not filename:
            return jsonify({"success": False, "message": "code_desa dan filename wajib"}), 400
        
        # Dapatkan semua ESP32 dengan code_desa yang sesuai
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id.device_ip 
            FROM iot_device id
            JOIN desa d ON id.desa_id = d.id
            WHERE d.code_desa = %s
        """, (code_desa,))
        
        devices = cursor.fetchall()
        cursor.close()
        conn.close()
        
        if not devices:
            return jsonify({"success": False, "message": "Tidak ada ESP32 terdaftar untuk desa ini"}), 404
        
        # Kirim notifikasi ke semua ESP32 yang sesuai
        notification_results = []
        for device in devices:
            device_ip = device["device_ip"]
            success = send_esp_notification(device_ip, filename, play_count)
            notification_results.append({
                "device_ip": device_ip,
                "status": "success" if success else "failed"
            })
        
        return jsonify({
            "success": True,
            "message": f"Notifikasi dikirim ke {len(devices)} ESP32",
            "results": notification_results
        })
        
    except Exception as e:
        log_exc("=== ERROR notify_esp ===")
        return jsonify({"success": False, "message": str(e)}), 500

def send_esp_notification(device_ip, filename, play_count):
    """Kirim notifikasi ke ESP32 tertentu"""
    try:
        notification_url = f"http://{device_ip}/notify"
        payload = {
            "filename": filename,
            "play_count": play_count,
            "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}"
        }
        
        response = requests_session.post(
            notification_url, 
            json=payload, 
            timeout=5
        )
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Gagal kirim notifikasi ke {device_ip}: {e}")
        return False

def _save_report(desa_id, user_id, text, filename, code_desa, category):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True, buffered=True)

    try:
        # Simpan laporan ke tabel messages
        cursor.execute("""
            INSERT INTO messages (desa_id, user_id, description, tts_url, category)
            VALUES (%s, %s, %s, %s, %s)
        """, (desa_id, user_id, text, filename, category))
        conn.commit()

        result = {
            "success": True,
            "message": "Laporan berhasil disimpan.",
            "file": filename,
            "audio_url": f"http://{os.environ.get('PUBLIC_HOST', '192.168.0.99')}:5000/audio/{filename}"
        }

    except Exception as e:
        conn.rollback()
        result = {
            "success": False,
            "message": f"Gagal menyimpan laporan: {e}"
        }

    finally:
        cursor.close()
        conn.close()

    return result

def send_esp_notification_by_desa(code_desa, filename, play_count=3):
    """Kirim notifikasi ke semua ESP32 dengan code_desa tertentu"""
    try:
        notification_url = f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/notify-esp"
        payload = {
            "code_desa": code_desa,
            "filename": filename,
            "play_count": play_count
        }
        
        response = requests_session.post(
            notification_url, 
            json=payload, 
            timeout=10
        )
        return response.json()
    except Exception as e:
        print(f"❌ Gagal kirim notifikasi massal: {e}")
        return {"success": False, "error": str(e)}

# endpoint untuk register ESP32 otomatis:
@app.route("/register-esp", methods=["POST"])
def register_esp():
    """Endpoint untuk ESP32 register IP otomatis"""
    try:
        data = request.get_json()
        device_ip = request.remote_addr
        code_desa = data.get("code_desa")
        
        print(f"📝 ESP Registration - IP: {device_ip}, Code Desa: {code_desa}")
        
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Cari desa_id berdasarkan code_desa
        cursor.execute("SELECT id FROM desa WHERE code_desa = %s", (code_desa,))
        desa = cursor.fetchone()
        
        if not desa:
            return jsonify({"success": False, "message": "Kode desa tidak ditemukan"}), 400
        
        desa_id = desa["id"]
        
        # Update atau insert device
        cursor.execute("""
            INSERT INTO iot_device (device_ip, desa_id, created_at) 
            VALUES (%s, %s, NOW())
            ON DUPLICATE KEY UPDATE device_ip = VALUES(device_ip)
        """, (device_ip, desa_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"✅ ESP registered/updated - IP: {device_ip}, Desa ID: {desa_id}")
        
        return jsonify({
            "success": True, 
            "message": "ESP registered successfully",
            "ip_address": device_ip,
            "desa_id": desa_id
        })
        
    except Exception as e:
        print(f"❌ ESP registration failed: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    
# -------------------------
# WebSocket connection (no JWT) - read from query params
# -------------------------
@socketio.on('connect')
def handle_connect():
    try:
        # Read credentials from query string (client should send ?user_id=...&role=...&desa_id=...)
        admin_id = request.args.get('user_id')
        role = request.args.get('role')
        desa_id = request.args.get('desa_id')

        if not admin_id or not role:
            print("❌ No auth provided for socket connect")
            return False

        try:
            admin_id = int(admin_id)
            desa_id = int(desa_id) if desa_id else None
        except Exception:
            print("❌ Invalid admin_id/desa_id")
            return False

        if role == 'admin' and admin_id and desa_id:
            admin_clients[admin_id] = {
                'sid': request.sid,
                'desa_id': desa_id
            }
            print(f"✅ Admin {admin_id} connected (desa_id: {desa_id})")
            emit('connected', {'message': 'Connected to admin real-time updates'})
        else:
            print("❌ Connection rejected - not admin")
            return False

    except Exception as e:
        print(f"❌ WebSocket connection error: {e}")
        return False

@socketio.on('disconnect')
def handle_disconnect():
    for admin_id, info in list(admin_clients.items()):
        if info['sid'] == request.sid:
            admin_clients.pop(admin_id, None)
            print(f"❌ Admin {admin_id} disconnected")
            break

def broadcast_to_admins(desa_id, event_name, data):
    count = 0
    for admin_id, info in admin_clients.items():
        if info['desa_id'] == desa_id:
            socketio.emit(event_name, data, room=info['sid'])
            count += 1
            print(f"📢 Broadcast to admin {admin_id}: {event_name}")

    print(f"📢 Broadcasted to {count} admin(s) for desa_id {desa_id}")

# -------------------------
# LAPOR CEPAT
# -------------------------
@app.route("/lapor-cepat", methods=["POST"])
@require_auth
def lapor_cepat():
    try:
        user_id = g.user_id
        desa_id = g.desa_id
        data = request.json or {}
        category = data.get("category", "Kejadian")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # if g.desa_id != desa_id_from_request:
        #     return jsonify({"error": "akses ditolak"}), 403

        # Ambil data user
        cursor.execute("SELECT nama_lengkap, rt, rw, blok FROM user WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

        # Ambil data desa
        cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
        desa = cursor.fetchone()
        if not desa:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

        name = user["nama_lengkap"]
        rt = user["rt"]
        rw = user["rw"]
        blok = user["blok"]
        code_desa = desa["code_desa"]

        text = f"telah terjadi {category}. Di rumah {name}, RT {rt}, RW {rw}, Blok {blok}, Mohon bantuan segera."

        filename = generate_mp3(text)
        if not filename:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "message": "Gagal membuat file audio"}), 500

        result = _save_report(desa_id, user_id, text, filename, code_desa, category)

        # Ambil semua ESP32 yang sesuai desa_id
        cursor.execute("SELECT device_ip FROM iot_device WHERE desa_id=%s", (desa_id,))
        devices = cursor.fetchall()

        for device in devices:
            device_ip = device["device_ip"]
            try:
                notify_data = {"filename": filename, "url": f"http://{request.host}/audio/{filename}"}
                response = requests.post(f"http://{device_ip}/notify", json=notify_data, timeout=5)
                if response.status_code == 200:
                    print(f"ESP32 {device_ip} notified successfully for file: {filename}")
                else:
                    print(f"ESP32 {device_ip} notification failed with code {response.status_code}")
            except requests.RequestException as e:
                print(f"Gagal menghubungi ESP32 {device_ip}: {e}")

        cursor.close()
        conn.close()

        broadcast_data = {
            "type": "new_report",
            "data": {
                "pelapor": name,
                "category": category,
                "rt": rt,
                "rw": rw,
                "blok": blok,
                "desa": desa["nama_desa"],
                "timestamp": datetime.now().isoformat(),
                "audio_file": filename
            }
        }
        broadcast_to_admins(desa_id, "new_report", broadcast_data)

        return jsonify(result)

    except Exception as e:
        log_exc("=== ERROR lapor_cepat ===")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route("/lapor-manual", methods=["POST"])
@require_auth
def lapor_manual():
    try:
        user_id = g.user_id
        desa_id = g.desa_id

        data = request.json or {}
        category = data.get("category", "Kejadian")
        nama_lengkap = data.get("nama_lengkap")
        rt = data.get("rt")
        rw = data.get("rw")
        blok = data.get("blok")

        # Validasi data wajib
        required_fields = ["nama_lengkap", "rt", "rw", "blok", "category"]
        if not all(data.get(field) for field in required_fields):
            return jsonify({"error": "Data tidak lengkap"}), 400

        # Format teks laporan
        text = (
            f"Telah terjadi {category}. "
            f"Di rumah {nama_lengkap}, RT {rt}, RW {rw}, Blok {blok}. "
            "Mohon bantuan segera."
        )

        # Ambil data desa untuk keperluan penyimpanan laporan
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
        desa = cursor.fetchone()
        cursor.close()
        conn.close()

        if not desa:
            return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

        code_desa = desa["code_desa"]

        # Buat job background untuk membuat mp3 + simpan + notify ESP
        # Fungsi worker: worker_tasks.generate_and_send_notifications(report_data)
        job = rq_queue.enqueue(
            'worker_tasks.generate_and_send_notifications',
            {
                "desa_id": desa_id,
                "user_id": user_id,
                "text": text,
                "code_desa": code_desa,
                "category": category
            },
            job_timeout=300
        )

        # Fast response to client
        return jsonify({
            "success": True,
            "message": "Laporan diterima dan sedang diproses (background)",
            "job_id": job.get_id()
        }), 202

    except Exception as e:
        log_exc("=== ERROR lapor_manual ===")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

# -------------------------
# ENPOINT ESP32 DOWNLOAD AUDIO
# -------------------------
# def _save_and_trigger_laporan(desa_id, user_id, text, filename, code_desa, category):
#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True, buffered=True)

#     cursor.execute("""
#         INSERT INTO messages (desa_id, user_id, description, tts_url, category)
#         VALUES (%s, %s, %s, %s, %s)
#     """, (desa_id, user_id, text, filename, category))
#     conn.commit()

#     cursor.execute("SELECT * FROM iot_device WHERE desa_id=%s", (desa_id,))
#     devices = cursor.fetchall()
#     cursor.close()
#     conn.close()

#     if not devices:
#         return {
#             "success": True,
#             "message": "Laporan berhasil disimpan, tapi tidak ada device ESP untuk desa ini",
#             "file": filename,
#             "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}"
#         }

#     trigger_results = []
#     for device in devices:
#         device_ip = device.get("device_ip")
#         success = trigger_esp_device(device_ip, filename)
#         trigger_results.append({
#             "device": device_ip,
#             "status": "triggered" if success else "failed"
#         })

#     return {
#         "success": True,
#         "message": "Laporan berhasil dikirim ke ESP devices",
#         "file": filename,
#         "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}",
#         "triggers": trigger_results
#     }

# def trigger_esp_device(device_ip, filename, play_count=2):
#     try:
#         trigger_url = f"http://{device_ip}/trigger"
#         payload = {
#             "file": filename,
#             "play_count": play_count,
#             "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}"
#         }
#         resp = requests_session.post(trigger_url, json=payload, timeout=(2, 6))
#         return resp.status_code == 200
#     except requests.exceptions.Timeout:
#         print(f"⏰ Timeout ketika trigger ESP {device_ip}")
#         return False
#     except requests.exceptions.ConnectionError:
#         print(f"🔌 ESP {device_ip} tidak bisa dihubungi")
#         return False
#     except Exception as e:
#         print(f"❌ Error triggering ESP {device_ip}: {e}")
#         return False

# @app.route('/audio/<filename>')
# def serve_audio(filename):
#     filepath = os.path.join(AUDIO_DIR, filename)

#     user_agent = request.headers.get('User-Agent', '')
#     is_esp = 'ESP32' in user_agent or 'arduino' in user_agent.lower()

#     print(f"🔊 Request audio: {filename}")
#     print(f"📁 File path: {filepath}")
#     print(f"📁 File exists: {os.path.exists(filepath)}")
#     print(f"📁 Audio folder contents: {os.listdir(AUDIO_DIR) if os.path.exists(AUDIO_DIR) else 'Folder tidak ada'}")

#     if not os.path.exists(filepath):
#         if is_esp:
#             return jsonify({
#                 "status": "error",
#                 "message": "FILE_NOT_FOUND",
#                 "stop_retry": True
#             }), 404
#         else:
#             return jsonify({"error": "File tidak ditemukan"}), 404

#     return send_from_directory(AUDIO_DIR, filename)

# @app.route('/hapus-audio/<filename>', methods=["POST"])
# def hapus_audio(filename):
#     try:
#         filepath = os.path.join(AUDIO_DIR, filename)
#         if os.path.exists(filepath):
#             os.remove(filepath)
#             return jsonify({"success": True, "message": f"File {filename} dihapus"})
#         else:
#             return jsonify({"success": False, "message": "File tidak ditemukan"}), 404
#     except Exception as e:
#         return jsonify({"success": False, "message": str(e)}), 500

# -------------------------
# LAPOR LOKASI
# -------------------------
@app.route("/lapor-lokasi", methods=["POST"])
@require_auth
def lapor_lokasi_user():
    user_id = g.user_id
    desa_id = g.desa_id

    data = request.json or {}
    category = data.get("category", "Kejadian")
    latitude = data.get("latitude")
    longitude = data.get("longitude")

    if not latitude or not longitude:
        return jsonify({"success": False, "message": "lokasi wajib diisi"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT nama_lengkap, rt, rw, blok FROM user WHERE id=%s", (user_id,))
        u = cursor.fetchone()
        if not u:
            return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

        cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
        d = cursor.fetchone()
        if not d:
            return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

        name, rt, rw, blok = u["nama_lengkap"], u["rt"], u["rw"], u["blok"]
        code_desa = d["code_desa"]
        desa_name = d["nama_desa"]

        text = f"Laporan {category} di lokasi {latitude}, {longitude}, identitas pelapor {name}, RT {rt}, RW {rw}, Blok {blok}."

        cursor.execute("""
            INSERT INTO messages (desa_id, user_id, payload, tts_url)
            VALUES (%s,%s,%s,%s)
        """, (desa_id, user_id, text, f"{latitude},{longitude}"))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    publish_mqtt(code_desa, json.dumps({
        "category": category,
        "latitude": latitude,
        "longitude": longitude,
        "name": name,
        "desa": desa_name
    }))

    return jsonify({
        "success": True,
        "message": "Laporan berhasil dikirim",
        "data": {
            "category": category,
            "latitude": latitude,
            "longitude": longitude,
            "pelapor": name,
            "desa": desa_name
        }
    }), 201

@app.route("/laporan-terbaru", methods=["GET"])
@require_auth
def laporan_terbaru_admin():
    role = g.role
    desa_id = g.desa_id

    if role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.payload, m.tts_url, u.nama_lengkap, d.nama_desa, m.created_at
        FROM messages m
        JOIN user u ON m.user_id = u.id
        JOIN desa d ON m.desa_id = d.id
        WHERE m.desa_id=%s
        ORDER BY m.created_at DESC LIMIT 1
    """, (desa_id,))
    report = cursor.fetchone()
    cursor.close()
    conn.close()

    if not report:
        return jsonify({"success": False, "message": "Belum ada laporan"}), 404

    lat, lon = report["tts_url"].split(",")

    return jsonify({
        "success": True,
        "report": {
            "kategori": report["payload"],
            "pelapor": report["nama_lengkap"],
            "desa": report["nama_desa"],
            "latitude": float(lat),
            "longitude": float(lon),
            "created_at": str(report["created_at"])
        }
    })

# @app.errorhandler(422)
# def handle_unprocessable_entity(err):
#     return jsonify({
#         "success": False,
#         "message": "Request tidak valid atau hilang",
#         "detail": str(err)
#     }), 422

# @app.route('/get-audio/<filename>', methods=['GET'])
# def get_audio(filename):
#     filepath = os.path.join(AUDIO_FOLDER, filename)
#     if not os.path.exists(filepath):
#         return jsonify({"error": "File tidak ditemukan"}), 404

#     play_count[filename] += 1
#     if play_count[filename] >= 3:
#         resp = send_file(filepath, mimetype='audio/mpeg', as_attachment=True)
#         try:
#             time.sleep(2)
#             os.remove(filepath)
#             del play_count[filename]
#         except Exception:
#             pass
#         return resp
#     else:
#         return send_file(filepath, mimetype='audio/mpeg')


@app.route('/hapus/<filename>', methods=["GET"])
def hapus_file(filename):
    filepath = os.path.join(AUDIO_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        if filename in play_count:
            del play_count[filename]
        return jsonify({"status": "success", "message": f"File {filename} dihapus"})
    else:
        return jsonify({"status": "error", "message": "File tidak ditemukan"}), 404

# -------------------------
# NEWS MANAGEMENT
# -------------------------
@app.route("/upload-news", methods=["POST"])
@require_auth
def upload_news():
    try:
        user_id = g.user_id
        role = g.role
        desa_id = g.desa_id

        if role != "admin":
            return jsonify({
                "success": False,
                "message": "Hanya admin yang bisa upload berita"
            }), 403

        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Data tidak boleh kosong"
            }), 400

        title = data.get("title")
        description = data.get("description")
        source = data.get("source", "Admin Desa")

        if not all([title, description]):
            return jsonify({
                "success": False,
                "message": "Judul dan deskripsi wajib diisi"
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO news (title, description, source, created_at, visitors, desa_id)
            VALUES (%s, %s, %s, NOW(), 0, %s)
        """, (title, description, source, desa_id))

        conn.commit()
        news_id = cursor.lastrowid
        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Berita berhasil disimpan ke tabel news",
            "news_id": news_id
        }), 201

    except Exception as e:
        log_exc("=== ERROR upload_news ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

@app.route("/upload-news-with-image", methods=["POST"])
@require_auth
def upload_news_with_image():
    try:
        user_id = g.user_id
        role = g.role
        desa_id = g.desa_id

        print(f"📰 Upload news - user_id: {user_id}, role: {role}, desa_id: {desa_id}")

        if role != "admin":
            return jsonify({
                "success": False,
                "message": "Hanya admin yang bisa upload berita"
            }), 403

        # Get files and form data
        files = request.files.getlist('image')  # Support multiple files
        title = request.form.get('title')
        description = request.form.get('description')
        source = request.form.get('source', 'Admin Desa')

        print(f"📝 Form data - title: {title}, description: {description}, source: {source}")
        print(f"🖼️ Files received: {[f.filename for f in files]}")

        if not all([title, description]):
            return jsonify({
                "success": False,
                "message": "Judul dan deskripsi wajib diisi"
            }), 400

        image_paths = []

        # Handle multiple images (max 2 as per your Flutter code)
        for file in files[:2]:  # Limit to 2 files
            if file and file.filename != '' and allowed_file(file.filename):
                NEWS_IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'news_images')
                os.makedirs(NEWS_IMAGES_FOLDER, exist_ok=True)

                filename = secure_filename(file.filename)
                timestamp = str(int(time.time()))
                file_extension = filename.rsplit('.', 1)[1].lower()
                new_filename = f"news_{desa_id}_{timestamp}_{len(image_paths)}.{file_extension}"
                filepath = os.path.join(NEWS_IMAGES_FOLDER, new_filename)
                file.save(filepath)

                image_paths.append(f"news_images/{new_filename}")
                print(f"✅ Saved image: {new_filename}")

        # Join image paths with comma for database storage
        image_path = ','.join(image_paths) if image_paths else None

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO news (title, description, image, source, created_at, visitors, desa_id)
            VALUES (%s, %s, %s, %s, NOW(), 0, %s)
        """, (title, description, image_path, source, desa_id))

        conn.commit()
        news_id = cursor.lastrowid
        cursor.close()
        conn.close()

        # Prepare response with image URLs
        image_urls = []
        if image_paths:
            for img_path in image_paths:
                image_urls.append(f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/uploads/{img_path}")

        return jsonify({
            "success": True,
            "message": "Berita berhasil disimpan",
            "news_id": news_id,
            "image_paths": image_paths,
            "image_urls": image_urls
        }), 201

    except Exception as e:
        log_exc("=== ERROR upload_news_with_image ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500
    
@app.route("/news", methods=["GET"])
@require_auth
def get_news():
    try:
        desa_id = g.desa_id
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 20))
        offset = (page-1) * per_page
        cache_key = f"news:{desa_id}:page{page}:per{per_page}"
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, title, description, image, source, created_at, visitors, desa_id
            FROM news
            WHERE desa_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (desa_id, per_page, offset))
        news_list = cursor.fetchall()
        cursor.close()
        conn.close()

        formatted_news = []
        for news in news_list:
            news_data = {
                "id": news["id"],
                "title": news["title"],
                "description": news["description"],
                "image": news["image"],
                "source": news["source"],
                "created_at": str(news["created_at"]),
                "visitors": news["visitors"],
                "desa_id": news["desa_id"]
            }
            if news['image']:
                news_data["image_url"] = f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/uploads/{news['image']}"
            formatted_news.append(news_data)

        resp = {"success": True, "data": formatted_news, "total": len(formatted_news), "page": page}
        cache.set(cache_key, resp, timeout=30)
        return jsonify(resp)

    except Exception as e:
        log_exc("=== ERROR get_news ===")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route("/news/<int:news_id>", methods=["GET"])
@require_auth
def get_single_news(news_id):
    try:
        user_id = g.user_id
        desa_id = g.desa_id

        print(f"📰 Fetching news detail - news_id: {news_id}, user_id: {user_id}, desa_id: {desa_id}")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT 
                id, title, description, image, source, 
                created_at, visitors, desa_id
            FROM news 
            WHERE id = %s AND desa_id = %s
        """, (news_id, desa_id))

        news = cursor.fetchone()

        if not news:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "message": "Berita tidak ditemukan"
            }), 404

        cursor.execute("""
            SELECT id FROM news_visitors 
            WHERE news_id = %s AND user_id = %s
        """, (news_id, user_id))

        already_visited = cursor.fetchone()

        if not already_visited:
            print(f"👤 Recording new visit - user_id: {user_id}, news_id: {news_id}")
            cursor.execute("""
                INSERT INTO news_visitors (news_id, user_id, desa_id, created_at)
                VALUES (%s, %s, %s, NOW())
            """, (news_id, user_id, desa_id))

            cursor.execute("""
                UPDATE news 
                SET visitors = visitors + 1 
                WHERE id = %s
            """, (news_id,))

            conn.commit()
            print(f"✅ Visit recorded and counter updated")

        cursor.close()
        conn.close()

        news_data = {
            "id": news["id"],
            "title": news["title"],
            "description": news["description"],
            "image": news["image"],
            "source": news["source"],
            "created_at": str(news["created_at"]),
            "visitors": news["visitors"],
            "desa_id": news["desa_id"]
        }

        if news['image']:
            news_data["image_url"] = f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/uploads/{news['image']}"

        return jsonify({
            "success": True,
            "data": news_data
        })

    except Exception as e:
        log_exc("=== ERROR get_single_news ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

@app.route("/news-statistics", methods=["GET"])
@require_auth
def get_news_statistics():
    try:
        role = g.role
        desa_id = g.desa_id

        if role != "admin":
            return jsonify({
                "success": False,
                "message": "Hanya admin yang bisa melihat statistik"
            }), 403

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT COUNT(*) as total_news 
            FROM news 
            WHERE desa_id = %s
        """, (desa_id,))
        total_news = cursor.fetchone()["total_news"]

        cursor.execute("""
            SELECT COUNT(*) as total_visitors 
            FROM news_visitors 
            WHERE desa_id = %s
        """, (desa_id,))
        total_visitors = cursor.fetchone()["total_visitors"]

        cursor.execute("""
            SELECT title, visitors 
            FROM news 
            WHERE desa_id = %s 
            ORDER BY visitors DESC 
            LIMIT 5
        """, (desa_id,))
        popular_news = cursor.fetchall()

        cursor.execute("""
            SELECT COUNT(*) as visitors_today 
            FROM news_visitors 
            WHERE desa_id = %s AND DATE(created_at) = CURDATE()
        """, (desa_id,))
        visitors_today = cursor.fetchone()["visitors_today"]

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "data": {
                "total_news": total_news,
                "total_visitors": total_visitors,
                "visitors_today": visitors_today,
                "popular_news": popular_news
            }
        })

    except Exception as e:
        log_exc("=== ERROR get_news_statistics ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

# -------------------------
# GET REPORT SUMMARY (Today, Week, Month) - VERSI ALTERNATIF
# -------------------------
@app.route("/messages/summary", methods=["GET"])
@require_auth
def get_report_summary():
    try:
        desa_id = g.desa_id
        role = g.role

        print(f"📊 Fetching report summary for desa_id: {desa_id}")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Nama bulan dalam bahasa Indonesia
        month_names = {
            1: 'Januari', 2: 'Februari', 3: 'Maret', 4: 'April',
            5: 'Mei', 6: 'Juni', 7: 'Juli', 8: 'Agustus',
            9: 'September', 10: 'Oktober', 11: 'November', 12: 'Desember'
        }

        # Base condition untuk filter desa
        desa_condition = "WHERE u.desa_id = %s" if role != "superadmin" else ""
        params = [desa_id] if role != "superadmin" else []

        # Hitung hari ini
        today_query = f"""
            SELECT COUNT(*) as count 
            FROM messages m
            {"JOIN user u ON m.user_id = u.id" if role != "superadmin" else ""}
            {desa_condition}
            AND DATE(m.created_at) = CURDATE()
        """
        cursor.execute(today_query, params)
        today_result = cursor.fetchone()
        today_count = today_result['count'] if today_result else 0

        # Hitung minggu ini (minggu dalam bulan)
        current_day = datetime.now().day
        current_week = ((current_day - 1) // 7) + 1
        
        # Tentukan awal dan akhir minggu
        week_start_day = ((current_week - 1) * 7) + 1
        week_end_day = min(current_week * 7, 31)
        
        # Dapatkan tahun dan bulan saat ini
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        # Buat tanggal untuk minggu ini
        week_start = datetime(current_year, current_month, week_start_day)
        week_end = datetime(current_year, current_month, week_end_day)
        
        # Hitung laporan minggu ini
        week_query = f"""
            SELECT COUNT(*) as count 
            FROM messages m
            {"JOIN user u ON m.user_id = u.id" if role != "superadmin" else ""}
            {desa_condition}
            AND DATE(m.created_at) BETWEEN %s AND %s
        """
        week_params = params + [week_start.date(), week_end.date()]
        cursor.execute(week_query, week_params)
        week_result = cursor.fetchone()
        week_count = week_result['count'] if week_result else 0

        # Hitung bulan ini
        month_query = f"""
            SELECT COUNT(*) as count 
            FROM messages m
            {"JOIN user u ON m.user_id = u.id" if role != "superadmin" else ""}
            {desa_condition}
            AND MONTH(m.created_at) = MONTH(CURDATE()) 
            AND YEAR(m.created_at) = YEAR(CURDATE())
        """
        cursor.execute(month_query, params)
        month_result = cursor.fetchone()
        month_count = month_result['count'] if month_result else 0

        cursor.close()
        conn.close()

        month_name = month_names.get(current_month, 'Bulan')

        print(f"📊 Summary - Today: {today_count}, Week {current_week}: {week_count}, Month: {month_count}")

        return jsonify({
            "success": True,
            "data": {
                "today": today_count,
                "week": week_count,
                "month": month_count,
                "current_week": f"Minggu-{current_week}",
                "current_month": month_name,
                "year": current_year
            }
        }), 200

    except Exception as e:
        print("❌ ERROR get_report_summary:", e)
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500
    
# -------------------------
# GET CHART DATA FOR TREND ANALYSIS
# -------------------------
@app.route("/messages/chart-data", methods=["GET"])
@require_auth
def get_chart_data():
    try:
        desa_id = g.desa_id
        role = g.role

        print(f"📊 Fetching chart data for desa_id: {desa_id} | role: {role}")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Query untuk mendapatkan data per bulan dengan kategori
        if role == "superadmin":
            cursor.execute("""
                SELECT 
                    DATE_FORMAT(created_at, '%Y-%m') as month,
                    SUM(CASE WHEN category = 'kemalingan' THEN 1 ELSE 0 END) as kemalingan,
                    SUM(CASE WHEN category = 'medis' THEN 1 ELSE 0 END) as medis,
                    SUM(CASE WHEN category = 'kebakaran' THEN 1 ELSE 0 END) as kebakaran,
                    COUNT(*) as total
                FROM messages 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY DATE_FORMAT(created_at, '%Y-%m')
                ORDER BY month ASC
            """)
        else:
            cursor.execute("""
                SELECT 
                    DATE_FORMAT(m.created_at, '%Y-%m') as month,
                    SUM(CASE WHEN m.category = 'kemalingan' THEN 1 ELSE 0 END) as kemalingan,
                    SUM(CASE WHEN m.category = 'medis' THEN 1 ELSE 0 END) as medis,
                    SUM(CASE WHEN m.category = 'kebakaran' THEN 1 ELSE 0 END) as kebakaran,
                    COUNT(*) as total
                FROM messages m
                JOIN user u ON m.user_id = u.id
                WHERE u.desa_id = %s 
                AND m.created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY DATE_FORMAT(m.created_at, '%Y-%m')
                ORDER BY month ASC
            """, (desa_id,))

        chart_data = cursor.fetchall()
        cursor.close()
        conn.close()

        print(f"📊 Found {len(chart_data)} months of chart data")

        # Format nama bulan dalam bahasa Indonesia
        month_names = {
            '01': 'Jan', '02': 'Feb', '03': 'Mar', '04': 'Apr',
            '05': 'Mei', '06': 'Jun', '07': 'Jul', '08': 'Agu',
            '09': 'Sep', '10': 'Okt', '11': 'Nov', '12': 'Des'
        }

        formatted_data = []
        for data in chart_data:
            year_month = data['month']
            year, month = year_month.split('-')
            month_name = month_names.get(month, month)
            display_name = f"{month_name} {year}"

            formatted_data.append({
                "month": display_name,
                "month_raw": year_month,
                "kemalingan": int(data['kemalingan']),
                "medis": int(data['medis']),
                "kebakaran": int(data['kebakaran']),
                "total": int(data['total'])
            })

        return jsonify({
            "success": True,
            "data": formatted_data,
            "total_months": len(formatted_data)
        }), 200

    except Exception as e:
        print("❌ ERROR get_chart_data:", e)
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500


# ==========================
# Eventlet server patch (keep as original)
# ==========================
if 'ping_timeout' not in inspect.signature(eventlet.wsgi.server).parameters:
    old_server = eventlet.wsgi.server

    def patched_server(*args, **kwargs):
        kwargs.pop("ping_timeout", None)
        kwargs.pop("ping_interval", None)
        return old_server(*args, **kwargs)

    eventlet.wsgi.server = patched_server

# ==========================
# Main Runner
# ==========================
if __name__ == "__main__":
    print("🚀 Server berjalan di http://0.0.0.0:5000")
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True,
        ping_timeout=60,
        ping_interval=25
    )
