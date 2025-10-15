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
import paho.mqtt.publish as publish  # ✅ tambahkan ini
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
from flask import Flask, request, jsonify, send_file, send_from_directory, g
from flask_cors import CORS
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit

from db import get_connection
from tts_utils import generate_mp3

import eventlet.wsgi

import inspect

# ==========================
# APP & CONFIG INIT
# ==========================
app = Flask(__name__)
# keep original CORS config from your file
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "http://10.10.10.224:8080"]}})

# SocketIO pakai eventlet mode
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    message_queue=os.environ.get("REDIS_URL")
)

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
AUDIO_FOLDER = 'audio'
if not os.path.exists(AUDIO_FOLDER):
    os.makedirs(AUDIO_FOLDER)

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

# Simple auth replacement for JWT:
# - Reads user_id, role, desa_id from headers or query params.
# - Sets them on flask.g for handlers to use.
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Try headers first
        user_id = request.headers.get('X-User-Id') or request.args.get('user_id') or request.json.get('user_id') if request.is_json else None
        role = request.headers.get('X-User-Role') or request.args.get('role') or (request.json.get('role') if request.is_json else None)
        desa_id = request.headers.get('X-Desa-Id') or request.args.get('desa_id') or (request.json.get('desa_id') if request.is_json else None)

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
            "latlong", "role", "desa_id", "profile_image"
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

        print(f"📨 Fetching messages for desa_id: {desa_id} | role: {role}")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Jika superadmin → bisa lihat semua laporan
        if role == "superadmin":
            cursor.execute("""
                SELECT 
                    m.id, m.desa_id, m.description, m.category, m.tts_url,
                    m.latitude, m.longitude, m.created_at,
                    u.nama_lengkap AS reporter_name, u.email AS reporter_email,
                    u.rt, u.rw, u.blok
                FROM messages m
                JOIN user u ON m.user_id = u.id
                ORDER BY m.created_at DESC
            """)
        else:
            # Admin dan User: hanya laporan dari desanya sendiri
            cursor.execute("""
                SELECT 
                    m.id, m.desa_id, m.description, m.category, m.tts_url,
                    m.latitude, m.longitude, m.created_at,
                    u.nama_lengkap AS reporter_name, u.email AS reporter_email,
                    u.rt, u.rw, u.blok
                FROM messages m
                JOIN user u ON m.user_id = u.id
                WHERE u.desa_id = %s
                ORDER BY m.created_at DESC
            """, (desa_id,))

        messages = cursor.fetchall()
        cursor.close()
        conn.close()

        print(f"📊 Found {len(messages)} messages for desa_id {desa_id}")

        # Format data agar lebih rapi
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
                # tambahkan URL audio TTS jika ada
                "tts_url_full": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{msg['tts_url']}" if msg["tts_url"] else None
            })

        return jsonify({
            "success": True,
            "desa_id": desa_id,
            "role": role,
            "total": len(formatted),
            "data": formatted
        }), 200

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
# FILE UPLOAD HELPERS (already present)
# -------------------------

# konfigurasi MQTT is above

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

        cursor.execute("SELECT nama_lengkap, rt, rw, blok FROM user WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

        cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
        desa = cursor.fetchone()
        if not desa:
            return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

        cursor.close()
        conn.close()

        name = user["nama_lengkap"]
        rt = user["rt"]
        rw = user["rw"]
        blok = user["blok"]
        code_desa = desa["code_desa"]

        text = f"telah terjadi {category}. Di rumah {name}, RT {rt}, RW {rw}, Blok {blok}, Mohon bantuan segera."

        filename = generate_mp3(text)
        if not filename:
            return jsonify({"success": False, "message": "Gagal membuat file audio"}), 500

        result = _save_and_trigger_laporan(desa_id, user_id, text, filename, code_desa, category)

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

        if not all([nama_lengkap, rt, rw, blok]):
            return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
        desa = cursor.fetchone()
        if not desa:
            return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

        cursor.close()
        conn.close()

        code_desa = desa["code_desa"]

        text = f"telah terjadi {category}. Di rumah {nama_lengkap}, RT {rt}, RW {rw}, Blok {blok}, Mohon bantuan segera."

        filename = generate_mp3(text)
        if not filename:
            return jsonify({"success": False, "message": "Gagal membuat file audio"}), 500

        result = _save_and_trigger_laporan(desa_id, user_id, text, filename, code_desa, category)

        return jsonify(result)

    except Exception as e:
        log_exc("=== ERROR lapor_manual ===")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

# -------------------------
# ENPOINT ESP32 DOWNLOAD AUDIO
# -------------------------
def _save_and_trigger_laporan(desa_id, user_id, text, filename, code_desa, category):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True, buffered=True)

    cursor.execute("""
        INSERT INTO messages (desa_id, user_id, description, tts_url, category)
        VALUES (%s, %s, %s, %s, %s)
    """, (desa_id, user_id, text, filename, category))
    conn.commit()

    cursor.execute("SELECT * FROM iot_device WHERE desa_id=%s", (desa_id,))
    devices = cursor.fetchall()
    cursor.close()
    conn.close()

    if not devices:
        return {
            "success": True,
            "message": "Laporan berhasil disimpan, tapi tidak ada device ESP untuk desa ini",
            "file": filename,
            "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}"
        }

    trigger_results = []
    for device in devices:
        device_ip = device.get("device_ip")
        success = trigger_esp_device(device_ip, filename)
        trigger_results.append({
            "device": device_ip,
            "status": "triggered" if success else "failed"
        })

    return {
        "success": True,
        "message": "Laporan berhasil dikirim ke ESP devices",
        "file": filename,
        "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}",
        "triggers": trigger_results
    }

def trigger_esp_device(device_ip, filename, play_count=2):
    try:
        trigger_url = f"http://{device_ip}/trigger"
        payload = {
            "file": filename,
            "play_count": play_count,
            "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}"
        }
        resp = requests_session.post(trigger_url, json=payload, timeout=(2, 6))
        return resp.status_code == 200
    except requests.exceptions.Timeout:
        print(f"⏰ Timeout ketika trigger ESP {device_ip}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"🔌 ESP {device_ip} tidak bisa dihubungi")
        return False
    except Exception as e:
        print(f"❌ Error triggering ESP {device_ip}: {e}")
        return False

@app.route('/audio/<filename>')
def serve_audio(filename):
    filepath = os.path.join(AUDIO_FOLDER, filename)

    user_agent = request.headers.get('User-Agent', '')
    is_esp = 'ESP32' in user_agent or 'arduino' in user_agent.lower()

    print(f"🔊 Request audio: {filename}")
    print(f"📁 File path: {filepath}")
    print(f"📁 File exists: {os.path.exists(filepath)}")
    print(f"📁 Audio folder contents: {os.listdir(AUDIO_FOLDER) if os.path.exists(AUDIO_FOLDER) else 'Folder tidak ada'}")

    if not os.path.exists(filepath):
        if is_esp:
            return jsonify({
                "status": "error",
                "message": "FILE_NOT_FOUND",
                "stop_retry": True
            }), 404
        else:
            return jsonify({"error": "File tidak ditemukan"}), 404

    return send_from_directory(AUDIO_FOLDER, filename)

@app.route('/hapus-audio/<filename>', methods=["POST"])
def hapus_audio(filename):
    try:
        filepath = os.path.join(AUDIO_FOLDER, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({"success": True, "message": f"File {filename} dihapus"})
        else:
            return jsonify({"success": False, "message": "File tidak ditemukan"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

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

@app.errorhandler(422)
def handle_unprocessable_entity(err):
    return jsonify({
        "success": False,
        "message": "Request tidak valid atau hilang",
        "detail": str(err)
    }), 422

@app.route('/get-audio/<filename>', methods=['GET'])
def get_audio(filename):
    filepath = os.path.join(AUDIO_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File tidak ditemukan"}), 404

    play_count[filename] += 1
    if play_count[filename] >= 3:
        resp = send_file(filepath, mimetype='audio/mpeg', as_attachment=True)
        try:
            time.sleep(2)
            os.remove(filepath)
            del play_count[filename]
        except Exception:
            pass
        return resp
    else:
        return send_file(filepath, mimetype='audio/mpeg')

@app.route('/hapus/<filename>', methods=["GET"])
def hapus_file(filename):
    filepath = os.path.join(AUDIO_FOLDER, filename)
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

        if role != "admin":
            return jsonify({
                "success": False,
                "message": "Hanya admin yang bisa upload berita"
            }), 403

        file = request.files.get('image')
        title = request.form.get('title')
        description = request.form.get('description')
        source = request.form.get('source', 'Admin Desa')

        if not all([title, description]):
            return jsonify({
                "success": False,
                "message": "Judul dan deskripsi wajib diisi"
            }), 400

        image_path = None

        if file and allowed_file(file.filename):
            NEWS_IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'news_images')
            os.makedirs(NEWS_IMAGES_FOLDER, exist_ok=True)

            filename = secure_filename(file.filename)
            timestamp = str(int(time.time()))
            file_extension = filename.rsplit('.', 1)[1].lower()
            filename = f"news_{desa_id}_{timestamp}.{file_extension}"
            filepath = os.path.join(NEWS_IMAGES_FOLDER, filename)
            file.save(filepath)

            image_path = f"news_images/{filename}"

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

        return jsonify({
            "success": True,
            "message": "Berita berhasil disimpan ke tabel news",
            "news_id": news_id,
            "image_url": image_path
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

        print(f"📰 Fetching news for desa_id: {desa_id}")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT 
                id, title, description, image, source, 
                created_at, visitors, desa_id
            FROM news 
            WHERE desa_id = %s 
            ORDER BY created_at DESC
        """, (desa_id,))

        news_list = cursor.fetchall()
        cursor.close()
        conn.close()

        print(f"📊 Found {len(news_list)} news items for desa_id {desa_id}")

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

        return jsonify({
            "success": True,
            "data": formatted_news,
            "total": len(formatted_news),
            "desa_id": desa_id
        })

    except Exception as e:
        log_exc("=== ERROR get_news ===")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

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
        debug=False,
        allow_unsafe_werkzeug=True,
        ping_timeout=60,
        ping_interval=25
    )
