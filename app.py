# # app.py
# import os
# os.environ["EVENTLET_NO_GREENDNS"] = "yes" 
# import eventlet
# eventlet.monkey_patch()  # HARUS di paling atas sebelum import Flask, requests, dll

# from dotenv import load_dotenv
# load_dotenv()  # baca file .env lebih awal

# import json
# import time
# import traceback
# import requests
# import paho.mqtt.publish as publish  # ✅ tambahkan ini
# from requests.adapters import HTTPAdapter
# from urllib3.util.retry import Retry
# from datetime import datetime
# from flask import Flask, request, jsonify, send_file, send_from_directory
# from flask_cors import CORS
# from collections import defaultdict
# from werkzeug.security import generate_password_hash, check_password_hash
# from werkzeug.utils import secure_filename
# # from flask_jwt_extended import (
# #     JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
# # )
# from flask_socketio import SocketIO, emit

# from db import get_connection
# from tts_utils import generate_mp3


# import eventlet.wsgi

# import inspect
# # ==========================
# # APP & CONFIG INIT
# # ==========================
# app = Flask(__name__)
# CORS(app)

# # # SECRET untuk JWT
# # app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-secret-change-me")
# # jwt = JWTManager(app)

# # Setup CORS
# CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "http://10.10.10.224:8080"]}})

# # SocketIO pakai eventlet mode
# socketio = SocketIO(
#     app,
#     cors_allowed_origins="*",
#     async_mode="eventlet",
#     message_queue=os.environ.get("REDIS_URL")
# )

# # ==========================
# # GLOBAL REQUESTS SESSION
# # ==========================
# requests_session = requests.Session()
# retry_strategy = Retry(
#     total=2,
#     status_forcelist=[429, 500, 502, 503, 504],
#     allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
# )
# adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
# requests_session.mount("http://", adapter)
# requests_session.mount("https://", adapter)

# # Store connected admin clients
# admin_clients = {}

# # ==========================
# # Konfigurasi Upload
# # ==========================
# UPLOAD_FOLDER = 'uploads'
# PROFILE_IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'profile_images')
# ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# os.makedirs(PROFILE_IMAGES_FOLDER, exist_ok=True)

# print("DB_HOST:", os.environ.get("DB_HOST"))

# @app.route("/users", methods=["GET"])
# # @jwt_required()
# def get_users():
#     try:
#         current_user_id = get_jwt_identity()  # sekarang berisi ID user
#         claims = get_jwt()                    # ambil role dan desa_id dari token
#         role = claims.get("role")
#         desa_id = claims.get("desa_id")

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)

#         # Validasi user
#         cursor.execute("SELECT id FROM user WHERE id=%s", (current_user_id,))
#         user_login = cursor.fetchone()
#         if not user_login:
#             cursor.close()
#             conn.close()
#             return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

#         # Ambil fields
#         fields = request.args.get("fields")
#         allowed_columns = {
#             "id", "nama_lengkap", "email", "rt", "rw", "blok",
#             "latlong", "role", "desa_id", "profile_image"
#         }

#         if fields:
#             selected_fields = [f for f in fields.split(",") if f in allowed_columns]
#             if not selected_fields:
#                 cursor.close()
#                 conn.close()
#                 return jsonify({"success": False, "message": "Field tidak valid"}), 400
#         else:
#             selected_fields = list(allowed_columns)

#         sql = f"SELECT {', '.join(selected_fields)} FROM user"

#         # Filter berdasarkan role
#         conditions = []
#         params = []
#         if role == "admin":
#             conditions.append("desa_id = %s")
#             params.append(desa_id)
#         elif role == "user":
#             conditions.append("id = %s")
#             params.append(current_user_id)

#         if conditions:
#             sql += " WHERE " + " AND ".join(conditions)

#         cursor.execute(sql, params)
#         users = cursor.fetchall()
#         cursor.close()
#         conn.close()

#         return jsonify({"success": True, "data": users}), 200

#     except Exception as e:
#         print("❌ Error:", e)
#         return jsonify({"success": False, "message": str(e)}), 500


# # @app.route("/messages", methods=["GET"])
# # @jwt_required()
# # def get_messages():
# #     try:
# #         claims = get_jwt()
# #         role = claims["role"]
# #         desa_id = claims["desa_id"]

# #         conn = get_connection()
# #         cursor = conn.cursor(dictionary=True)

# #         # Ambil field yang diinginkan dari query param (opsional)
# #         fields = request.args.get("fields")
# #         allowed_columns = {
# #             "m.id", "m.description", "m.category", "m.tts_url",
# #             "m.latitude", "m.longitude", "m.created_at",
# #             "u.nama_lengkap", "u.email", "u.rt", "u.rw", "u.blok"
# #         }

# #         if fields:
# #             selected_fields = []
# #             for f in fields.split(","):
# #                 f = f.strip()
# #                 if f in allowed_columns:
# #                     selected_fields.append(f)
# #             if not selected_fields:
# #                 cursor.close()
# #                 return jsonify({"success": False, "message": "Field tidak valid"}), 400
# #         else:
# #             # default ambil semua
# #             selected_fields = list(allowed_columns)

# #         sql = f"""
# #             SELECT {', '.join(selected_fields)}
# #             FROM messages m
# #             JOIN user u ON m.user_id = u.id
# #         """

# #         params = []
# #         if role == "admin":
# #             sql += " WHERE u.desa_id = %s"
# #             params.append(desa_id)
# #         elif role == "user":
# #             sql += " WHERE u.id = %s"
# #             params.append(claims["user_id"])

# #         sql += " ORDER BY m.created_at DESC"

# #         cursor.execute(sql, params)
# #         messages = cursor.fetchall()
# #         cursor.close()
# #         conn.close()

# #         return jsonify({"success": True, "data": messages}), 200

# #     except Exception as e:
# #         print("❌ Error:", e)
# #         return jsonify({"success": False, "message": str(e)}), 500

# # -------------------------
# # GET MESSAGES FOR ADMIN/USER (based on desa_id)
# # -------------------------
# @app.route("/messages", methods=["GET"])
# @jwt_required()
# def get_messages():
#     try:
#         claims = get_jwt()
#         desa_id = claims.get("desa_id")
#         role = claims.get("role")

#         print(f"📨 Fetching messages for desa_id: {desa_id} | role: {role}")

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)

#         # Jika superadmin → bisa lihat semua laporan
#         if role == "superadmin":
#             cursor.execute("""
#                 SELECT 
#                     m.id, m.desa_id, m.description, m.category, m.tts_url,
#                     m.latitude, m.longitude, m.created_at,
#                     u.nama_lengkap AS reporter_name, u.email AS reporter_email,
#                     u.rt, u.rw, u.blok
#                 FROM messages m
#                 JOIN user u ON m.user_id = u.id
#                 ORDER BY m.created_at DESC
#             """)
#         else:
#             # Admin dan User: hanya laporan dari desanya sendiri
#             cursor.execute("""
#                 SELECT 
#                     m.id, m.desa_id, m.description, m.category, m.tts_url,
#                     m.latitude, m.longitude, m.created_at,
#                     u.nama_lengkap AS reporter_name, u.email AS reporter_email,
#                     u.rt, u.rw, u.blok
#                 FROM messages m
#                 JOIN user u ON m.user_id = u.id
#                 WHERE u.desa_id = %s
#                 ORDER BY m.created_at DESC
#             """, (desa_id,))

#         messages = cursor.fetchall()
#         cursor.close()
#         conn.close()

#         print(f"📊 Found {len(messages)} messages for desa_id {desa_id}")

#         # Format data agar lebih rapi
#         formatted = []
#         for msg in messages:
#             formatted.append({
#                 "id": msg["id"],
#                 "desa_id": msg["desa_id"],
#                 "description": msg["description"],
#                 "category": msg["category"],
#                 "tts_url": msg["tts_url"],
#                 "latitude": msg["latitude"],
#                 "longitude": msg["longitude"],
#                 "created_at": str(msg["created_at"]),
#                 "reporter": {
#                     "name": msg["reporter_name"],
#                     "email": msg["reporter_email"],
#                     "rt": msg["rt"],
#                     "rw": msg["rw"],
#                     "blok": msg["blok"]
#                 },
#                 # tambahkan URL audio TTS jika ada
#                 "tts_url_full": f"http://192.168.0.99:5000/audio/{msg['tts_url']}" if msg["tts_url"] else None
#             })

#         return jsonify({
#             "success": True,
#             "desa_id": desa_id,
#             "role": role,
#             "total": len(formatted),
#             "data": formatted
#         }), 200

#     except Exception as e:
#         print("❌ ERROR get_messages:", e)
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500


# # -------------------------
# # GET ONLY COORDINATES (for map / trend report)
# # -------------------------
# @app.route("/messages/coords", methods=["GET"])
# @jwt_required()
# def get_message_coords():
#     try:
#         claims = get_jwt()
#         desa_id = claims.get("desa_id")
#         role = claims.get("role")

#         print(f"📨 Fetching coordinates for desa_id: {desa_id} | role: {role}")

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)

#         if role == "superadmin":
#             cursor.execute("""
#                 SELECT m.id, m.latitude, m.longitude, m.desa_id
#                 FROM messages m
#                 WHERE m.latitude IS NOT NULL AND m.longitude IS NOT NULL
#             """)
#         else:
#             cursor.execute("""
#                 SELECT m.id, m.latitude, m.longitude, m.desa_id
#                 FROM messages m
#                 JOIN user u ON m.user_id = u.id
#                 WHERE u.desa_id = %s
#                 AND m.latitude IS NOT NULL AND m.longitude IS NOT NULL
#             """, (desa_id,))

#         messages = cursor.fetchall()
#         cursor.close()
#         conn.close()

#         print(f"📊 Found {len(messages)} coordinates for desa_id {desa_id}")

#         return jsonify({
#             "success": True,
#             "data": messages
#         }), 200

#     except Exception as e:
#         print("❌ ERROR get_message_coords:", e)
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500



# # -------------------------
# # FILE UPLOAD HELPERS
# # -------------------------
# def allowed_file(filename):
#     return '.' in filename and \
#         filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# # konfigurasi MQTT
# MQTT_BROKER = "localhost"  # atau IP VPS kamu
# MQTT_PORT = 1883

# # folder untuk menyimpan file audio
# AUDIO_FOLDER = 'audio'
# if not os.path.exists(AUDIO_FOLDER):
#     os.makedirs(AUDIO_FOLDER)

# # untuk tracking berapa kali file sudah diakses
# # setelah 3 kali diakses, file akan dihapus
# play_count = defaultdict(int)

# # -------------------------
# # MQTT PUBLISH
# # -------------------------
# def publish_mqtt(code_desa, message):
#     topic = f"desa/{code_desa}"
#     publish.single(topic, message, hostname=MQTT_BROKER, port=MQTT_PORT)

# # -------------------------
# # HELPERS
# # -------------------------
# def log_exc(prefix=""):
#     print(prefix)
#     traceback.print_exc()


# # -------------------------
# # 1. SIGNUP ADMIN
# # - Input: email, katasandi, code_desa
# # - Behavior:
# #   * Jika ada record admin untuk code_desa -> reject (satu admin per code_desa)
# #   * Jika ada dummy record (misal device mapping or placeholder) untuk code_desa,
# #     update satu record (email,katasandi,role='admin') OR
# #   * Jika tidak ada dummy, kita tidak buat admin baru otomatis (sesuaikan kebijakan).
# #   * Di implementasi ini: kita cek apakah ada minimal satu device terdaftar untuk code_desa;
# #     lalu cek apakah sudah ada admin; jika belum ada, kita INSERT admin baru.
# #   (Kamu bisa ubah logika update vs insert sesuai kebutuhan.)
# # -------------------------
# @app.route("/signup-admin", methods=["POST"])
# def signup_admin():
#     data = request.get_json()
#     email = data.get("email")
#     katasandi = data.get("katasandi")
#     code_desa = data.get("code_desa")

#     # jika tidak lengkap data yang di inputkan -> reject
#     if not all([email, katasandi, code_desa]):
#         return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400

#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True, buffered=True)

#     try:
#         # cari desa.id dari code_desa
#         cursor.execute("SELECT id FROM desa WHERE code_desa=%s", (code_desa,))
#         desa = cursor.fetchone()
        
#         # jika tidak ada desa dengan code_desa tersebut -> reject
#         if not desa:
#             return jsonify({"success": False, "message": "Kode desa tidak ditemukan"}), 400
        
#         # dapatkan desa_id
#         desa_id = desa["id"]

#         # PERBAIKAN: cek devices berdasarkan desa_id, bukan code_desa
#         cursor.execute("SELECT * FROM iot_device WHERE desa_id=%s", (desa_id,))
#         if not cursor.fetchone():
#             return jsonify({"success": False, "message": "Belum ada iot device terdaftar untuk kode desa ini"}), 400

#         # cek apakah sudah ada admin
#         cursor.execute("SELECT * FROM user WHERE role='admin' AND desa_id=%s", (desa_id,))
#         # jika sudah ada admin -> reject
#         if cursor.fetchone():
#             return jsonify({"success": False, "message": "Admin sudah ada untuk desa ini"}), 400

#         # insert admin baru
#         pw_hash = generate_password_hash(katasandi)
#         cursor.execute("""
#             INSERT INTO user (nama_lengkap, email, katasandi, role, desa_id)
#             VALUES (%s,%s,%s,'admin',%s)
#         """, ("Admin", email, pw_hash, desa_id))

#         # simpan perubahan
#         conn.commit()
#         return jsonify({"success": True, "message": "Admin berhasil dibuat"})
    
#     # error handling
#     except Exception as e:
#         # kembalikan ke keadaan sebelumnya
#         conn.rollback()
#         log_exc("=== ERROR signup_admin ===")
#         return jsonify({"success": False, "message": str(e)}), 500
#     # tutup koneksi
#     finally:
#         cursor.close()
#         conn.close()
# # -------------------------
# # 2. SIGNUP USER
# # - Input: nama_lengkap, rt, rw, blok, desa, code_desa, email, katasandi
# # - Behavior:
# #   * Validasi: semua field wajib
# #   * Validasi: code_desa harus ada minimal 1 admin/device (kamu gunakan admin check)
# #   * Jika email sudah ada -> error
# #   * Insert user dengan role='user'
# # -------------------------
# @app.route("/signup-user", methods=["POST"])
# def signup_user():
#     data = request.get_json()
#     nama_lengkap = data.get("nama_lengkap")
#     rt = data.get("rt")
#     rw = data.get("rw")
#     blok = data.get("blok")
#     desa_nama = data.get("desa")
#     code_desa = data.get("code_desa")
#     email = data.get("email")
#     katasandi = data.get("katasandi")

#     # validasi semua field wajib
#     if not all([nama_lengkap, rt, rw, blok, desa_nama, code_desa, email, katasandi]):
#         return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400
    
#     # validasi singkat...
#     if not email or not katasandi:
#         return jsonify({"success": False, "message": "Email dan password wajib"}), 400
    
#     # hash password
#     pw_hash = generate_password_hash(katasandi)  # default method pbkdf2:sha256

#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True, buffered=True)

#     try:
#         # cek email unik
#         cursor.execute("SELECT id FROM user WHERE email=%s", (email,))
#         if cursor.fetchone():
#             return jsonify({"success": False, "message": "Email sudah terdaftar"}), 400

#         # cari desa.id
#         cursor.execute("SELECT id FROM desa WHERE code_desa=%s", (code_desa,))
#         desa = cursor.fetchone()
#         if not desa:
#             return jsonify({"success": False, "message": "Kode desa tidak ditemukan"}), 400
#         desa_id = desa["id"]

#         # pastikan sudah ada admin
#         cursor.execute("SELECT * FROM user WHERE role='admin' AND desa_id=%s", (desa_id,))
#         if not cursor.fetchone():
#             return jsonify({"success": False, "message": "Belum ada admin untuk desa ini"}), 400

#         # cek email unik
#         cursor.execute("SELECT * FROM user WHERE email=%s", (email,))
#         if cursor.fetchone():
#             return jsonify({"success": False, "message": "Email sudah terdaftar"}), 400

#         # insert user dengan pw hash
#         cursor.execute("""
#             INSERT INTO user (nama_lengkap, rt, rw, blok, email, katasandi, role, desa_id)
#             VALUES (%s,%s,%s,%s,%s,%s,'user',%s)
#         """, (nama_lengkap, rt, rw, blok, email, pw_hash, desa_id))

#         conn.commit()
#         return jsonify({"success": True, "message": "User berhasil dibuat"}), 201
#     except Exception as e:
#         conn.rollback()
#         log_exc("=== ERROR signup_user ===")
#         return jsonify({"success": False, "message": str(e)}), 500
#     finally:
#         cursor.close()
#         conn.close()

# # -------------------------
# # 3. LOGIN (user/admin)
# # - Input: email, katasandi
# # - Return: user object (including role) jika cocok
# # -------------------------
# @app.route("/login", methods=["POST"])
# def login():
#     data = request.get_json() or {}
#     email = data.get("email")
#     katasandi = data.get("katasandi")
#     if not email or not katasandi:
#         return jsonify({"success": False, "message": "Email dan kata sandi wajib"}), 400

#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True, buffered=True)

#     try:
#         cursor.execute("""
#             SELECT u.id, u.nama_lengkap, u.email, u.katasandi, u.role, d.code_desa, d.nama_desa, u.desa_id
#             FROM user u
#             JOIN desa d ON u.desa_id = d.id
#             WHERE u.email=%s
#         """, (email,))
#         user = cursor.fetchone()

#         if not user:
#             return jsonify({"success": False, "message": "Login gagal"}), 401

#         if not check_password_hash(user["katasandi"], katasandi):
#             return jsonify({"success": False, "message": "Login gagal"}), 401
#         # buat token (payload minimal)
#         access_token = create_access_token(identity=str(user["id"]),
#         additional_claims={"user_id": user["id"], "role": user["role"], "desa_id": user["desa_id"]})
#         return jsonify({"success": True, "message": "Login berhasil", "access_token": access_token, "user": {
#             "id": user["id"], "nama_lengkap": user["nama_lengkap"], "email": user["email"], "role": user["role"], "desa_id": user["desa_id"]
#         }}), 200
    
#     except Exception as e:
#         log_exc("=== ERROR login ===")
#         return jsonify({"success": False, "message": str(e)}), 500
#     finally:
#         cursor.close()
#         conn.close()

# # -------------------------
# # 4. forgot_password (user)
# # - Input: email, new_password
# # - Behavior:
# #   * Jika email tidak ditemukan -> error
# #   * Update katasandi
# # -------------------------
# @app.route("/forgot-password", methods=["POST"])
# def forgot_password():
#     data = request.get_json()
#     email = data.get("email")
#     new_pass = data.get("new_password")

#     if not all([email, new_pass]):
#         return jsonify({"success": False, "message": "Email & password baru wajib"}), 400

#     pw_hash = generate_password_hash(new_pass)

#     conn = get_connection()
#     cursor = conn.cursor()
#     try:
#         cursor.execute("UPDATE user SET katasandi=%s WHERE email=%s", (pw_hash, email))

#         if cursor.rowcount == 0:
#             return jsonify({"success": False, "message": "Email tidak ditemukan"}), 404
#         conn.commit()
#         return jsonify({"success": True, "message": "Password berhasil diubah"})
#     except Exception as e:
#         conn.rollback()
#         return jsonify({"success": False, "message": str(e)}), 500
#     finally:
#         cursor.close()
#         conn.close()

# # -------------------------
# # 5. update_user (user)
# # - Input: user_id (path), nama_lengkap, email, katasandi, rt, rw, blok, image_profile
# # - Behavior:
# #   * Update data user
# #   * Jika user tidak ditemukan -> error
# #   * image_profile: simpan saja string (base64/url) di kolom, tidak perlu decode/simpan file
# #   * Untuk simplicity, tidak ada validasi email unik di update
# #   * user_id diambil dari path (bukan dari body)
# #   * Pastikan hanya user yang bersangkutan yang bisa update (bukan user lain)
# #   * Di implementasi ini, kita asumsikan user_id sudah valid dan user hanya bisa update dirinya sendiri
# # -------------------------
# @app.route("/update-user/<int:user_id>", methods=["PUT"])
# @jwt_required()
# def update_user(user_id):
#     data = request.get_json()
#     nama_lengkap = data.get("nama_lengkap")
#     email = data.get("email")
#     katasandi = data.get("katasandi")
#     rt = data.get("rt")
#     rw = data.get("rw")
#     blok = data.get("blok")
#     image_profile = data.get("image_profile")  # base64 / url

#     conn = get_connection()
#     cursor = conn.cursor()
#     try:
#         cursor.execute("""
#             UPDATE user 
#             SET nama_lengkap=%s, email=%s, katasandi=%s, rt=%s, rw=%s, blok=%s
#             WHERE id=%s
#         """, (nama_lengkap, email, katasandi, rt, rw, blok, user_id))
#         conn.commit()
#         return jsonify({"success": True, "message": "User berhasil diupdate"})
#     except Exception as e:
#         conn.rollback()
#         return jsonify({"success": False, "message": str(e)}), 500
#     finally:
#         cursor.close()
#         conn.close()

# # -------------------------
# # 6. get profile (user)
# # -------------------------
# # GET /profile:
# @app.route("/profile", methods=["GET"])
# @jwt_required()
# def get_profile():
#     try:
#         # Ambil user_id dari JWT token
#         identity = get_jwt_identity()
#         user_id = int(identity)
        
#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         # Query untuk mendapatkan data user
#         cursor.execute("""
#             SELECT 
#                 u.id,
#                 u.nama_lengkap,
#                 u.email,
#                 u.rt,
#                 u.rw,
#                 u.blok,
#                 u.latlong,
#                 u.role,
#                 u.desa_id,
#                 u.profile_image,
#                 d.nama_desa,
#                 d.code_desa
#             FROM user u
#             LEFT JOIN desa d ON u.desa_id = d.id
#             WHERE u.id = %s
#         """, (user_id,))
        
#         user_data = cursor.fetchone()
#         cursor.close()
#         conn.close()
        
#         if not user_data:
#             return jsonify({
#                 "success": False,
#                 "message": "User tidak ditemukan"
#             }), 404
        
#         # Format response
#         profile_data = {
#             "id": user_data["id"],
#             "nama_lengkap": user_data["nama_lengkap"],
#             "rt": user_data["rt"],
#             "rw": user_data["rw"],
#             "blok": user_data["blok"],
#             "latlong": user_data["latlong"],
#             "email": user_data["email"],
#             "role": user_data["role"],
#             "desa_id": user_data["desa_id"],
#             "profile_image": user_data["profile_image"],
#             "desa": {
#                 "nama_desa": user_data["nama_desa"],
#                 "code_desa": user_data["code_desa"]
#             }
#         }
        
#         return jsonify({
#             "success": True,
#             "data": profile_data
#         })
        
#     except Exception as e:
#         log_exc("=== ERROR get_profile ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500

# # -------------------------
# # 7. update profile (user)
# # -------------------------
# @app.route("/profile", methods=["PUT"])
# @jwt_required()
# def update_profile():
#     try:
#         # Ambil user_id dari JWT token
#         identity = get_jwt_identity()
#         user_id = int(identity)
        
#         data = request.get_json()
#         if not data:
#             return jsonify({
#                 "success": False,
#                 "message": "Data tidak boleh kosong"
#             }), 400
        
#         # Field yang bisa diupdate
#         allowed_fields = [
#             'nama_lengkap', 'email', 'rt', 'rw', 'blok', 
#             'latlong'
#         ]
        
#         update_data = {}
#         for field in allowed_fields:
#             if field in data and data[field] is not None:
#                 update_data[field] = data[field]
        
#         if not update_data:
#             return jsonify({
#                 "success": False,
#                 "message": "Tidak ada data yang diupdate"
#             }), 400
        
#         # Cek jika email sudah digunakan oleh user lain
#         if 'email' in update_data:
#             conn = get_connection()
#             cursor = conn.cursor(dictionary=True)
#             cursor.execute(
#                 "SELECT id FROM user WHERE email = %s AND id != %s", 
#                 (update_data['email'], user_id)
#             )
#             existing_user = cursor.fetchone()
#             cursor.close()
#             conn.close()
            
#             if existing_user:
#                 return jsonify({
#                     "success": False,
#                     "message": "Email sudah digunakan oleh user lain"
#                 }), 400
        
#         # Build query update
#         set_clause = ", ".join([f"{key} = %s" for key in update_data.keys()])
#         values = list(update_data.values())
#         values.append(user_id)
        
#         conn = get_connection()
#         cursor = conn.cursor()
        
#         cursor.execute(f"""
#             UPDATE user 
#             SET {set_clause}
#             WHERE id = %s
#         """, values)
        
#         conn.commit()
#         cursor.close()
#         conn.close()
        
#         return jsonify({
#             "success": True,
#             "message": "Profile berhasil diupdate"
#         })
        
#     except Exception as e:
#         log_exc("=== ERROR update_profile ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500

# # -------------------------
# # upload profile image (user)
# # -------------------------
# @app.route("/upload-profile-image", methods=["POST"])
# @jwt_required()
# def upload_profile_image():
#     try:
#         identity = get_jwt_identity()
#         user_id = int(identity)
        
#         # Cek apakah ada file dalam request
#         if 'file' not in request.files:
#             return jsonify({
#                 "success": False,
#                 "message": "Tidak ada file yang diupload"
#             }), 400
        
#         file = request.files['file']
        
#         # Jika user tidak memilih file
#         if file.filename == '':
#             return jsonify({
#                 "success": False,
#                 "message": "Tidak ada file yang dipilih"
#             }), 400
        
#         if file and allowed_file(file.filename):
#             # Secure filename dan buat nama unik
#             filename = secure_filename(file.filename)
#             # Buat nama file unik dengan user_id dan timestamp
#             import time
#             timestamp = str(int(time.time()))
#             file_extension = filename.rsplit('.', 1)[1].lower()
#             filename = f"profile_{user_id}_{timestamp}_.{file_extension}"
#             filepath = os.path.join(PROFILE_IMAGES_FOLDER, filename)
            
#             # Simpan file
#             file.save(filepath)
            
#             # Dapatkan relative path untuk disimpan di database
#             relative_path = f"profile_images/{filename}"
            
#             # Update database
#             conn = get_connection()
#             cursor = conn.cursor()
            
#             # Update profile_image dengan nama file baru
#             cursor.execute(
#                 "UPDATE user SET profile_image = %s WHERE id = %s",
#                 (relative_path, user_id)
#             )
#             conn.commit()
#             cursor.close()
#             conn.close()
            
#             return jsonify({
#                 "success": True,
#                 "message": "Foto profil berhasil diupload",
#                 "profile_image": relative_path
#             })
#         else:
#             return jsonify({
#                 "success": False,
#                 "message": "Tipe file tidak diizinkan. Hanya boleh PNG, JPG, JPEG, GIF"
#             }), 400
            
#     except Exception as e:
#         log_exc("=== ERROR upload_profile_image ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500

# # -------------------------
# # SERVE UPLOADS
# # untuk Mengakses File Static
# # Endpoint untuk mengakses file yang diupload
# # -------------------------
# @app.route('/uploads/<path:filename>')
# def serve_uploaded_file(filename):
#     return send_from_directory(UPLOAD_FOLDER, filename)

# # -------------------------
# # verify password (user)
# # -------------------------
# @app.route("/verify-password", methods=["POST"])
# @jwt_required()
# def verify_password():
#     try:
#         identity = get_jwt_identity()
#         user_id = int(identity)
        
#         data = request.get_json()
#         password = data.get("katasandi")
        
#         if not password:
#             return jsonify({
#                 "success": False,
#                 "message": "katasandi wajib diisi"
#             }), 400
        
#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         cursor.execute("SELECT katasandi FROM user WHERE id = %s", (user_id,))
#         user = cursor.fetchone()
#         cursor.close()
#         conn.close()
        
#         if not user:
#             return jsonify({
#                 "success": False,
#                 "message": "User tidak ditemukan"
#             }), 404
        
#         # Verifikasi password
#         if check_password_hash(user["katasandi"], password):
#             return jsonify({
#                 "success": True,
#                 "message": "Password benar"
#             })
#         else:
#             return jsonify({
#                 "success": False,
#                 "message": "Password salah"
#             }), 401
            
#     except Exception as e:
#         log_exc("=== ERROR verify_password ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500

# # -------------------------
# # LAPOR (generate TTS + trigger specific ESP)
# # - Input dari client: minimal include code_desa (dan data lain untuk teks)
# # - Behavior:
# #   * Generate mp3
# #   * Cari device(s) yang punya code_desa sama di tabel `devices`
# #   * Kirim POST ke device_ip/trigger dengan payload {"file": filename}
# #   * Hanya device(s) yang code_desa sama yang akan ditrigger
# # -------------------------
# def _save_and_trigger(desa_id, user_id, text, filename, code_desa):
#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True, buffered=True)
#     # simpan messages
#     cursor.execute("""
#         INSERT INTO messages (desa_id, user_id, description, tts_url)
#         VALUES (%s,%s,%s,%s)
#     """, (desa_id, user_id, text, filename))
#     conn.commit()

#     # cari devices sesuai desa
#     cursor.execute("SELECT * FROM iot_device WHERE desa_id=%s", (desa_id,))
#     iot_device = cursor.fetchall()
#     cursor.close()
#     conn.close()

#     if not iot_device:
#         return {
#             "success": True,
#             "message": "File dibuat & pesan tersimpan, tapi tidak ada iot device untuk desa ini",
#             "file": filename
#         }

#     trigger_results = []
#     for dev in iot_device:
#         device_ip = dev.get("device_ip")
#         trigger_url = f"http://{device_ip}/trigger"
#         try:
#             r = requests.post(trigger_url, json={"file": filename}, timeout=3)
#             trigger_results.append({"iot_device": device_ip, "status": r.status_code, "text": r.text})
#         except Exception as e:
#             trigger_results.append({"iot_device": device_ip, "error": str(e)})

#     return {
#         "success": True,
#         "message": "Pesan tersimpan & trigger dikirim",
#         "file": filename,
#         "triggers": trigger_results
#     }

# # -------------------------
# # LAPORAN TTS
# # -------------------------




# # WebSocket connection dengan JWT authentication
# @socketio.on('connect')
# def handle_connect():
#     try:
#         # Untuk WebSocket, token biasanya dikirim via query string
#         token = request.args.get('token')
#         if not token:
#             print("❌ No token provided")
#             return False
        
#         # Decode token manually atau gunakan flask_jwt_extended
#         from flask_jwt_extended import decode_token
#         try:
#             decoded_token = decode_token(token)
#             claims = decoded_token
#         except Exception as e:
#             print(f"❌ Token invalid: {e}")
#             return False
        
#         role = claims.get('role')
#         admin_id = claims.get('user_id')
#         desa_id = claims.get('desa_id')
        
#         if role == 'admin' and admin_id and desa_id:
#             admin_clients[admin_id] = {
#                 'sid': request.sid,
#                 'desa_id': desa_id
#             }
#             print(f"✅ Admin {admin_id} connected (desa_id: {desa_id})")
#             emit('connected', {'message': 'Connected to admin real-time updates'})
#         else:
#             print("❌ Connection rejected - not admin")
#             return False
            
#     except Exception as e:
#         print(f"❌ WebSocket connection error: {e}")
#         return False

# @socketio.on('disconnect')
# def handle_disconnect():
#     for admin_id, info in list(admin_clients.items()):
#         if info['sid'] == request.sid:
#             admin_clients.pop(admin_id, None)
#             print(f"❌ Admin {admin_id} disconnected")
#             break

# # Function untuk broadcast ke admin berdasarkan desa_id
# def broadcast_to_admins(desa_id, event_name, data):
#     count = 0
#     for admin_id, info in admin_clients.items():
#         if info['desa_id'] == desa_id:
#             socketio.emit(event_name, data, room=info['sid'])
#             count += 1
#             print(f"📢 Broadcast to admin {admin_id}: {event_name}")
    
#     print(f"📢 Broadcasted to {count} admin(s) for desa_id {desa_id}")


# @app.route("/lapor-cepat", methods=["POST"])
# @jwt_required()
# def lapor_cepat():
#     try:
#         identity = get_jwt_identity()
#         user_id = int(identity)
#         claims = get_jwt()
#         desa_id = claims.get("desa_id")

#         data = request.json or {}
#         category = data.get("category", "Kejadian")

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         # Ambil data user
#         cursor.execute("SELECT nama_lengkap, rt, rw, blok FROM user WHERE id=%s", (user_id,))
#         user = cursor.fetchone()
#         if not user:
#             return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

#         # Ambil data desa
#         cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
#         desa = cursor.fetchone()
#         if not desa:
#             return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

#         cursor.close()
#         conn.close()

#         name = user["nama_lengkap"]
#         rt = user["rt"]
#         rw = user["rw"] 
#         blok = user["blok"]
#         code_desa = desa["code_desa"]

#         # Generate teks laporan
#         text = f"telah terjadi {category}. Di rumah {name}, RT {rt}, RW {rw}, Blok {blok}, Mohon bantuan segera."

#         # Generate file TTS
#         filename = generate_mp3(text)
#         if not filename:
#             return jsonify({"success": False, "message": "Gagal membuat file audio"}), 500

#         # Simpan ke database dan trigger ESP
#         result = _save_and_trigger_laporan(desa_id, user_id, text, filename, code_desa, category)

        
#         # ✅ BROADCAST KE ADMIN REAL-TIME
#         broadcast_data = {
#             "type": "new_report",
#             "data": {
#                 "pelapor": name,
#                 "category": category,
#                 "rt": rt,
#                 "rw": rw,
#                 "blok": blok,
#                 "desa": desa["nama_desa"],
#                 "timestamp": datetime.now().isoformat(),
#                 "audio_file": filename
#             }
#         }
#         broadcast_to_admins(desa_id, "new_report", broadcast_data)

#         return jsonify(result)

#     except Exception as e:
#         log_exc("=== ERROR lapor_cepat ===")
#         return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

# @app.route("/lapor-manual", methods=["POST"])
# @jwt_required()
# def lapor_manual():
#     try:
#         identity = get_jwt_identity()
#         user_id = int(identity)
#         claims = get_jwt()
#         desa_id = claims.get("desa_id")

#         data = request.json or {}
#         category = data.get("category", "Kejadian")
#         nama_lengkap = data.get("nama_lengkap")
#         rt = data.get("rt")
#         rw = data.get("rw")
#         blok = data.get("blok")

#         # Validasi input
#         if not all([nama_lengkap, rt, rw, blok]):
#             return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         # Ambil data desa
#         cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
#         desa = cursor.fetchone()
#         if not desa:
#             return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

#         cursor.close()
#         conn.close()

#         code_desa = desa["code_desa"]

#         # Generate teks laporan
#         text = f"telah terjadi {category}. Di rumah {nama_lengkap}, RT {rt}, RW {rw}, Blok {blok}, Mohon bantuan segera."

#         # Generate file TTS
#         filename = generate_mp3(text)
#         if not filename:
#             return jsonify({"success": False, "message": "Gagal membuat file audio"}), 500

#         # Simpan ke database dan trigger ESP
#         result = _save_and_trigger_laporan(desa_id, user_id, text, filename, code_desa, category)

#         return jsonify(result)

#     except Exception as e:
#         log_exc("=== ERROR lapor_manual ===")
#         return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

# # -------------------------
# # enpoin esp32 download audio
# # -------------------------
# # Endpoint untuk ESP32 check audio (optional)
# # -------------------------
# # LAPORAN TTS - SERVER PUSH TO ESP32
# # -------------------------

# def _save_and_trigger_laporan(desa_id, user_id, text, filename, code_desa, category):
#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True, buffered=True)
    
#     # Simpan ke messages
#     cursor.execute("""
#         INSERT INTO messages (desa_id, user_id, description, tts_url, category)
#         VALUES (%s, %s, %s, %s, %s)
#     """, (desa_id, user_id, text, filename, category))
#     conn.commit()

#     # Cari ESP devices dengan desa yang sama
#     cursor.execute("SELECT * FROM iot_device WHERE desa_id=%s", (desa_id,))
#     devices = cursor.fetchall()
#     cursor.close()
#     conn.close()

#     if not devices:
#         return {
#             "success": True,
#             "message": "Laporan berhasil disimpan, tapi tidak ada device ESP untuk desa ini",
#             "file": filename,
#             "audio_url": f"http://192.168.0.99:5000/audio/{filename}"
#         }

#     # Trigger semua ESP devices - SERVER PUSH
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
#         "audio_url": f"http://192.168.0.99:5000/audio/{filename}",
#         "triggers": trigger_results
#     }

# # Endpoint untuk trigger langsung dari server ke ESP
# def trigger_esp_device(device_ip, filename, play_count=2):
#     """Server push ke ESP32 menggunakan global requests_session (reuse connection)"""
#     try:
#         trigger_url = f"http://{device_ip}/trigger"
#         payload = {
#             "file": filename,
#             "play_count": play_count,
#             "audio_url": f"http://{os.environ.get('PUBLIC_HOST','192.168.0.99')}:5000/audio/{filename}"
#         }

#         # Gunakan global session (reuse) dan timeout pendek
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

# # Endpoint untuk ESP mendownload audio
# @app.route('/audio/<filename>')
# def serve_audio(filename):
#     filepath = os.path.join(AUDIO_FOLDER, filename)
    
#     # Cek User-Agent untuk mengetahui apakah request dari ESP32
#     user_agent = request.headers.get('User-Agent', '')
#     is_esp = 'ESP32' in user_agent or 'arduino' in user_agent.lower()
    
#     print(f"🔊 Request audio: {filename}")
#     print(f"📁 File path: {filepath}")
#     print(f"📁 File exists: {os.path.exists(filepath)}")
#     print(f"📁 Audio folder contents: {os.listdir(AUDIO_FOLDER) if os.path.exists(AUDIO_FOLDER) else 'Folder tidak ada'}")
    
#     if not os.path.exists(filepath):
#         if is_esp:
#             # Untuk ESP32, kirim response khusus agar stop retry
#             return jsonify({
#                 "status": "error",
#                 "message": "FILE_NOT_FOUND",
#                 "stop_retry": True
#             }), 404
#         else:
#             return jsonify({"error": "File tidak ditemukan"}), 404
    
#     return send_from_directory(AUDIO_FOLDER, filename)

# # Endpoint untuk hapus audio setelah 2x diputar
# @app.route('/hapus-audio/<filename>', methods=["POST"])
# def hapus_audio(filename):
#     try:
#         filepath = os.path.join(AUDIO_FOLDER, filename)
#         if os.path.exists(filepath):
#             os.remove(filepath)
#             return jsonify({"success": True, "message": f"File {filename} dihapus"})
#         else:
#             return jsonify({"success": False, "message": "File tidak ditemukan"}), 404
#     except Exception as e:
#         return jsonify({"success": False, "message": str(e)}), 500

# # @app.route("/lapor-manual", methods=["POST"])
# # @jwt_required()
# # def lapor_manual():
# #     identity = get_jwt_identity()
# #     user_id = int(identity)
# #     claims = get_jwt()
# #     desa_id = claims.get("desa_id")

# #     data = request.json or {}
# #     category = data.get("category", "Kejadian")
# #     name = data.get("name")
# #     rt = data.get("rt")
# #     rw = data.get("rw")
# #     blok = data.get("blok")

# #     conn = get_connection()
# #     cursor = conn.cursor(dictionary=True)
# #     cursor.execute("SELECT code_desa FROM desa WHERE id=%s", (desa_id,))
# #     d = cursor.fetchone()
# #     if not d:
# #         return jsonify({"error": "Desa tidak ditemukan"}), 404
# #     cursor.close()
# #     conn.close()

# #     code_desa = d["code_desa"]

# #     text = f"Telah terjadi {category} di rumah {name}, RT {rt}, RW {rw}, Blok {blok}. Tolong segera menuju lokasi."
# #     filename = generate_mp3(text)
# #     return jsonify(_save_and_trigger(desa_id, user_id, text, filename, code_desa))

# # di app.py tambahkan
# @app.route("/lapor-lokasi", methods=["POST"])
# @jwt_required()
# def lapor_lokasi_user():
#     identity = get_jwt_identity()
#     user_id = int(identity)
#     claims = get_jwt()
#     desa_id = claims.get("desa_id")

#     data = request.json or {}
#     category = data.get("category", "Kejadian")
#     latitude = data.get("latitude")
#     longitude = data.get("longitude")

#     if not latitude or not longitude:
#         return jsonify({"success": False, "message": "lokasi wajib diisi"}), 400

#         conn = get_connection()
#     cursor = conn.cursor(dictionary=True)
#     try:
#         cursor.execute("SELECT nama_lengkap, rt, rw, blok FROM user WHERE id=%s", (user_id,))
#         u = cursor.fetchone()
#         if not u:
#             return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

#         cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
#         d = cursor.fetchone()
#         if not d:
#             return jsonify({"success": False, "message": "Desa tidak ditemukan"}), 404

#         name, rt, rw, blok = u["nama_lengkap"], u["rt"], u["rw"], u["blok"]
#         code_desa = d["code_desa"]
#         desa_name = d["nama_desa"]

#         text = f"Laporan {category} di lokasi {latitude}, {longitude}, identitas pelapor {name}, RT {rt}, RW {rw}, Blok {blok}."
        
#         # Simpan ke messages
#         cursor.execute("""
#             INSERT INTO messages (desa_id, user_id, payload, tts_url)
#             VALUES (%s,%s,%s,%s)
#         """, (desa_id, user_id, text, f"{latitude},{longitude}"))
#         conn.commit()
#     except Exception as e:
#         conn.rollback()
#         raise
#     finally:
#         cursor.close()
#         conn.close()

#     # desa_name = desa["nama_desa"]
#     text = f"Laporan {category} di lokasi {latitude}, {longitude}, identitas pelapor {name}, RT {rt}, RW {rw}, Blok {blok}."
    
#     # Simpan ke messages
#     conn = get_connection()
#     cursor = conn.cursor()
#     cursor.execute("""
#         INSERT INTO messages (desa_id, user_id, payload, tts_url)
#         VALUES (%s,%s,%s,%s)
#     """, (desa_id, user_id, text, f"{latitude},{longitude}"))
#     conn.commit()
#     cursor.close()
#     conn.close()

#     # publish MQTT (optional)
#     publish_mqtt(code_desa, json.dumps({
#         "category": category,
#         "latitude": latitude,
#         "longitude": longitude,
#         "name": name,
#         "desa": desa_name
#     }))

#     return jsonify({
#         "success": True,
#         "message": "Laporan berhasil dikirim",
#         "data": {
#             "category": category,
#             "latitude": latitude,
#             "longitude": longitude,
#             "pelapor": name,
#             "desa": desa_name
#         }
#     }), 201

# @app.route("/laporan-terbaru", methods=["GET"])
# @jwt_required()
# def laporan_terbaru_admin():
#     claims = get_jwt()
#     role = claims.get("role")
#     desa_id = claims.get("desa_id")

#     if role != "admin":
#         return jsonify({"success": False, "message": "Unauthorized"}), 403

#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True)
#     cursor.execute("""
#         SELECT m.payload, m.tts_url, u.nama_lengkap, d.nama_desa, m.created_at
#         FROM messages m
#         JOIN user u ON m.user_id = u.id
#         JOIN desa d ON m.desa_id = d.id
#         WHERE m.desa_id=%s
#         ORDER BY m.created_at DESC LIMIT 1
#     """, (desa_id,))
#     report = cursor.fetchone()
#     cursor.close()
#     conn.close()

#     if not report:
#         return jsonify({"success": False, "message": "Belum ada laporan"}), 404

#     lat, lon = report["tts_url"].split(",")

#     return jsonify({
#         "success": True,
#         "report": {
#             "kategori": report["payload"],
#             "pelapor": report["nama_lengkap"],
#             "desa": report["nama_desa"],
#             "latitude": float(lat),
#             "longitude": float(lon),
#             "created_at": str(report["created_at"])
#         }
#     })

# @app.errorhandler(422)
# def handle_unprocessable_entity(err):
#     return jsonify({
#         "success": False,
#         "message": "Token JWT tidak valid atau hilang",
#         "detail": str(err)
#     }), 422

# @app.route('/get-audio/<filename>', methods=['GET'])
# def get_audio(filename):
#     filepath = os.path.join(AUDIO_FOLDER, filename)
#     if not os.path.exists(filepath):
#         return jsonify({"error": "File tidak ditemukan"}), 404

#     play_count[filename] += 1
#     if play_count[filename] >= 3:
#         # kirim file terakhir, lalu hapus setelah kirim (catatan: send_file akan gagal kalau file dihapus sebelum dikirim)
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

# # -------------------------
# # 6. Hapus file (opsional)
# # -------------------------
# @app.route('/hapus/<filename>', methods=["GET"])
# def hapus_file(filename):
#     filepath = os.path.join(AUDIO_FOLDER, filename)
#     if os.path.exists(filepath):
#         os.remove(filepath)
#         if filename in play_count:
#             del play_count[filename]
#         return jsonify({"status": "success", "message": f"File {filename} dihapus"})
#     else:
#         return jsonify({"status": "error", "message": "File tidak ditemukan"}), 404

# # -------------------------
# # NEWS MANAGEMENT
# # -------------------------
# # Upload news (admin only) → masuk ke tabel messages
# @app.route("/upload-news", methods=["POST"])
# @jwt_required()
# def upload_news():
#     try:
#         identity = get_jwt_identity()
#         user_id = int(identity)
#         claims = get_jwt()
#         role = claims.get("role")
#         desa_id = claims.get("desa_id")

#         if role != "admin":
#             return jsonify({
#                 "success": False,
#                 "message": "Hanya admin yang bisa upload berita"
#             }), 403

#         data = request.get_json()
#         if not data:
#             return jsonify({
#                 "success": False,
#                 "message": "Data tidak boleh kosong"
#             }), 400

#         title = data.get("title")
#         description = data.get("description")
#         source = data.get("source", "Admin Desa")

#         if not all([title, description]):
#             return jsonify({
#                 "success": False,
#                 "message": "Judul dan deskripsi wajib diisi"
#             }), 400

#         conn = get_connection()
#         cursor = conn.cursor()

#         # ✅ simpan ke tabel `news`
#         cursor.execute("""
#             INSERT INTO news (title, description, source, created_at, visitors, desa_id)
#             VALUES (%s, %s, %s, NOW(), 0, %s)
#         """, (title, description, source, desa_id))

#         conn.commit()
#         news_id = cursor.lastrowid
#         cursor.close()
#         conn.close()

#         return jsonify({
#             "success": True,
#             "message": "Berita berhasil disimpan ke tabel news",
#             "news_id": news_id
#         }), 201

#     except Exception as e:
#         log_exc("=== ERROR upload_news ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500



# # Upload news dengan gambar (masuk ke messages)
# @app.route("/upload-news-with-image", methods=["POST"])
# @jwt_required()
# def upload_news_with_image():
#     try:
#         identity = get_jwt_identity()
#         user_id = int(identity)
#         claims = get_jwt()
#         role = claims.get("role")
#         desa_id = claims.get("desa_id")

#         if role != "admin":
#             return jsonify({
#                 "success": False,
#                 "message": "Hanya admin yang bisa upload berita"
#             }), 403

#         # 🔹 ambil data form
#         file = request.files.get('image')
#         title = request.form.get('title')
#         description = request.form.get('description')
#         source = request.form.get('source', 'Admin Desa')

#         if not all([title, description]):
#             return jsonify({
#                 "success": False,
#                 "message": "Judul dan deskripsi wajib diisi"
#             }), 400

#         image_path = None  # default tidak ada gambar

#         # 🔹 jika ada gambar dan valid → simpan
#         if file and allowed_file(file.filename):
#             NEWS_IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'news_images')
#             os.makedirs(NEWS_IMAGES_FOLDER, exist_ok=True)

#             filename = secure_filename(file.filename)
#             timestamp = str(int(time.time()))
#             file_extension = filename.rsplit('.', 1)[1].lower()
#             filename = f"news_{desa_id}_{timestamp}.{file_extension}"
#             filepath = os.path.join(NEWS_IMAGES_FOLDER, filename)
#             file.save(filepath)

#             image_path = f"news_images/{filename}"

#         # 🔹 simpan berita ke tabel news (walau tanpa gambar)
#         conn = get_connection()
#         cursor = conn.cursor()

#         cursor.execute("""
#             INSERT INTO news (title, description, image, source, created_at, visitors, desa_id)
#             VALUES (%s, %s, %s, %s, NOW(), 0, %s)
#         """, (title, description, image_path, source, desa_id))

#         conn.commit()
#         news_id = cursor.lastrowid
#         cursor.close()
#         conn.close()

#         return jsonify({
#             "success": True,
#             "message": "Berita berhasil disimpan ke tabel news",
#             "news_id": news_id,
#             "image_url": image_path
#         }), 201

#     except Exception as e:
#         log_exc("=== ERROR upload_news_with_image ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500

# # -------------------------
# # GET NEWS FOR USER (based on desa_id)
# # -------------------------
# @app.route("/news", methods=["GET"])
# @jwt_required()
# def get_news():
#     try:
#         claims = get_jwt()
#         desa_id = claims.get("desa_id")
        
#         print(f"📰 Fetching news for desa_id: {desa_id}")

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)

#         # Ambil berita berdasarkan desa_id, urutkan dari yang terbaru
#         cursor.execute("""
#             SELECT 
#                 id, title, description, image, source, 
#                 created_at, visitors, desa_id
#             FROM news 
#             WHERE desa_id = %s 
#             ORDER BY created_at DESC
#         """, (desa_id,))

#         news_list = cursor.fetchall()
#         cursor.close()
#         conn.close()

#         print(f"📊 Found {len(news_list)} news items for desa_id {desa_id}")

#         # Format response
#         formatted_news = []
#         for news in news_list:
#             news_data = {
#                 "id": news["id"],
#                 "title": news["title"],
#                 "description": news["description"],
#                 "image": news["image"],
#                 "source": news["source"],
#                 "created_at": str(news["created_at"]),
#                 "visitors": news["visitors"],
#                 "desa_id": news["desa_id"]
#             }
            
#             # Tambahkan full image URL jika ada image
#             if news['image']:
#                 news_data["image_url"] = f"http://192.168.0.99:5000/uploads/{news['image']}"
            
#             formatted_news.append(news_data)

#         return jsonify({
#             "success": True,
#             "data": formatted_news,
#             "total": len(formatted_news),
#             "desa_id": desa_id
#         })

#     except Exception as e:
#         log_exc("=== ERROR get_news ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500

# # -------------------------
# # GET SINGLE NEWS DETAIL
# # -------------------------
# @app.route("/news/<int:news_id>", methods=["GET"])
# @jwt_required()
# def get_single_news(news_id):
#     try:
#         identity = get_jwt_identity()
#         user_id = int(identity)
#         claims = get_jwt()
#         desa_id = claims.get("desa_id")

#         print(f"📰 Fetching news detail - news_id: {news_id}, user_id: {user_id}, desa_id: {desa_id}")

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)

#         # Ambil detail berita
#         cursor.execute("""
#             SELECT 
#                 id, title, description, image, source, 
#                 created_at, visitors, desa_id
#             FROM news 
#             WHERE id = %s AND desa_id = %s
#         """, (news_id, desa_id))

#         news = cursor.fetchone()
        
#         if not news:
#             cursor.close()
#             conn.close()
#             return jsonify({
#                 "success": False,
#                 "message": "Berita tidak ditemukan"
#             }), 404

#         # Cek apakah user sudah pernah membaca berita ini
#         cursor.execute("""
#             SELECT id FROM news_visitors 
#             WHERE news_id = %s AND user_id = %s
#         """, (news_id, user_id))

#         already_visited = cursor.fetchone()

#         # Jika belum pernah membaca, record kunjungan
#         if not already_visited:
#             print(f"👤 Recording new visit - user_id: {user_id}, news_id: {news_id}")
#             cursor.execute("""
#                 INSERT INTO news_visitors (news_id, user_id, desa_id, created_at)
#                 VALUES (%s, %s, %s, NOW())
#             """, (news_id, user_id, desa_id))

#             # Update visitor count
#             cursor.execute("""
#                 UPDATE news 
#                 SET visitors = visitors + 1 
#                 WHERE id = %s
#             """, (news_id,))

#             conn.commit()
#             print(f"✅ Visit recorded and counter updated")

#         cursor.close()
#         conn.close()

#         # Format response
#         news_data = {
#             "id": news["id"],
#             "title": news["title"],
#             "description": news["description"],
#             "image": news["image"],
#             "source": news["source"],
#             "created_at": str(news["created_at"]),
#             "visitors": news["visitors"],
#             "desa_id": news["desa_id"]
#         }
        
#         if news['image']:
#             news_data["image_url"] = f"http://192.168.0.99:5000/uploads/{news['image']}"

#         return jsonify({
#             "success": True,
#             "data": news_data
#         })

#     except Exception as e:
#         log_exc("=== ERROR get_single_news ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500
    
# # Get news statistics untuk admin
# @app.route("/news-statistics", methods=["GET"])
# @jwt_required()
# def get_news_statistics():
#     try:
#         claims = get_jwt()
#         role = claims.get("role")
#         desa_id = claims.get("desa_id")

#         if role != "admin":
#             return jsonify({
#                 "success": False,
#                 "message": "Hanya admin yang bisa melihat statistik"
#             }), 403

#         conn = get_connection()
#         cursor = conn.cursor(dictionary=True)

#         # Total berita
#         cursor.execute("""
#             SELECT COUNT(*) as total_news 
#             FROM news 
#             WHERE desa_id = %s
#         """, (desa_id,))
#         total_news = cursor.fetchone()["total_news"]

#         # Total pengunjung
#         cursor.execute("""
#             SELECT COUNT(*) as total_visitors 
#             FROM news_visitors 
#             WHERE desa_id = %s
#         """, (desa_id,))
#         total_visitors = cursor.fetchone()["total_visitors"]

#         # Berita paling populer
#         cursor.execute("""
#             SELECT title, visitors 
#             FROM news 
#             WHERE desa_id = %s 
#             ORDER BY visitors DESC 
#             LIMIT 5
#         """, (desa_id,))
#         popular_news = cursor.fetchall()

#         # Pengunjung hari ini
#         cursor.execute("""
#             SELECT COUNT(*) as visitors_today 
#             FROM news_visitors 
#             WHERE desa_id = %s AND DATE(created_at) = CURDATE()
#         """, (desa_id,))
#         visitors_today = cursor.fetchone()["visitors_today"]

#         cursor.close()
#         conn.close()

#         return jsonify({
#             "success": True,
#             "data": {
#                 "total_news": total_news,
#                 "total_visitors": total_visitors,
#                 "visitors_today": visitors_today,
#                 "popular_news": popular_news
#             }
#         })

#     except Exception as e:
#         log_exc("=== ERROR get_news_statistics ===")
#         return jsonify({
#             "success": False,
#             "message": f"Error: {str(e)}"
#         }), 500

# if 'ping_timeout' not in inspect.signature(eventlet.wsgi.server).parameters:
#     old_server = eventlet.wsgi.server

#     def patched_server(*args, **kwargs):
#         # buang argumen yang tidak dikenal
#         kwargs.pop("ping_timeout", None)
#         kwargs.pop("ping_interval", None)
#         return old_server(*args, **kwargs)

#     eventlet.wsgi.server = patched_server

# if __name__ == "__main__":
#     print("🚀 Server berjalan di http://0.0.0.0:5000")
    
#     # Gunakan production server untuk WebSocket
#     socketio.run(
#         app, 
#         host="0.0.0.0", 
#         port=5000, 
#         debug=False,  # False di production
#         allow_unsafe_werkzeug=True,
#         ping_timeout=60,
#         ping_interval=25
#     )
# # if __name__ == "__main__":
# #     print("🚀 Server Flask berjalan di http://localhost:5000")
# #     from db import get_connection 
# #     app.run(host="0.0.0.0", port=5000, debug=True)
# #     # socketio.run(app, host="0.0.0.0", port=5000, debug=True)

import os
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
import eventlet
eventlet.monkey_patch()

from dotenv import load_dotenv
load_dotenv()

import json
import time
import traceback
import requests
import paho.mqtt.publish as publish
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit

from db import get_connection
from tts_utils import generate_mp3
import inspect

# ==========================
# APP & CONFIG INIT
# ==========================
app = Flask(__name__)
CORS(app)

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
retry_strategy = Retry(total=2, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
requests_session.mount("http://", adapter)
requests_session.mount("https://", adapter)

admin_clients = {}

UPLOAD_FOLDER = 'uploads'
PROFILE_IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'profile_images')
AUDIO_FOLDER = 'audio'
os.makedirs(PROFILE_IMAGES_FOLDER, exist_ok=True)
os.makedirs(AUDIO_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
play_count = defaultdict(int)

MQTT_BROKER = "localhost"
MQTT_PORT = 1883

# ==========================
# HELPERS
# ==========================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_exc(prefix=""):
    print(prefix)
    traceback.print_exc()

def publish_mqtt(code_desa, message):
    topic = f"desa/{code_desa}"
    publish.single(topic, message, hostname=MQTT_BROKER, port=MQTT_PORT)

# ===========================================================
# LOGIN TANPA JWT
# ===========================================================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    katasandi = data.get("katasandi")

    if not email or not katasandi:
        return jsonify({"success": False, "message": "Email dan kata sandi wajib"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT u.id, u.nama_lengkap, u.email, u.katasandi, u.role, u.desa_id, d.code_desa, d.nama_desa
            FROM user u
            JOIN desa d ON u.desa_id = d.id
            WHERE u.email=%s
        """, (email,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user["katasandi"], katasandi):
            return jsonify({"success": False, "message": "Email atau kata sandi salah"}), 401

        return jsonify({
            "success": True,
            "message": "Login berhasil",
            "user": {
                "id": user["id"],
                "nama_lengkap": user["nama_lengkap"],
                "email": user["email"],
                "role": user["role"],
                "desa_id": user["desa_id"],
                "code_desa": user["code_desa"],
                "nama_desa": user["nama_desa"]
            }
        }), 200
    except Exception as e:
        log_exc("=== ERROR login ===")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ===========================================================
# CONTOH: GET USERS TANPA JWT (dari query param)
# ===========================================================
@app.route("/users", methods=["GET"])
def get_users():
    try:
        user_id = request.args.get("user_id", type=int)
        role = request.args.get("role")
        desa_id = request.args.get("desa_id", type=int)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        sql = "SELECT id, nama_lengkap, email, rt, rw, blok, role, desa_id, profile_image FROM user"
        params = []
        if role == "admin":
            sql += " WHERE desa_id=%s"
            params.append(desa_id)
        elif role == "user":
            sql += " WHERE id=%s"
            params.append(user_id)

        cursor.execute(sql, params)
        users = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify({"success": True, "data": users})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ===========================================================
# CONTOH: GET MESSAGES TANPA JWT
# ===========================================================
@app.route("/messages", methods=["GET"])
def get_messages():
    try:
        role = request.args.get("role")
        desa_id = request.args.get("desa_id", type=int)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if role == "superadmin":
            cursor.execute("""
                SELECT m.*, u.nama_lengkap as reporter_name
                FROM messages m
                JOIN user u ON m.user_id = u.id
                ORDER BY m.created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT m.*, u.nama_lengkap as reporter_name
                FROM messages m
                JOIN user u ON m.user_id = u.id
                WHERE m.desa_id = %s
                ORDER BY m.created_at DESC
            """, (desa_id,))
        messages = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify({"success": True, "data": messages})
    except Exception as e:
        log_exc("get_messages error")
        return jsonify({"success": False, "message": str(e)}), 500

# ===========================================================
# CONTOH: PROFILE TANPA JWT
# ===========================================================
@app.route("/profile/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.*, d.nama_desa, d.code_desa
            FROM user u
            LEFT JOIN desa d ON u.desa_id = d.id
            WHERE u.id = %s
        """, (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return jsonify({"success": False, "message": "User tidak ditemukan"}), 404
        return jsonify({"success": True, "data": user})
    except Exception as e:
        log_exc("get_profile error")
        return jsonify({"success": False, "message": str(e)}), 500

# ===========================================================
# UPLOAD PROFILE IMAGE TANPA JWT
# ===========================================================
@app.route("/upload-profile-image/<int:user_id>", methods=["POST"])
def upload_profile_image(user_id):
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "message": "Tidak ada file di request"}), 400
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = str(int(time.time()))
            ext = filename.rsplit('.', 1)[1]
            filename = f"profile_{user_id}_{timestamp}.{ext}"
            filepath = os.path.join(PROFILE_IMAGES_FOLDER, filename)
            file.save(filepath)
            rel_path = f"profile_images/{filename}"

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE user SET profile_image=%s WHERE id=%s", (rel_path, user_id))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"success": True, "profile_image": rel_path})
        return jsonify({"success": False, "message": "Format file tidak diizinkan"}), 400
    except Exception as e:
        log_exc("upload_profile_image error")
        return jsonify({"success": False, "message": str(e)}), 500

# ===========================================================
# AUDIO SERVE DAN HAPUS
# ===========================================================
@app.route('/audio/<filename>')
def serve_audio(filename):
    filepath = os.path.join(AUDIO_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File tidak ditemukan"}), 404
    return send_from_directory(AUDIO_FOLDER, filename)

@app.route('/hapus-audio/<filename>', methods=["POST"])
def hapus_audio(filename):
    try:
        filepath = os.path.join(AUDIO_FOLDER, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({"success": True})
        return jsonify({"success": False, "message": "File tidak ditemukan"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ===========================================================
# Laporan Cepat TANPA JWT
# ===========================================================
@app.route("/lapor-cepat", methods=["POST"])
def lapor_cepat():
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        desa_id = data.get("desa_id")
        category = data.get("category", "Kejadian")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT nama_lengkap, rt, rw, blok FROM user WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.execute("SELECT code_desa, nama_desa FROM desa WHERE id=%s", (desa_id,))
        desa = cursor.fetchone()
        cursor.close()
        conn.close()

        text = f"Telah terjadi {category} di rumah {user['nama_lengkap']}, RT {user['rt']}, RW {user['rw']}, Blok {user['blok']}."
        filename = generate_mp3(text)
        return jsonify({"success": True, "message": "Laporan dikirim", "audio": filename})
    except Exception as e:
        log_exc("lapor_cepat error")
        return jsonify({"success": False, "message": str(e)}), 500

# ===========================================================
# MAIN RUN
# ===========================================================
if 'ping_timeout' not in inspect.signature(eventlet.wsgi.server).parameters:
    old_server = eventlet.wsgi.server
    def patched_server(*args, **kwargs):
        kwargs.pop("ping_timeout", None)
        kwargs.pop("ping_interval", None)
        return old_server(*args, **kwargs)
    eventlet.wsgi.server = patched_server

if __name__ == "__main__":
    print("🚀 Server berjalan di http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
