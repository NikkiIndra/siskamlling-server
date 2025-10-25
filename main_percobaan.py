from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

app = Flask(__name__)

# ======================
# KONFIGURASI DATABASE
# ======================
DB_CONFIG = {
    "host": "localhost",      # atau IP MySQL kamu
    "user": "root",
    "password": "",
    "database": "siskamling_digital"
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)

# ======================
# ENDPOINT SIGNUP
# ======================
@app.route("/signup-user", methods=["POST"])
def signup_user():
    data = request.get_json() or {}
    nama_lengkap = data.get("nama_lengkap")
    rt = data.get("rt")
    rw = data.get("rw")
    blok = data.get("blok")
    desa = data.get("desa")
    code_desa = data.get("code_desa")
    email = data.get("email")
    katasandi = data.get("katasandi")

    if not all([nama_lengkap, rt, rw, blok, desa, code_desa, email, katasandi]):
        return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # hash password sebelum disimpan
        hashed_password = generate_password_hash(katasandi)

        # cek apakah email sudah ada
        cursor.execute("SELECT id FROM user WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "Email sudah terdaftar"}), 409

        cursor.execute("""
            INSERT INTO user (nama_lengkap, rt, rw, blok, desa_id, email, katasandi, role)
            VALUES (%s, %s, %s, %s,
                (SELECT id FROM desa WHERE code_desa=%s LIMIT 1),
                %s, %s, 'user')
        """, (nama_lengkap, rt, rw, blok, code_desa, email, hashed_password))
        conn.commit()

        return jsonify({"success": True, "message": "Registrasi berhasil"}), 201

    except Exception as e:
        print("ERROR signup:", e)
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ======================
# ENDPOINT LOGIN
# ======================
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
            SELECT u.id, u.nama_lengkap, u.email, u.katasandi, u.role,
                   d.code_desa, d.nama_desa, u.desa_id
            FROM user u
            JOIN desa d ON u.desa_id = d.id
            WHERE u.email=%s
        """, (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "message": "Login gagal, user tidak ditemukan"}), 401

        if not check_password_hash(user["katasandi"], katasandi):
            return jsonify({"success": False, "message": "Password salah"}), 401

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
                "nama_desa": user["nama_desa"],
            }
        }), 200

    except Exception as e:
        print("ERROR login:", e)
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# ======================
# JALANKAN SERVER
# ======================
if __name__ == "__main__":
    print("🚀 Test Auth Server berjalan di http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
