from flask import Flask, request, jsonify, send_from_directory
from gtts import gTTS
from flask_cors import CORS
import os
import requests
import datetime
import mysql.connector

app = Flask(__name__)
CORS(app)

AUDIO_DIR = "audio"

# Konfigurasi koneksi database
db_config = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
    "database": "siskamling_digital",
    "autocommit": True
}

if not os.path.exists(AUDIO_DIR):
    os.makedirs(AUDIO_DIR)


# ==========================================================
# Endpoint utama laporan
# ==========================================================
@app.route("/report", methods=["POST"])
def receive_report():
    data = request.get_json()

    # Validasi field wajib
    required_fields = ["nama", "rt", "rw", "blok", "kategori", "code_desa"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Data tidak lengkap"}), 400

    code_desa = data["code_desa"]

    # Ambil daftar perangkat dari database berdasarkan kode desa
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT i.device_ip, i.device_id, d.code_desa, d.nama_desa, i.description
            FROM iot_device i
            JOIN desa d ON i.desa_id = d.id
            WHERE d.code_desa = %s
        """, (code_desa,))
        target_devices = cursor.fetchall()
    except Exception as e:
        return jsonify({"error": f"Gagal konek database: {e}"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    if not target_devices:
        return jsonify({"error": f"Tidak ada perangkat ESP untuk kode desa {code_desa}"}), 404

    # Buat teks laporan
    text = (
        f"Telah terjadi {data['kategori']}. "
        f"Di rumah {data['nama']}, RT {data['rt']}, RW {data['rw']}, Blok {data['blok']}. "
        "Mohon bantuan segera."
    )

    # Buat file audio
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.mp3"
    filepath = os.path.join(AUDIO_DIR, filename)

    try:
        tts = gTTS(text=text, lang="id")
        tts.save(filepath)
    except Exception as e:
        return jsonify({"error": f"Gagal membuat file suara: {e}"}), 500

    # Kirim notifikasi ke setiap ESP dengan code_desa yang sama
    audio_url = f"http://{request.host}/audio/{filename}"
    results = []

    for device in target_devices:
        esp_ip = device["device_ip"]
        notify_data = {"filename": filename, "url": audio_url}

        try:
            response = requests.post(f"http://{esp_ip}:8080/notify", json=notify_data, timeout=5)
            if response.status_code == 200:
                print(f"✅ Notifikasi terkirim ke {esp_ip} ({device['description']})")
                results.append({"ip": esp_ip, "status": "success"})
            else:
                print(f"⚠️ ESP di {esp_ip} gagal ({response.status_code})")
                results.append({"ip": esp_ip, "status": "failed"})
        except requests.RequestException as e:
            print(f"❌ Tidak bisa menghubungi {esp_ip}: {e}")
            results.append({"ip": esp_ip, "status": "offline"})

    return jsonify({
        "status": "done",
        "desa": code_desa,
        "file": filename,
        "audio_url": audio_url,
        "results": results
    })


# ==========================================================
# Endpoint untuk menyajikan file MP3
# ==========================================================
@app.route("/audio/<path:filename>")
def serve_audio(filename):
    return send_from_directory(AUDIO_DIR, filename)


# ==========================================================
# Jalankan server
# ==========================================================
if __name__ == "__main__":
    print("🚀 Server Flask laporan berjalan di http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
