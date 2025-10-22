from flask import Flask, request, jsonify, send_from_directory
from gtts import gTTS
from flask_cors import CORS
import os
import requests
import datetime

app = Flask(__name__)
CORS(app)

AUDIO_DIR = "audio"
ESP32_IP = "http://10.234.3.57:8080"  # Ganti dengan IP ESP32 kamu

if not os.path.exists(AUDIO_DIR):
    os.makedirs(AUDIO_DIR)

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
