# worker_tasks.py
import os
import time
import json
import requests
from datetime import datetime
from database_config import get_connection
from tts_utils import generate_mp3  # Anda punya fungsi ini
from main import redis_conn, socketio  # pastikan import aman (hindari circular imports)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor

# configure requests session for worker
requests_session = requests.Session()
retry_strategy = Retry(total=2, status_forcelist=[429,500,502,503,504], allowed_methods=["GET","POST"])
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
requests_session.mount("http://", adapter)
requests_session.mount("https://", adapter)

def generate_and_send_notifications(payload):
    """
    payload: dict with keys desa_id, user_id, text, code_desa, category
    """
    desa_id = payload["desa_id"]
    user_id = payload["user_id"]
    text = payload["text"]
    code_desa = payload["code_desa"]
    category = payload.get("category", "Kejadian")

    # 1) generate mp3 (use generate_mp3 from your tts_utils)
    filename = None
    try:
        filename = generate_mp3(text)
    except Exception as e:
        print("❌ Worker: gagal generate mp3:", e)
        # proceed but mark filename None

    # 2) save to DB (messages)
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
                INSERT INTO messages (desa_id, user_id, description, tts_url, category, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, (desa_id, user_id, text, filename, category))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("❌ Worker: gagal simpan messages:", e)
    finally:
        cursor.close()
        conn.close()

    # 3) get devices and notify in parallel (ThreadPoolExecutor)
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT device_ip FROM iot_device WHERE desa_id = %s", (desa_id,))
        devices = cursor.fetchall()
        cursor.close()
        conn.close()

        def notify_one(dev):
            try:
                device_ip = dev["device_ip"]
                payload = {
                    "filename": filename,
                    "url": f"http://{os.environ.get('PUBLIC_HOST','127.0.0.1')}:5000/audio/{filename}"
                }
                r = requests_session.post(f"http://{device_ip}/notify", json=payload, timeout=5)
                return (device_ip, r.status_code == 200, r.status_code, getattr(r, 'text', ''))
            except Exception as e:
                return (dev.get("device_ip"), False, None, str(e))

        results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(notify_one, d) for d in devices]
            for f in futures:
                results.append(f.result())

        print("✅ Worker notifications results:", results)

    except Exception as e:
        print("❌ Worker error while notifying devices:", e)

    # Optionally broadcast to admins via socketio (non-blocking)
    try:
        socketio.emit("new_report", {
            "desa_id": desa_id,
            "category": category,
            "audio_file": filename,
            "timestamp": datetime.utcnow().isoformat()
        }, broadcast=True)
    except Exception as e:
        print("⚠️ Worker socketio broadcast failed:", e)

    return {"success": True, "filename": filename}
