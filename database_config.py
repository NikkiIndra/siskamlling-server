# db.py
from mysql.connector import pooling
import os

# ==============================
# ✅ Konfigurasi dasar database
# ==============================
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "")
DB_NAME = os.environ.get("DB_NAME", "siskamling_digital")
DB_PORT = int(os.environ.get("DB_PORT", 3306))

DB_CONFIG = {
    "host": DB_HOST,
    "user": DB_USER,
    "password": DB_PASS,
    "database": DB_NAME,
    "port": DB_PORT,
    "charset": "utf8mb4",
    "use_pure": True,
    "autocommit": True,           # ✅ biar gak perlu commit manual
    "connection_timeout": 5       # ✅ batasi waktu koneksi ke 5 detik
}

print("📦 MySQL config:", DB_CONFIG)

# ==============================
# ✅ Buat connection pool global
# ==============================
POOL_NAME = os.environ.get("DB_POOL_NAME", "flask_pool")
POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", 10))

try:
    connection_pool = pooling.MySQLConnectionPool(
        pool_name=POOL_NAME,
        pool_size=POOL_SIZE,
        pool_reset_session=True,
        **DB_CONFIG
    )
    print(f"✅ MySQL Connection Pool '{POOL_NAME}' aktif (size={POOL_SIZE})")
except Exception as e:
    print(f"❌ Gagal membuat connection pool: {e}")
    connection_pool = None


# ==============================
# ✅ Fungsi ambil koneksi dari pool
# ==============================
def get_connection():
    """Ambil koneksi dari pool yang sudah dibuat."""
    if connection_pool is None:
        raise RuntimeError("❌ Connection pool belum siap!")
    try:
        conn = connection_pool.get_connection()
        return conn
    except Exception as e:
        print(f"⚠️ Gagal ambil koneksi dari pool: {e}")
        raise
