# db.py
from mysql.connector import pooling
import os

DB_HOST = os.environ.get("DB_HOST") or "localhost"
DB_USER = os.environ.get("DB_USER") or "root"
DB_PASS = os.environ.get("DB_PASS") or ""
DB_NAME = os.environ.get("DB_NAME") or "siskamling_digital"
DB_PORT = int(os.environ.get("DB_PORT") or 3306)

DB_CONFIG = {
    "host": DB_HOST,
    "user": DB_USER,
    "password": DB_PASS,
    "database": DB_NAME,
    "port": DB_PORT,
    "charset": "utf8mb4",
    "use_pure": True
}

# DB_CONFIG = {
#     "host": os.environ.get("DB_HOST", "localhost"),
#     "user": os.environ.get("DB_USER", "root"),
#     "password": os.environ.get("DB_PASS", ""),
#     "database": os.environ.get("DB_NAME", "siskamling_digital"),
#     "port": int(os.environ.get("DB_PORT", 3306)),
#     "charset": "utf8mb4",
#     "use_pure": True
# }
print("📦 MySQL config:", DB_CONFIG)

# POOL_NAME = os.environ.get("DB_POOL_NAME", "flask_pool")
# POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", 10))
POOL_NAME = os.environ.get("DB_POOL_NAME", "flask_pool")
POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", 10))

# connection_pool = pooling.MySQLConnectionPool(
#     pool_name=POOL_NAME,
#     pool_size=POOL_SIZE,
#     **DB_CONFIG
# )
connection_pool = pooling.MySQLConnectionPool(
    pool_name=POOL_NAME,
    pool_size=POOL_SIZE,
    **DB_CONFIG
)

def get_connection():
    return connection_pool.get_connection()
