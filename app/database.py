import sqlite3
import threading
from contextlib import contextmanager
from app.config import DATABASE_PATH

_thread_local = threading.local()

def get_connection():
    """Get a thread-local SQLite connection with foreign keys enabled."""
    if not hasattr(_thread_local, "connection") or _thread_local.connection is None:
        conn = sqlite3.connect(
            str(DATABASE_PATH),
            check_same_thread=False,
            timeout=30.0
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        _thread_local.connection = conn
    return _thread_local.connection

@contextmanager
def get_db():
    """Context manager for SQLite transactions."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise

def execute_query(query: str, params: tuple = (), fetch_one: bool = False, fetch_all: bool = False):
    """Utility to execute a query and commit/fetch safely."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        if fetch_one:
            row = cursor.fetchone()
            return dict(row) if row else None
        if fetch_all:
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        return cursor.lastrowid
