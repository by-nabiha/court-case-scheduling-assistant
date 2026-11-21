"""
Database access point.

DESIGN PATTERN: Singleton (Creational)
---------------------------------------
The whole application must share ONE SQLite connection so that every module
(Case Management, Priority Engine, Scheduling) sees the same data and so that
writes are serialised through a single lock.  `Database.get_instance()` always
returns the same object; the constructor is never called directly by clients.
"""
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT NOT NULL DEFAULT '',
    totp_secret TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    last_login TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS judges (
    judge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    court_name TEXT NOT NULL,
    user_id INTEGER REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS courtrooms (
    courtroom_id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_name TEXT NOT NULL,
    availability_status TEXT NOT NULL DEFAULT 'ACTIVE'
);
CREATE TABLE IF NOT EXISTS availability (
    availability_id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('JUDGE','COURTROOM')),
    resource_id INTEGER NOT NULL,
    available_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_title TEXT NOT NULL,
    case_type TEXT NOT NULL,
    filing_date TEXT NOT NULL,
    parties TEXT NOT NULL DEFAULT '',
    judge_id INTEGER REFERENCES judges(judge_id),
    lawyer_id INTEGER REFERENCES users(user_id),
    case_status TEXT NOT NULL,
    is_urgent INTEGER NOT NULL DEFAULT 0,
    urgency_reason TEXT NOT NULL DEFAULT '',
    vulnerable_party INTEGER NOT NULL DEFAULT 0,
    vulnerability_type TEXT NOT NULL DEFAULT '',   -- stored ENCRYPTED (Fernet)
    priority_score REAL NOT NULL DEFAULT 0,
    priority_level TEXT NOT NULL DEFAULT 'UNASSESSED',
    priority_explanation TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hearings (
    schedule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    judge_id INTEGER NOT NULL REFERENCES judges(judge_id),
    courtroom_id INTEGER NOT NULL REFERENCES courtrooms(courtroom_id),
    hearing_date TEXT NOT NULL,
    hearing_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS conflicts (
    conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id INTEGER REFERENCES hearings(schedule_id),
    conflict_type TEXT NOT NULL,
    description TEXT NOT NULL,
    resolution_status TEXT NOT NULL DEFAULT 'OPEN',
    detected_at TEXT NOT NULL,
    resolution_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_role TEXT NOT NULL,
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    recipient_role TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Database:
    """Singleton wrapper around a single SQLite connection."""

    _instance = None
    _instance_lock = threading.Lock()

    def __init__(self, path):
        if Database._instance is not None:
            raise RuntimeError("Database is a Singleton - use Database.get_instance()")
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    @classmethod
    def get_instance(cls, path="court.db"):
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:      # double-checked locking
                    cls._instance = cls(path)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Used by unit tests to start from a clean database."""
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance.conn.close()
            cls._instance = None

    # -- small helpers used by the repositories --------------------------
    def query(self, sql, params=()):
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql, params=()):
        with self.lock:
            return self.conn.execute(sql, params).fetchone()

    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid
