"""
Repositories: the only classes that contain SQL.

All statements use parameter placeholders (?) - user input is never
concatenated into SQL, which prevents SQL injection.
Sensitive case data (vulnerability details) is encrypted/decrypted here, so
the rest of the system only ever sees plain domain objects.
"""
from datetime import datetime

from .case_management.case_factory import CaseFactory
from .models import (Availability, Courtroom, HearingSchedule, Judge,
                     NotFoundError, SchedulingConflict, SystemUser)
from .security import GENESIS_HASH, audit_hash, verify_audit_chain


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class UserRepository:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def _to_user(r):
        if r is None:
            return None
        return SystemUser(r["user_id"], r["username"], r["name"], r["email"], r["role"],
                          r["password_hash"], bool(r["is_active"]), r["failed_attempts"],
                          r["locked_until"], r["totp_secret"], bool(r["totp_enabled"]),
                          r["last_login"])

    def get(self, user_id):
        return self._to_user(self.db.query_one("SELECT * FROM users WHERE user_id=?", (user_id,)))

    def by_username(self, username):
        return self._to_user(self.db.query_one(
            "SELECT * FROM users WHERE lower(username)=lower(?)", (username,)))

    def all(self):
        return [self._to_user(r) for r in self.db.query("SELECT * FROM users ORDER BY role, name")]

    def by_role(self, role):
        return [self._to_user(r) for r in self.db.query(
            "SELECT * FROM users WHERE role=? ORDER BY name", (role,))]

    def add(self, username, name, email, role, password_hash):
        return self.db.execute(
            "INSERT INTO users (username,name,email,role,password_hash) VALUES (?,?,?,?,?)",
            (username, name, email, role, password_hash))

    def update_security(self, user):
        self.db.execute(
            """UPDATE users SET password_hash=?, is_active=?, failed_attempts=?, locked_until=?,
               totp_secret=?, totp_enabled=?, last_login=? WHERE user_id=?""",
            (user.password_hash, int(user.is_active), user.failed_attempts, user.locked_until,
             user.totp_secret, int(user.totp_enabled), user.last_login, user.user_id))


class JudgeRepository:
    def __init__(self, db):
        self.db = db

    def all(self):
        return [Judge(r["judge_id"], r["name"], r["court_name"], r["user_id"])
                for r in self.db.query("SELECT * FROM judges ORDER BY judge_id")]

    def get(self, judge_id):
        r = self.db.query_one("SELECT * FROM judges WHERE judge_id=?", (judge_id,))
        return Judge(r["judge_id"], r["name"], r["court_name"], r["user_id"]) if r else None

    def by_user(self, user_id):
        r = self.db.query_one("SELECT * FROM judges WHERE user_id=?", (user_id,))
        return Judge(r["judge_id"], r["name"], r["court_name"], r["user_id"]) if r else None

    def add(self, name, court_name, user_id=None):
        return self.db.execute("INSERT INTO judges (name,court_name,user_id) VALUES (?,?,?)",
                               (name, court_name, user_id))


class CourtroomRepository:
    def __init__(self, db):
        self.db = db

    def all(self):
        return [Courtroom(r["courtroom_id"], r["room_name"], r["availability_status"])
                for r in self.db.query("SELECT * FROM courtrooms ORDER BY courtroom_id")]

    def get(self, courtroom_id):
        r = self.db.query_one("SELECT * FROM courtrooms WHERE courtroom_id=?", (courtroom_id,))
        return Courtroom(r["courtroom_id"], r["room_name"], r["availability_status"]) if r else None

    def add(self, room_name):
        return self.db.execute("INSERT INTO courtrooms (room_name) VALUES (?)", (room_name,))

    def set_status(self, courtroom_id, status):
        self.db.execute("UPDATE courtrooms SET availability_status=? WHERE courtroom_id=?",
                        (status, courtroom_id))


class AvailabilityRepository:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def _to(r):
        return Availability(r["availability_id"], r["resource_type"], r["resource_id"],
                            r["available_date"], r["start_time"], r["end_time"])

    def all(self, from_date=None):
        if from_date:
            rows = self.db.query("SELECT * FROM availability WHERE available_date>=? "
                                 "ORDER BY available_date,start_time", (from_date,))
        else:
            rows = self.db.query("SELECT * FROM availability ORDER BY available_date,start_time")
        return [self._to(r) for r in rows]

    def get(self, availability_id):
        r = self.db.query_one("SELECT * FROM availability WHERE availability_id=?", (availability_id,))
        return self._to(r) if r else None

    def add(self, a: Availability):
        return self.db.execute(
            "INSERT INTO availability (resource_type,resource_id,available_date,start_time,end_time) "
            "VALUES (?,?,?,?,?)",
            (a.resource_type, a.resource_id, a.available_date, a.start_time, a.end_time))

    def delete(self, availability_id):
        self.db.execute("DELETE FROM availability WHERE availability_id=?", (availability_id,))


class CaseRepository:
    COLUMNS = ("case_id", "case_title", "case_type", "filing_date", "parties", "judge_id",
               "lawyer_id", "case_status", "is_urgent", "urgency_reason", "vulnerable_party",
               "vulnerability_type", "priority_score", "priority_level", "priority_explanation")

    def __init__(self, db, cipher):
        self.db = db
        self.cipher = cipher

    def _to_case(self, r):
        if r is None:
            return None
        return CaseFactory.create(
            r["case_type"], case_id=r["case_id"], case_title=r["case_title"],
            filing_date=r["filing_date"], parties=r["parties"], judge_id=r["judge_id"],
            lawyer_id=r["lawyer_id"], case_status=r["case_status"],
            is_urgent=bool(r["is_urgent"]), urgency_reason=r["urgency_reason"],
            vulnerable_party=bool(r["vulnerable_party"]),
            vulnerability_type=self.cipher.decrypt(r["vulnerability_type"]),
            priority_score=r["priority_score"], priority_level=r["priority_level"],
            priority_explanation=r["priority_explanation"])

    def _values(self, c):
        return (c.case_id, c.case_title, c.case_type, c.filing_date, c.parties, c.judge_id,
                c.lawyer_id, c.case_status, int(c.is_urgent), c.urgency_reason,
                int(c.vulnerable_party), self.cipher.encrypt(c.vulnerability_type),
                c.priority_score, c.priority_level, c.priority_explanation)

    def get(self, case_id):
        case = self._to_case(self.db.query_one("SELECT * FROM cases WHERE case_id=?", (case_id,)))
        if case is None:
            raise NotFoundError(f"Case {case_id} not found")
        return case

    def exists(self, case_id):
        return self.db.query_one("SELECT 1 FROM cases WHERE case_id=?", (case_id,)) is not None

    def all(self, lawyer_id=None):
        if lawyer_id is not None:
            rows = self.db.query("SELECT * FROM cases WHERE lawyer_id=? ORDER BY filing_date", (lawyer_id,))
        else:
            rows = self.db.query("SELECT * FROM cases ORDER BY filing_date")
        return [self._to_case(r) for r in rows]

    def by_status(self, *statuses):
        marks = ",".join("?" * len(statuses))
        return [self._to_case(r) for r in self.db.query(
            f"SELECT * FROM cases WHERE case_status IN ({marks}) ORDER BY filing_date", statuses)]

    def add(self, c):
        marks = ",".join("?" * len(self.COLUMNS))
        self.db.execute(f"INSERT INTO cases ({','.join(self.COLUMNS)}) VALUES ({marks})",
                        self._values(c))

    def save(self, c):
        sets = ",".join(f"{col}=?" for col in self.COLUMNS[1:])
        vals = self._values(c)
        self.db.execute(f"UPDATE cases SET {sets} WHERE case_id=?", vals[1:] + (vals[0],))


class HearingRepository:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def _to(r):
        return HearingSchedule(r["schedule_id"], r["case_id"], r["judge_id"], r["courtroom_id"],
                               r["hearing_date"], r["hearing_time"], r["end_time"], r["status"],
                               r["created_by"], r["reason"])

    def get(self, schedule_id):
        r = self.db.query_one("SELECT * FROM hearings WHERE schedule_id=?", (schedule_id,))
        if r is None:
            raise NotFoundError(f"Hearing #{schedule_id} not found")
        return self._to(r)

    def all(self):
        return [self._to(r) for r in self.db.query(
            "SELECT * FROM hearings ORDER BY hearing_date, hearing_time, courtroom_id")]

    def active(self):
        return [self._to(r) for r in self.db.query(
            "SELECT * FROM hearings WHERE status IN ('PENDING_APPROVAL','APPROVED','CHANGES_REQUESTED') "
            "ORDER BY hearing_date, hearing_time")]

    def for_case(self, case_id):
        return [self._to(r) for r in self.db.query(
            "SELECT * FROM hearings WHERE case_id=? ORDER BY schedule_id", (case_id,))]

    def add(self, h):
        return self.db.execute(
            "INSERT INTO hearings (case_id,judge_id,courtroom_id,hearing_date,hearing_time,end_time,"
            "status,created_by,reason) VALUES (?,?,?,?,?,?,?,?,?)",
            (h.case_id, h.judge_id, h.courtroom_id, h.hearing_date, h.hearing_time, h.end_time,
             h.status, h.created_by, h.reason))

    def save(self, h):
        self.db.execute(
            "UPDATE hearings SET judge_id=?,courtroom_id=?,hearing_date=?,hearing_time=?,end_time=?,"
            "status=?,reason=? WHERE schedule_id=?",
            (h.judge_id, h.courtroom_id, h.hearing_date, h.hearing_time, h.end_time, h.status,
             h.reason, h.schedule_id))


class ConflictRepository:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def _to(r):
        return SchedulingConflict(r["conflict_id"], r["schedule_id"], r["conflict_type"],
                                  r["description"], r["resolution_status"], r["detected_at"],
                                  r["resolution_note"])

    def add(self, schedule_id, conflict_type, description):
        # do not duplicate an identical open conflict
        existing = self.db.query_one(
            "SELECT conflict_id FROM conflicts WHERE schedule_id IS ? AND conflict_type=? "
            "AND description=? AND resolution_status='OPEN'", (schedule_id, conflict_type, description))
        if existing:
            return existing["conflict_id"]
        return self.db.execute(
            "INSERT INTO conflicts (schedule_id,conflict_type,description,detected_at) VALUES (?,?,?,?)",
            (schedule_id, conflict_type, description, _now()))

    def get(self, conflict_id):
        r = self.db.query_one("SELECT * FROM conflicts WHERE conflict_id=?", (conflict_id,))
        if r is None:
            raise NotFoundError(f"Conflict #{conflict_id} not found")
        return self._to(r)

    def all(self):
        return [self._to(r) for r in self.db.query(
            "SELECT * FROM conflicts ORDER BY resolution_status DESC, conflict_id DESC")]

    def open_for(self, schedule_id):
        return [self._to(r) for r in self.db.query(
            "SELECT * FROM conflicts WHERE schedule_id=? AND resolution_status='OPEN'", (schedule_id,))]

    def resolve(self, conflict_id, note):
        self.db.execute("UPDATE conflicts SET resolution_status='RESOLVED', resolution_note=? "
                        "WHERE conflict_id=?", (note, conflict_id))


class SettingsRepository:
    def __init__(self, db):
        self.db = db

    def get(self, key, default=None):
        r = self.db.query_one("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else default

    def set(self, key, value):
        self.db.execute("INSERT INTO settings (key,value) VALUES (?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


class AuditRepository:
    """Append-only, hash-chained audit trail (FR-15, NFR-09, DR-08)."""

    def __init__(self, db):
        self.db = db

    def add(self, event):
        with self.db.lock:
            last = self.db.query_one("SELECT entry_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1")
            prev = last["entry_hash"] if last else GENESIS_HASH
            record = {"timestamp": event.timestamp, "user_name": event.actor_name,
                      "user_role": event.actor_role, "action": event.event_type,
                      "entity": event.entity, "entity_id": str(event.entity_id),
                      "details": event.details, "reason": event.reason}
            self.db.execute(
                "INSERT INTO audit_log (timestamp,user_name,user_role,action,entity,entity_id,"
                "details,reason,prev_hash,entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (*record.values(), prev, audit_hash(prev, record)))

    def recent(self, limit=300, entity_id=None):
        if entity_id:
            return self.db.query("SELECT * FROM audit_log WHERE entity_id=? ORDER BY audit_id DESC",
                                 (str(entity_id),))
        return self.db.query("SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT ?", (limit,))

    def verify(self):
        rows = [dict(r) for r in self.db.query("SELECT * FROM audit_log ORDER BY audit_id")]
        ok, bad = verify_audit_chain(rows)
        return ok, bad, len(rows)


class NotificationRepository:
    def __init__(self, db):
        self.db = db

    def add(self, role, message, timestamp):
        self.db.execute("INSERT INTO notifications (timestamp,recipient_role,message) VALUES (?,?,?)",
                        (timestamp, role, message))

    def for_role(self, role, limit=50):
        return self.db.query("SELECT * FROM notifications WHERE recipient_role=? "
                             "ORDER BY notification_id DESC LIMIT ?", (role, limit))
