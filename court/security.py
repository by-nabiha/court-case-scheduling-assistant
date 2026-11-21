"""
Security utilities (NFR-01 Security, NFR-02 Privacy, NFR-09 Auditability).

  * Password hashing + password policy  (Werkzeug scrypt/PBKDF2, salted)
  * Field encryption at rest            (Fernet = AES-128-CBC + HMAC-SHA256)
  * Tamper-evident audit hash chain     (SHA-256)
  * Two-factor authentication           (TOTP, RFC 6238, via pyotp)
"""
import hashlib
import os
import re
from pathlib import Path

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

from .models import ValidationError

# ------------------------------------------------------------------ passwords
PASSWORD_RULES = ("at least 10 characters, with an uppercase letter, a lowercase "
                  "letter, a digit and a symbol")


def check_password_policy(password: str):
    problems = []
    if len(password) < 10:
        problems.append("at least 10 characters")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a symbol")
    if problems:
        raise ValidationError("Password must contain " + ", ".join(problems) + ".")


def hash_password(password: str) -> str:
    check_password_policy(password)
    return generate_password_hash(password)          # salted, slow hash


def verify_password(password_hash: str, password: str) -> bool:
    return bool(password_hash) and check_password_hash(password_hash, password)


# A valid hash used when the username does not exist, so a login attempt for
# an unknown user takes the same time as for a real one (no user enumeration).
DUMMY_HASH = generate_password_hash("Dummy-Password-123!")


# ----------------------------------------------------------------- encryption
class FieldCipher:
    """Encrypts sensitive columns (vulnerability details) before they reach SQLite."""

    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    @classmethod
    def from_environment(cls, key_file="instance/field.key"):
        key = os.environ.get("COURT_FIELD_KEY")
        if key:
            return cls(key.encode())
        path = Path(key_file)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(Fernet.generate_key())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return cls(path.read_bytes().strip())

    def encrypt(self, text: str) -> str:
        if not text:
            return ""
        return self._fernet.encrypt(text.encode()).decode()

    def decrypt(self, token: str) -> str:
        if not token:
            return ""
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return "[unreadable - wrong encryption key]"


# ----------------------------------------------------------- audit hash chain
GENESIS_HASH = "0" * 64
AUDIT_FIELDS = ("timestamp", "user_name", "user_role", "action", "entity",
                "entity_id", "details", "reason")


def audit_hash(prev_hash: str, record: dict) -> str:
    payload = prev_hash + "|" + "|".join(str(record[f]) for f in AUDIT_FIELDS)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_audit_chain(rows):
    """Return (ok, first_bad_audit_id).  rows must be ordered by audit_id."""
    prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != prev or audit_hash(prev, row) != row["entry_hash"]:
            return False, row["audit_id"]
        prev = row["entry_hash"]
    return True, None


# ---------------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username,
                                               issuer_name="Court Scheduling Assistant")


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    return bool(secret) and code.isdigit() and pyotp.TOTP(secret).verify(code, valid_window=1)
