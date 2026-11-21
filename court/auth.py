"""
Authentication service (NFR-01).

  * generic error message - never reveals whether the username exists
  * constant-time-ish check against a dummy hash for unknown users
  * account lockout: 5 failed attempts -> locked for 15 minutes
  * optional second factor (TOTP) per user
  * every login, failure, lockout and logout is published as an event and
    therefore lands in the tamper-evident audit log (Observer)
"""
from datetime import datetime, timedelta

from .models import CourtError
from .security import DUMMY_HASH, verify_password, verify_totp

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
GENERIC_ERROR = "Invalid username or password."


class AuthenticationError(CourtError):
    pass


def _now():
    return datetime.now().isoformat(timespec="seconds")


class AuthService:
    def __init__(self, facade):
        self.facade = facade
        self.users = facade.users

    def _event(self, user, event_type, username, details=""):
        self.facade.publish(user, event_type, "Session", username, details)

    def authenticate(self, username, password, client=""):
        """Step 1. Returns (user, needs_second_factor)."""
        username = (username or "").strip()[:50]
        user = self.users.by_username(username) if username else None

        if user is None:
            verify_password(DUMMY_HASH, password or "")       # same cost as a real check
            self._event(None, "LOGIN_FAILED", username or "-", f"unknown user {client}")
            raise AuthenticationError(GENERIC_ERROR)

        if not user.is_active:
            self._event(user, "LOGIN_FAILED", username, f"disabled account {client}")
            raise AuthenticationError(GENERIC_ERROR)

        if user.locked_until and user.locked_until > _now():
            self._event(user, "LOGIN_FAILED", username, f"account locked {client}")
            raise AuthenticationError(
                f"Account locked after {MAX_FAILED_ATTEMPTS} failed attempts. "
                f"Try again after {user.locked_until[11:16]} or contact the System Administrator.")

        if not verify_password(user.password_hash, password or ""):
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec="seconds")
                user.failed_attempts = 0
                self.users.update_security(user)
                self._event(user, "ACCOUNT_LOCKED", username,
                            f"{MAX_FAILED_ATTEMPTS} failed attempts {client}")
                raise AuthenticationError(
                    f"Too many failed attempts. The account is locked for {LOCKOUT_MINUTES} minutes.")
            self.users.update_security(user)
            self._event(user, "LOGIN_FAILED", username,
                        f"wrong password ({user.failed_attempts}/{MAX_FAILED_ATTEMPTS}) {client}")
            raise AuthenticationError(GENERIC_ERROR)

        if user.totp_enabled:
            return user, True
        self._success(user, client)
        return user, False

    def verify_second_factor(self, user_id, code, client=""):
        """Step 2 (only for users with two-factor enabled)."""
        user = self.users.get(user_id)
        if user is None or not user.is_active:
            raise AuthenticationError(GENERIC_ERROR)
        if not verify_totp(user.totp_secret, code):
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec="seconds")
                user.failed_attempts = 0
                self.users.update_security(user)
                self._event(user, "ACCOUNT_LOCKED", user.username, f"too many wrong 2FA codes {client}")
                raise AuthenticationError("Too many wrong codes. The account is locked.")
            self.users.update_security(user)
            self._event(user, "LOGIN_FAILED", user.username, f"wrong 2FA code {client}")
            raise AuthenticationError("Invalid verification code.")
        self._success(user, client)
        return user

    def _success(self, user, client):
        user.failed_attempts, user.locked_until = 0, ""
        user.last_login = _now()
        self.users.update_security(user)
        self._event(user, "LOGIN_SUCCESS", user.username,
                    ("with 2FA " if user.totp_enabled else "") + client)

    def logout(self, user, reason="user logout"):
        if user:
            self._event(user, "LOGOUT", user.username, reason)
