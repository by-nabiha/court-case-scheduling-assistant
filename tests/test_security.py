"""Security: Proxy (RBAC), authentication, lockout, 2FA, encryption, audit chain, web hardening."""
import os
import re
import tempfile
import unittest

import pyotp

from court.auth import AuthenticationError
from court.database import Database
from court.models import AccessDeniedError, ValidationError
from court.security import check_password_policy
from tests.helpers import CourtTestCase

PW = "Court@2026!"


class ProxyTests(CourtTestCase):
    def test_T17_lawyer_cannot_generate_schedule(self):
        with self.assertRaises(AccessDeniedError):
            self.as_user("lawyer.ali").generate_schedule("2030-01-01", 3)
        self.assertEqual(self.facade.audit.recent(1)[0]["action"], "ACCESS_DENIED")

    def test_unlisted_method_is_denied_by_default(self):
        with self.assertRaises(AccessDeniedError):
            self.as_user("admin.nabiha").publish(None, "X", "Y", "Z")

    def test_lawyer_sees_only_own_cases(self):
        lawyer = self.as_user("lawyer.ali")
        ali = self.facade.users.by_username("lawyer.ali").user_id
        self.assertTrue(all(c.lawyer_id == ali for c in lawyer.list_cases()))
        with self.assertRaises(AccessDeniedError):
            lawyer.get_case("FM-2025-019")             # Adv. Hina's case

    def test_sysadmin_cannot_read_cases(self):
        with self.assertRaises(AccessDeniedError):
            self.as_user("sysadmin").list_cases()

    def test_deactivated_user_loses_access_immediately(self):
        clerk = self.as_user("clerk.sara")
        self.as_user("sysadmin").set_user_active(self.facade.users.by_username("clerk.sara").user_id, False)
        with self.assertRaises(AccessDeniedError):
            clerk.list_cases()


class AuthenticationTests(CourtTestCase):
    def test_correct_login(self):
        user, needs_2fa = self.auth.authenticate("clerk.sara", PW)
        self.assertEqual(user.username, "clerk.sara")
        self.assertFalse(needs_2fa)

    def test_same_message_for_unknown_user_and_wrong_password(self):
        msgs = []
        for u, p in (("nobody", PW), ("clerk.sara", "wrong")):
            with self.assertRaises(AuthenticationError) as e:
                self.auth.authenticate(u, p)
            msgs.append(str(e.exception))
        self.assertEqual(msgs[0], msgs[1])

    def test_lockout_after_five_failures(self):
        for _ in range(5):
            with self.assertRaises(AuthenticationError):
                self.auth.authenticate("clerk.sara", "wrong")
        with self.assertRaises(AuthenticationError) as e:
            self.auth.authenticate("clerk.sara", PW)       # correct password, still locked
        self.assertIn("locked", str(e.exception))
        self.as_user("sysadmin").unlock_user(self.facade.users.by_username("clerk.sara").user_id)
        self.assertTrue(self.auth.authenticate("clerk.sara", PW)[0])

    def test_passwords_are_hashed(self):
        stored = self.db.query_one("SELECT password_hash FROM users WHERE username='clerk.sara'")[0]
        self.assertNotIn(PW, stored)
        self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))

    def test_password_policy(self):
        for weak in ("short1!", "alllowercase1!", "NoDigitsHere!", "NoSymbol1234"):
            with self.assertRaises(ValidationError):
                check_password_policy(weak)
        check_password_policy("Strong#Pass99")

    def test_two_factor_login(self):
        clerk = self.as_user("clerk.sara")
        secret, uri = clerk.begin_two_factor_setup()
        clerk.confirm_two_factor_setup(pyotp.TOTP(secret).now())
        user, needs_2fa = self.auth.authenticate("clerk.sara", PW)
        self.assertTrue(needs_2fa)
        with self.assertRaises(AuthenticationError):
            self.auth.verify_second_factor(user.user_id, "000000")
        self.assertEqual(self.auth.verify_second_factor(user.user_id, pyotp.TOTP(secret).now()).username,
                         "clerk.sara")


class DataProtectionTests(CourtTestCase):
    def test_vulnerability_detail_is_encrypted_at_rest(self):
        raw = self.db.query_one("SELECT vulnerability_type FROM cases WHERE case_id='FM-2025-019'")[0]
        self.assertNotIn("Minor", raw)
        self.assertEqual(self.facade.cases.get("FM-2025-019").vulnerability_type, "Minor (under 18)")

    def test_vulnerability_detail_never_written_to_audit(self):
        self.as_user("clerk.sara").record_vulnerability("CV-2022-118", True, "Seriously ill")
        rows = " ".join(str(dict(r)) for r in self.facade.audit.recent())
        self.assertNotIn("Seriously ill", rows)

    def test_sql_injection_is_harmless(self):
        clerk = self.as_user("clerk.sara")
        self.assertEqual(clerk.list_cases("x' OR '1'='1"), [])
        self.assertIsNone(self.facade.users.by_username("' OR 1=1 --"))


class AuditChainTests(CourtTestCase):
    def test_T18_actions_are_audited_and_chain_is_intact(self):
        admin = self.as_user("admin.nabiha")
        admin.recalculate_priorities()
        ok, bad, count = self.facade.audit.verify()
        self.assertTrue(ok)
        self.assertGreater(count, 0)

    def test_tampering_is_detected(self):
        admin = self.as_user("admin.nabiha")
        for _ in range(3):
            admin.recalculate_priorities()
        self.db.execute("UPDATE audit_log SET user_name='Someone else' WHERE audit_id=2")
        ok, bad, _ = self.facade.audit.verify()
        self.assertFalse(ok)
        self.assertEqual(bad, 2)

    def test_deleting_an_entry_is_detected(self):
        admin = self.as_user("admin.nabiha")
        for _ in range(3):
            admin.recalculate_priorities()
        self.db.execute("DELETE FROM audit_log WHERE audit_id=2")
        self.assertFalse(self.facade.audit.verify()[0])


class WebSecurityTests(unittest.TestCase):
    """HTTP-level checks against the real Flask app."""

    def setUp(self):
        Database.reset_instance()
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["COURT_INSTANCE"] = self.tmp.name
        import seed
        from app import create_app
        from court.security import FieldCipher
        self.app = create_app(os.path.join(self.tmp.name, "web.db"), testing=True)
        seed.seed(Database.get_instance(), FieldCipher.from_environment(os.path.join(self.tmp.name, "field.key")))
        self.client = self.app.test_client()

    def tearDown(self):
        Database.reset_instance()
        os.environ.pop("COURT_INSTANCE", None)
        self.tmp.cleanup()

    def token(self, path="/login"):
        return re.search(r'name="csrf_token" value="([^"]+)"', self.client.get(path).text).group(1)

    def login(self, user="admin.nabiha", password=PW):
        return self.client.post("/login", data={"csrf_token": self.token(), "username": user,
                                                "password": password})

    def test_pages_require_login(self):
        self.assertIn("/login", self.client.get("/cases").headers["Location"])

    def test_security_headers(self):
        r = self.client.get("/login")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_session_cookie_flags(self):
        cookie = self.login().headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_post_without_csrf_token_is_rejected(self):
        r = self.client.post("/login", data={"username": "admin.nabiha", "password": PW})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(self.client.get("/").status_code == 200)

    def test_html_is_escaped(self):
        self.login("clerk.sara")
        self.client.post("/cases/new", data={"csrf_token": self.token("/cases/new"), "case_id": "CV-2026-777",
                                             "case_type": "CIVIL", "case_title": "<script>alert(1)</script>",
                                             "filing_date": "2026-01-01", "parties": "A vs B"})
        page = self.client.get("/cases/CV-2026-777").text
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_full_login_and_logout(self):
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        self.assertEqual(self.client.get("/").status_code, 302)


if __name__ == "__main__":
    unittest.main()
