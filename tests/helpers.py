"""Shared fixture: a fresh database + facade with the demo data for every test."""
import os
import tempfile
import unittest

from cryptography.fernet import Fernet

from court.access_proxy import AccessControlProxy
from court.auth import AuthService
from court.database import Database
from court.facade import CourtSchedulingFacade
from court.security import FieldCipher
import seed


class CourtTestCase(unittest.TestCase):
    def setUp(self):
        Database.reset_instance()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database.get_instance(os.path.join(self.tmp.name, "test.db"))
        self.cipher = FieldCipher(Fernet.generate_key())
        seed.seed(self.db, self.cipher)
        self.facade = CourtSchedulingFacade(self.db, self.cipher)
        self.auth = AuthService(self.facade)

    def tearDown(self):
        Database.reset_instance()
        self.tmp.cleanup()

    def as_user(self, username):
        user = self.facade.users.by_username(username)
        return AccessControlProxy(self.facade, user)
