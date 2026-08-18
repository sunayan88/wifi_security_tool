import os
import tempfile
import unittest
from unittest.mock import patch

from database import db_manager


class AuthDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "auth_test.db")
        self.path_patch = patch.object(db_manager, "DB_PATH", self.db_path)
        self.path_patch.start()
        db_manager.initialize_db()

    def tearDown(self):
        self.path_patch.stop()
        self.tempdir.cleanup()

    def test_register_rejects_weak_password(self):
        ok, message = db_manager.register_user("student", "weak")

        self.assertFalse(ok)
        self.assertIn("at least 8 characters", message)

    def test_register_stores_bcrypt_hash_not_plaintext(self):
        ok, message = db_manager.register_user("student", "StrongPass1")
        self.assertTrue(ok, message)

        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password, hash_version FROM users WHERE username = ?", ("student",))
        stored, version = cursor.fetchone()
        conn.close()

        self.assertEqual(version, "bcrypt")
        self.assertNotEqual(stored, "StrongPass1")
        self.assertTrue(stored.startswith("$2"))

    def test_login_success_and_failure(self):
        ok, message = db_manager.register_user("student", "StrongPass1")
        self.assertTrue(ok, message)

        success, result = db_manager.login_user("student", "StrongPass1")
        self.assertTrue(success)
        self.assertEqual(result[1], "student")

        success, message = db_manager.login_user("student", "WrongPass1")
        self.assertFalse(success)
        self.assertEqual(message, "Incorrect username or password.")


if __name__ == "__main__":
    unittest.main()
