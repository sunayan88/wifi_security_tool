import os
import tempfile
import unittest
from unittest.mock import patch

from database import db_manager


class DatabasePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "test.db")
        self.path_patch = patch.object(db_manager, "DB_PATH", self.db_path)
        self.path_patch.start()
        db_manager.initialize_db()

    def tearDown(self):
        self.path_patch.stop()
        self.tempdir.cleanup()

    def test_gateway_requires_explicit_approval(self):
        self.assertIsNone(db_manager.get_approved_gateway("Home", "192.168.1.1"))
        db_manager.approve_gateway("Home", "192.168.1.1", "aa-bb-cc-dd-ee-ff")

        baseline = db_manager.get_approved_gateway("Home", "192.168.1.1")
        self.assertEqual(baseline["mac"], "AA:BB:CC:DD:EE:FF")

    def test_activity_clear_preserves_labels_and_trust(self):
        db_manager.save_device("192.168.1.2", "AA:AA:AA:AA:AA:AA", "phone", "New")
        db_manager.save_wifi_scan("Home", "WPA3", "SAFE")
        db_manager.save_alert("WIFI", "test")
        db_manager.set_device_label("AA:AA:AA:AA:AA:AA", "My phone")
        db_manager.add_trusted_bssid("Home", "BB:BB:BB:BB:BB:BB")
        db_manager.approve_gateway(
            "Home", "192.168.1.1", "CC:CC:CC:CC:CC:CC"
        )

        db_manager.clear_activity_history()
        counts = db_manager.get_privacy_counts()

        self.assertEqual(counts["devices"], 0)
        self.assertEqual(counts["wifi_scans"], 0)
        self.assertEqual(counts["alerts"], 0)
        self.assertEqual(counts["device_labels"], 1)
        self.assertEqual(counts["trusted_networks"], 1)
        self.assertEqual(counts["trusted_gateways"], 1)

    def test_retention_keeps_newest_records(self):
        with patch.object(db_manager, "MAX_ALERT_HISTORY", 2):
            db_manager.save_alert("SYSTEM", "one")
            db_manager.save_alert("SYSTEM", "two")
            db_manager.save_alert("SYSTEM", "three")

        messages = [row[2] for row in db_manager.get_recent_alerts()]
        self.assertEqual(messages, ["three", "two"])


if __name__ == "__main__":
    unittest.main()
