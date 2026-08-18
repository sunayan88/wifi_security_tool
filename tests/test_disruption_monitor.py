import unittest

from modules.disruption_monitor import SymptomDisruptionMonitor


class DisruptionMonitorTests(unittest.TestCase):
    def test_frequent_disconnects_become_suspicious(self):
        monitor = SymptomDisruptionMonitor(lambda _snapshot: None)
        for _ in range(3):
            monitor._record("disconnect", "WiFi disconnected.")

        snapshot = monitor.snapshot()

        self.assertIn(snapshot["status"], {"suspicious", "high_risk"})
        self.assertEqual(snapshot["disconnects"], 3)

    def test_bssid_and_gateway_changes_raise_score(self):
        monitor = SymptomDisruptionMonitor(lambda _snapshot: None)
        monitor._record("bssid_change", "BSSID changed.")
        monitor._record("gateway_change", "Gateway changed.")

        snapshot = monitor.snapshot()

        self.assertGreaterEqual(snapshot["score"], 6)
        self.assertEqual(snapshot["status"], "suspicious")

    def test_signal_drop_is_unstable(self):
        monitor = SymptomDisruptionMonitor(lambda _snapshot: None)
        monitor._record("signal_drop", "Signal dropped.")

        snapshot = monitor.snapshot()

        self.assertEqual(snapshot["signal_drops"], 1)
        self.assertEqual(snapshot["status"], "unstable")


if __name__ == "__main__":
    unittest.main()
