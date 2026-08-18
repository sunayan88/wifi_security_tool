import unittest

from modules.device_monitor import build_identity_status, is_private_mac


class DeviceIdentityTests(unittest.TestCase):
    def test_private_mac_detection(self):
        self.assertTrue(is_private_mac("02:11:22:33:44:55"))
        self.assertFalse(is_private_mac("00:11:22:33:44:55"))

    def test_new_mac_status(self):
        status, is_new = build_identity_status(
            "AA:BB:CC:DD:EE:FF",
            "HomeWiFi",
            known_macs=set(),
            network_map={},
        )
        self.assertEqual(status, "New MAC")
        self.assertTrue(is_new)

    def test_known_mac_new_wifi_status(self):
        status, is_new = build_identity_status(
            "AA:BB:CC:DD:EE:FF",
            "CafeWiFi",
            known_macs={"AA:BB:CC:DD:EE:FF"},
            network_map={"AA:BB:CC:DD:EE:FF": {"HomeWiFi"}},
        )
        self.assertEqual(status, "Known MAC / New WiFi")
        self.assertFalse(is_new)


if __name__ == "__main__":
    unittest.main()
