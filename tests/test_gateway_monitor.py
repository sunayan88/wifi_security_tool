import unittest
from unittest.mock import patch

from modules.arp_monitor import check_arp_spoof


APPROVED_GATEWAY = {
    "network": "HomeWiFi",
    "ip": "192.168.1.1",
    "mac": "AA:BB:CC:DD:EE:FF",
}


class GatewayMonitorLogicTests(unittest.TestCase):
    @patch("modules.arp_monitor.take_gateway_snapshot")
    def test_matching_gateway_is_safe(self, snapshot):
        snapshot.return_value = {
            "network": "HomeWiFi",
            "ip": "192.168.1.1",
            "mac": "AA:BB:CC:DD:EE:FF",
        }

        result = check_arp_spoof(APPROVED_GATEWAY)

        self.assertEqual(result["status"], "safe")
        self.assertEqual(result["current_mac"], "AA:BB:CC:DD:EE:FF")

    @patch("modules.arp_monitor.save_alert")
    @patch("modules.arp_monitor.take_gateway_snapshot")
    def test_gateway_mac_change_is_spoofed_indicator(self, snapshot, save_alert):
        snapshot.return_value = {
            "network": "HomeWiFi",
            "ip": "192.168.1.1",
            "mac": "11:22:33:44:55:66",
        }

        result = check_arp_spoof(APPROVED_GATEWAY)

        self.assertEqual(result["status"], "spoofed")
        self.assertEqual(result["known_mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result["current_mac"], "11:22:33:44:55:66")
        save_alert.assert_called_once()

    @patch("modules.arp_monitor.save_alert")
    @patch("modules.arp_monitor.take_gateway_snapshot")
    def test_gateway_ip_change_is_spoofed_indicator(self, snapshot, save_alert):
        snapshot.return_value = {
            "network": "HomeWiFi",
            "ip": "192.168.1.254",
            "mac": "AA:BB:CC:DD:EE:FF",
        }

        result = check_arp_spoof(APPROVED_GATEWAY)

        self.assertEqual(result["status"], "spoofed")
        self.assertEqual(result["current_ip"], "192.168.1.254")
        save_alert.assert_called_once()

    @patch("modules.arp_monitor.take_gateway_snapshot")
    def test_unreachable_gateway_returns_unreachable(self, snapshot):
        snapshot.return_value = None

        result = check_arp_spoof(APPROVED_GATEWAY)

        self.assertEqual(result["status"], "unreachable")
        self.assertIsNone(result["current_mac"])

    def test_missing_baseline_returns_unreachable(self):
        result = check_arp_spoof(None)

        self.assertEqual(result["status"], "unreachable")
        self.assertIn("No gateway snapshot", result["message"])


if __name__ == "__main__":
    unittest.main()
