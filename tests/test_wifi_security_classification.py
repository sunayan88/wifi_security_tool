import unittest

from config import RISK_DANGEROUS, RISK_RISKY, RISK_SAFE
from modules.wifi_analyzer import classify_security, detect_wps_from_text


class WiFiSecurityClassificationTests(unittest.TestCase):
    def test_open_and_wep_are_dangerous(self):
        self.assertEqual(classify_security("Open")["risk"], RISK_DANGEROUS)
        self.assertEqual(classify_security("WEP")["risk"], RISK_DANGEROUS)

    def test_wpa_is_risky(self):
        self.assertEqual(classify_security("WPA-Personal")["risk"], RISK_RISKY)

    def test_wpa2_and_wpa3_labels(self):
        self.assertEqual(classify_security("WPA2-Personal", "CCMP")["label"], "Safer")
        self.assertEqual(classify_security("WPA3-Personal", "GCMP")["label"], "Stronger")
        self.assertEqual(classify_security("WPA2-Personal", "CCMP")["risk"], RISK_SAFE)

    def test_wpa2_tkip_is_risky(self):
        self.assertEqual(classify_security("WPA2-Personal", "TKIP")["risk"], RISK_RISKY)

    def test_wps_detection_from_text(self):
        self.assertEqual(detect_wps_from_text("WPS Configured : Yes"), "Enabled / Visible")
        self.assertEqual(detect_wps_from_text("WPS Configured : No"), "Disabled / Not visible")
        self.assertEqual(detect_wps_from_text("Authentication : WPA2-Personal"), "Unknown")


if __name__ == "__main__":
    unittest.main()
