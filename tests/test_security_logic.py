import unittest
from unittest.mock import Mock, patch

from modules.dns_check import check_dns_integrity
from modules.portal_check import PROBE_URLS, check_portal


class PortalCheckTests(unittest.TestCase):
    @patch("modules.portal_check.requests.get")
    def test_expected_body_means_online(self, get):
        response = Mock()
        response.status_code = 200
        response.text = "Microsoft Connect Test"
        response.content = b"Microsoft Connect Test"
        response.is_redirect = False
        get.side_effect = [
            __import__("requests").ConnectionError(),
            response,
        ]

        self.assertEqual(check_portal()["status"], "online")

    @patch("modules.portal_check.requests.get")
    def test_replaced_success_page_means_portal(self, get):
        response = Mock()
        response.status_code = 200
        response.text = "<html>Sign in to WiFi</html>"
        response.content = response.text.encode()
        response.is_redirect = False
        get.return_value = response

        self.assertEqual(check_portal()["status"], "captive_portal")

    @patch("modules.portal_check.requests.get")
    def test_all_probe_failures_mean_no_internet(self, get):
        get.side_effect = __import__("requests").ConnectionError()

        self.assertEqual(check_portal()["status"], "no_internet")


class DNSCheckTests(unittest.TestCase):
    @patch("modules.dns_check._query_doh")
    @patch("modules.dns_check._query_system")
    def test_reference_disagreement_is_inconclusive(self, system, doh):
        system.return_value = ["10.0.0.1"]
        doh.side_effect = [["1.1.1.1"], ["2.2.2.2"]] * 3

        self.assertEqual(check_dns_integrity()["status"], "inconclusive")

    @patch("modules.dns_check._query_doh")
    @patch("modules.dns_check._query_system")
    def test_repeated_system_mismatch_is_suspicious(self, system, doh):
        system.return_value = ["10.0.0.1"]
        doh.return_value = ["1.1.1.1"]

        self.assertEqual(check_dns_integrity()["status"], "suspicious")

    @patch("modules.dns_check._query_doh")
    @patch("modules.dns_check._query_system")
    def test_all_dns_methods_unreachable(self, system, doh):
        system.return_value = None
        doh.return_value = None

        self.assertEqual(check_dns_integrity()["status"], "unreachable")


if __name__ == "__main__":
    unittest.main()
