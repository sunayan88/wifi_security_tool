import os
import unittest
from unittest.mock import Mock, patch

from modules.network_identity import check_network_identity


class NetworkIdentityTests(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=True)
    @patch("modules.network_identity._read_token_file", return_value="")
    def test_missing_token_is_reported(self, _read_token_file):
        self.assertEqual(check_network_identity()["status"], "missing_token")

    @patch.dict(os.environ, {"IPINFO_TOKEN": "test-token"}, clear=True)
    @patch("modules.network_identity.requests.get")
    def test_ipinfo_lite_response_is_normalized(self, get):
        response = Mock()
        response.ok = True
        response.status_code = 200
        response.json.return_value = {
            "ip": "8.8.8.8",
            "asn": "AS15169",
            "as_name": "Google LLC",
            "as_domain": "google.com",
            "country": "United States",
            "country_code": "US",
            "continent": "North America",
        }
        get.return_value = response

        result = check_network_identity()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["public_ip"], "8.8.8.8")
        self.assertEqual(result["isp"], "Google LLC")
        self.assertEqual(result["asn"], "AS15169")
        self.assertIn("United States", result["location"])

    @patch.dict(os.environ, {}, clear=True)
    @patch("modules.network_identity._read_token_file", return_value="file-token")
    @patch("modules.network_identity.requests.get")
    def test_token_file_is_used_when_env_is_missing(self, get, _read_token_file):
        response = Mock()
        response.ok = True
        response.status_code = 200
        response.json.return_value = {"ip": "1.1.1.1", "asn": "AS13335", "as_name": "Cloudflare"}
        get.return_value = response

        self.assertEqual(check_network_identity()["status"], "ok")
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"], "Bearer file-token")


if __name__ == "__main__":
    unittest.main()
