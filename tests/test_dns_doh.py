import unittest
from unittest.mock import Mock, patch

from modules.dns_check import _query_doh


class DoHQueryTests(unittest.TestCase):
    @patch("modules.dns_check.requests.get")
    def test_query_doh_parses_a_records(self, get):
        response = Mock()
        response.ok = True
        response.json.return_value = {
            "Status": 0,
            "Answer": [
                {"type": 5, "data": "example.cdn.test"},
                {"type": 1, "data": "93.184.216.34"},
                {"type": 1, "data": "93.184.216.34"},
            ],
        }
        get.return_value = response

        self.assertEqual(_query_doh("cloudflare", "example.com"), ["93.184.216.34"])

    @patch("modules.dns_check.requests.get")
    def test_query_doh_returns_none_on_http_failure(self, get):
        response = Mock()
        response.ok = False
        get.return_value = response

        self.assertIsNone(_query_doh("google", "example.com"))


if __name__ == "__main__":
    unittest.main()
