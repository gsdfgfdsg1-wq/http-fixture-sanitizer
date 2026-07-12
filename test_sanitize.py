import unittest
from sanitize import sanitize


class SanitizerTests(unittest.TestCase):
    def fixture(self):
        return {"request": {"headers": {"Authorization": "secret"}, "url": "https://x.test/a?token=abc&keep=y"}, "response": {"json": {"user": {"email": "a@b.test"}}}}

    def test_redacts_header(self):
        result = sanitize(self.fixture(), header_names=["Authorization"])
        self.assertEqual(result["fixture"]["request"]["headers"]["Authorization"], "[REDACTED]")

    def test_redacts_query_but_keeps_shape(self):
        result = sanitize(self.fixture(), query_names=["token"])
        self.assertIn("token=%5BREDACTED%5D", result["fixture"]["request"]["url"])
        self.assertIn("keep=y", result["fixture"]["request"]["url"])

    def test_redacts_json_path_and_audits(self):
        result = sanitize(self.fixture(), json_paths=["/user/email"])
        self.assertEqual(result["fixture"]["response"]["json"]["user"]["email"], "[REDACTED]")
        self.assertEqual(result["audit"], ["json:/user/email"])


if __name__ == "__main__":
    unittest.main()
