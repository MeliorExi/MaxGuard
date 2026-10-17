
import unittest
from unittest.mock import patch, Mock

from maxguard.ai.ollama_client import (
    AIUnavailable,
    explain,
    explain_all,
)


def make_finding(rule_id="HTTP-80"):
    """Create a sample finding for testing."""
    return {
        "rule_id": rule_id,
        "title": "Unencrypted HTTP traffic",
        "protocol": "TCP",
        "dst_port": 80,
        "details": "HTTP traffic may expose data in transit.",
        "controls": [
            {"framework": "PCI-DSS", "control_id": "4.2.1"}
        ],
    }


class TestOllamaClient(unittest.TestCase):

    @patch("maxguard.ai.ollama_client.requests.post")
    def test_explain_returns_response(self, mock_post):
        """A successful API response should return its explanation."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": "Use HTTPS to protect data in transit."
        }
        mock_post.return_value = mock_response

        result = explain(make_finding())

        self.assertEqual(
            result,
            "Use HTTPS to protect data in transit."
        )
        mock_post.assert_called_once()

    @patch("maxguard.ai.ollama_client.requests.post")
    def test_explain_all_caches_same_rule_id(self, mock_post):
        """Two findings with the same rule ID should make one API call."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "response": "Use HTTPS to protect data in transit."
        }
        mock_post.return_value = mock_response

        findings = [
            make_finding("HTTP-80"),
            make_finding("HTTP-80"),
        ]

        explain_all(findings)

        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual(
            findings[0]["explanation"],
            findings[1]["explanation"]
        )

    @patch("maxguard.ai.ollama_client.requests.post")
    def test_explain_raises_when_ollama_unavailable(self, mock_post):
        """A connection error should become AIUnavailable."""
        mock_post.side_effect = (
            __import__(
                "requests"
            ).exceptions.ConnectionError("Connection refused")
        )

        with self.assertRaises(AIUnavailable):
            explain(make_finding())


if __name__ == "__main__":
    unittest.main()
