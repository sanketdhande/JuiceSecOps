from __future__ import annotations

import json
import unittest
from unittest import mock

from juicesecops.providers.openrouter import (
    DEFAULT_MODEL_ALIAS,
    OPENROUTER_MODEL_CHOICES,
    OpenRouterSecurityProvider,
    _resolve,
)


class ResolveModelTests(unittest.TestCase):
    def test_default_alias_resolves_to_a_registered_choice(self):
        self.assertIn(DEFAULT_MODEL_ALIAS, OPENROUTER_MODEL_CHOICES)

    def test_known_alias_resolves_to_its_openrouter_model_id(self):
        expected = OPENROUTER_MODEL_CHOICES[DEFAULT_MODEL_ALIAS]
        self.assertEqual(_resolve(DEFAULT_MODEL_ALIAS), expected)

    def test_unknown_alias_passes_through_unchanged(self):
        # Lets callers pass any OpenRouter model id directly, not just the
        # curated free-tier aliases.
        model_id = "meta-llama/llama-3.1-8b-instruct"
        self.assertEqual(_resolve(model_id), model_id)


class MissingApiKeyTests(unittest.TestCase):
    def test_raises_without_openrouter_api_key_in_environment(self):
        with mock.patch.dict("os.environ", {}, clear=True), self.assertRaises(RuntimeError):
            OpenRouterSecurityProvider()


class GenerateTests(unittest.TestCase):
    def test_generate_posts_messages_and_parses_choice_content(self):
        response_body = json.dumps(
            {"choices": [{"message": {"content": "hello from openrouter"}}]}
        ).encode("utf-8")

        fake_response = mock.MagicMock()
        fake_response.read.return_value = response_body
        fake_response.__enter__.return_value = fake_response

        with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=True):
            provider = OpenRouterSecurityProvider()
            with mock.patch("urllib.request.urlopen", return_value=fake_response) as urlopen:
                result = provider._generate([{"role": "user", "content": "hi"}])

        self.assertEqual(result, "hello from openrouter")
        request = urlopen.call_args[0][0]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        sent_body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(sent_body["model"], OPENROUTER_MODEL_CHOICES[DEFAULT_MODEL_ALIAS])
        self.assertEqual(sent_body["messages"], [{"role": "user", "content": "hi"}])


if __name__ == "__main__":
    unittest.main()
