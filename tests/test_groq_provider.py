from __future__ import annotations

import json
import unittest
import urllib.error
from unittest import mock

from juicesecops.providers.base import RateLimitError
from juicesecops.providers.groq import DEFAULT_MODEL, MAX_RETRIES, USER_AGENT, GroqSecurityProvider


class MissingApiKeyTests(unittest.TestCase):
    def test_raises_without_groq_api_key_in_environment(self):
        with mock.patch.dict("os.environ", {}, clear=True), self.assertRaises(RuntimeError):
            GroqSecurityProvider()


class DefaultModelTests(unittest.TestCase):
    def test_default_model_is_gpt_oss_20b(self):
        self.assertEqual(DEFAULT_MODEL, "openai/gpt-oss-20b")
        with mock.patch.dict("os.environ", {"GROQ_API_KEY": "test-key"}, clear=True):
            self.assertEqual(GroqSecurityProvider().model, DEFAULT_MODEL)


class GenerateTests(unittest.TestCase):
    def test_generate_posts_messages_and_parses_choice_content(self):
        response_body = json.dumps(
            {"choices": [{"message": {"content": "hello from groq"}}]}
        ).encode("utf-8")

        fake_response = mock.MagicMock()
        fake_response.read.return_value = response_body
        fake_response.__enter__.return_value = fake_response

        with mock.patch.dict("os.environ", {"GROQ_API_KEY": "test-key"}, clear=True):
            provider = GroqSecurityProvider()
            with mock.patch("urllib.request.urlopen", return_value=fake_response) as urlopen:
                result = provider._generate([{"role": "user", "content": "hi"}])

        self.assertEqual(result, "hello from groq")
        request = urlopen.call_args[0][0]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(request.get_header("User-agent"), USER_AGENT)
        self.assertEqual(request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        sent_body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(sent_body["model"], DEFAULT_MODEL)
        self.assertEqual(sent_body["messages"], [{"role": "user", "content": "hi"}])
        self.assertIn("max_completion_tokens", sent_body)

    def test_generate_uses_explicit_max_tokens_override_when_given(self):
        # review_change() (via _prompted.py) passes its own larger budget
        # explicitly; confirm it reaches the request body as
        # max_completion_tokens instead of self.max_new_tokens.
        response_body = json.dumps(
            {"choices": [{"message": {"content": "hello from groq"}}]}
        ).encode("utf-8")
        fake_response = mock.MagicMock()
        fake_response.read.return_value = response_body
        fake_response.__enter__.return_value = fake_response

        with mock.patch.dict("os.environ", {"GROQ_API_KEY": "test-key"}, clear=True):
            provider = GroqSecurityProvider()
            with mock.patch("urllib.request.urlopen", return_value=fake_response) as urlopen:
                provider._generate([{"role": "user", "content": "hi"}], max_tokens=1536)

        request = urlopen.call_args[0][0]
        sent_body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(sent_body["max_completion_tokens"], 1536)

    def test_generate_sends_a_non_default_user_agent(self):
        # Regression test: Groq's API sits behind Cloudflare, which rejects
        # urllib.request's default "Python-urllib/x.y" User-Agent with a 403
        # ("error code: 1010") before the request reaches Groq at all.
        self.assertNotIn("python-urllib", USER_AGENT.lower())


def _http_error_429(retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = mock.MagicMock()
    headers.get.return_value = retry_after
    error = urllib.error.HTTPError(
        url="https://api.groq.com/openai/v1/chat/completions",
        code=429,
        msg="Too Many Requests",
        hdrs=headers,
        fp=mock.MagicMock(read=lambda: b'{"error": "rate limited"}'),
    )
    error.headers = headers
    return error


class RetryTests(unittest.TestCase):
    def test_retries_on_429_then_succeeds(self):
        response_body = json.dumps(
            {"choices": [{"message": {"content": "recovered"}}]}
        ).encode("utf-8")
        fake_response = mock.MagicMock()
        fake_response.read.return_value = response_body
        fake_response.__enter__.return_value = fake_response

        with mock.patch.dict("os.environ", {"GROQ_API_KEY": "test-key"}, clear=True):
            provider = GroqSecurityProvider()
            with (
                mock.patch(
                    "urllib.request.urlopen",
                    side_effect=[_http_error_429("0"), fake_response],
                ),
                mock.patch("time.sleep") as sleep,
            ):
                result = provider._generate([{"role": "user", "content": "hi"}])

        self.assertEqual(result, "recovered")
        sleep.assert_called_once_with(0.0)

    def test_raises_rate_limit_error_after_exhausting_retries_on_429(self):
        with mock.patch.dict("os.environ", {"GROQ_API_KEY": "test-key"}, clear=True):
            provider = GroqSecurityProvider()
            with (
                mock.patch(
                    "urllib.request.urlopen",
                    side_effect=[_http_error_429("0") for _ in range(MAX_RETRIES + 1)],
                ),
                mock.patch("time.sleep"),
                self.assertRaises(RateLimitError),
            ):
                provider._generate([{"role": "user", "content": "hi"}])

    def test_does_not_retry_on_non_429_error(self):
        headers = mock.MagicMock()
        error = urllib.error.HTTPError(
            url="https://api.groq.com/openai/v1/chat/completions",
            code=500,
            msg="Internal Server Error",
            hdrs=headers,
            fp=mock.MagicMock(read=lambda: b"boom"),
        )
        with mock.patch.dict("os.environ", {"GROQ_API_KEY": "test-key"}, clear=True):
            provider = GroqSecurityProvider()
            with (
                mock.patch("urllib.request.urlopen", side_effect=error) as urlopen,
                mock.patch("time.sleep") as sleep,
                self.assertRaises(RuntimeError) as ctx,
            ):
                provider._generate([{"role": "user", "content": "hi"}])
        self.assertNotIsInstance(ctx.exception, RateLimitError)
        urlopen.assert_called_once()
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
