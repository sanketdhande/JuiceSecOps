from __future__ import annotations

import sys
import types
import unittest
from unittest import mock

from juicesecops.providers.base import RateLimitError
from juicesecops.providers.openrouter import DEFAULT_MODEL, OpenRouterSecurityProvider


class MissingApiKeyTests(unittest.TestCase):
    def test_raises_without_openrouter_api_key_in_environment(self):
        with mock.patch.dict("os.environ", {}, clear=True), self.assertRaises(RuntimeError):
            OpenRouterSecurityProvider()


class DefaultModelTests(unittest.TestCase):
    def test_default_model_is_llama_3_3_70b_instruct(self):
        self.assertEqual(DEFAULT_MODEL, "meta-llama/llama-3.3-70b-instruct")
        with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=True):
            self.assertEqual(OpenRouterSecurityProvider().model, DEFAULT_MODEL)


def _fake_response(content: str):
    message = types.SimpleNamespace(content=content)
    choice = types.SimpleNamespace(message=message)
    return types.SimpleNamespace(choices=[choice])


def _stub_openrouter_module(send_mock, client_factory=None):
    # OpenRouterSecurityProvider._load_client() does `from openrouter import
    # OpenRouter` lazily, so the real `openrouter` package (and its
    # httpx/pydantic dependencies) doesn't need to be installed to unit-test
    # the surrounding logic -- inject a stand-in module into sys.modules
    # instead.
    module = types.ModuleType("openrouter")

    class FakeOpenRouter:
        def __init__(self, api_key):
            self.api_key = api_key
            self.chat = types.SimpleNamespace(send=send_mock)

    module.OpenRouter = client_factory or FakeOpenRouter
    return module


class GenerateTests(unittest.TestCase):
    def test_generate_sends_expected_arguments_and_parses_choice_content(self):
        send_mock = mock.MagicMock(return_value=_fake_response("hello from openrouter"))
        stub = _stub_openrouter_module(send_mock)

        with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=True):
            provider = OpenRouterSecurityProvider()
            with mock.patch.dict(sys.modules, {"openrouter": stub}):
                result = provider._generate([{"role": "user", "content": "hi"}])

        self.assertEqual(result, "hello from openrouter")
        send_mock.assert_called_once_with(
            model=DEFAULT_MODEL,
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=256,
            temperature=0,
        )

    def test_generate_uses_explicit_max_tokens_override_when_given(self):
        # review_change() (via _prompted.py) passes its own larger budget
        # explicitly; confirm it reaches the SDK call instead of
        # self.max_new_tokens.
        send_mock = mock.MagicMock(return_value=_fake_response("hello from openrouter"))
        stub = _stub_openrouter_module(send_mock)

        with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=True):
            provider = OpenRouterSecurityProvider()
            with mock.patch.dict(sys.modules, {"openrouter": stub}):
                provider._generate([{"role": "user", "content": "hi"}], max_tokens=1536)

        send_mock.assert_called_once_with(
            model=DEFAULT_MODEL,
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=1536,
            temperature=0,
        )

    def test_client_is_constructed_once_and_cached_across_calls(self):
        send_mock = mock.MagicMock(return_value=_fake_response("hi"))
        client_factory = mock.MagicMock(side_effect=lambda api_key: mock.MagicMock(
            chat=types.SimpleNamespace(send=send_mock)
        ))
        stub = _stub_openrouter_module(send_mock, client_factory=client_factory)

        with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=True):
            provider = OpenRouterSecurityProvider()
            with mock.patch.dict(sys.modules, {"openrouter": stub}):
                provider._generate([{"role": "user", "content": "hi"}])
                provider._generate([{"role": "user", "content": "hi again"}])

        client_factory.assert_called_once_with(api_key="test-key")


class RateLimitTests(unittest.TestCase):
    def test_generate_raises_rate_limit_error_on_429_status_code(self):
        # Stands in for the SDK's TooManyRequestsResponseError, which the
        # SDK itself raises only after exhausting its own internal retries
        # (see the module docstring) -- any exception with status_code 429
        # reaching _generate() means the limit persisted.
        sdk_error = Exception("rate limited")
        sdk_error.status_code = 429
        send_mock = mock.MagicMock(side_effect=sdk_error)
        stub = _stub_openrouter_module(send_mock)

        with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=True):
            provider = OpenRouterSecurityProvider()
            with (
                mock.patch.dict(sys.modules, {"openrouter": stub}),
                self.assertRaises(RateLimitError),
            ):
                provider._generate([{"role": "user", "content": "hi"}])

    def test_generate_reraises_non_429_errors_unchanged(self):
        sdk_error = Exception("server exploded")
        sdk_error.status_code = 500
        send_mock = mock.MagicMock(side_effect=sdk_error)
        stub = _stub_openrouter_module(send_mock)

        with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=True):
            provider = OpenRouterSecurityProvider()
            with (
                mock.patch.dict(sys.modules, {"openrouter": stub}),
                self.assertRaises(Exception) as ctx,
            ):
                provider._generate([{"role": "user", "content": "hi"}])
        self.assertIs(ctx.exception, sdk_error)


if __name__ == "__main__":
    unittest.main()
