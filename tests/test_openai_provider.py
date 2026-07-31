from __future__ import annotations

import sys
import types
import unittest
from unittest import mock

from juicesecops.providers.base import RateLimitError
from juicesecops.providers.openai import DEFAULT_MODEL, OpenAISecurityProvider


class MissingApiKeyTests(unittest.TestCase):
    def test_raises_without_openai_api_key_in_environment(self):
        with mock.patch.dict("os.environ", {}, clear=True), self.assertRaises(RuntimeError):
            OpenAISecurityProvider()


class DefaultModelTests(unittest.TestCase):
    def test_default_model_is_gpt_5_6_luna(self):
        self.assertEqual(DEFAULT_MODEL, "gpt-5.6-luna")
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            self.assertEqual(OpenAISecurityProvider().model, DEFAULT_MODEL)


def _fake_response(content: str):
    return types.SimpleNamespace(output_text=content)


def _fake_response_from_output(content: str):
    output_text = types.SimpleNamespace(type="output_text", text=content)
    output_message = types.SimpleNamespace(content=[output_text])
    return types.SimpleNamespace(output_text=None, output=[output_message])


def _stub_openai_module(create_mock, client_factory=None):
    # OpenAISecurityProvider._load_client() does `from openai import OpenAI`
    # lazily, so the real `openai` package doesn't need to be installed to
    # unit-test the surrounding logic -- inject a stand-in module into
    # sys.modules instead.
    module = types.ModuleType("openai")

    class FakeOpenAI:
        def __init__(self, api_key):
            self.api_key = api_key
            self.responses = types.SimpleNamespace(create=create_mock)

    module.OpenAI = client_factory or FakeOpenAI
    return module


class GenerateTests(unittest.TestCase):
    def test_generate_sends_expected_arguments_and_returns_output_text(self):
        create_mock = mock.MagicMock(return_value=_fake_response("hello from openai"))
        stub = _stub_openai_module(create_mock)

        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            provider = OpenAISecurityProvider()
            with mock.patch.dict(sys.modules, {"openai": stub}):
                result = provider._generate([{"role": "user", "content": "hi"}])

        self.assertEqual(result, "hello from openai")
        create_mock.assert_called_once_with(
            model=DEFAULT_MODEL,
            input=[{"role": "user", "content": "hi"}],
            max_output_tokens=256,
            store=False,
            text={"format": {"type": "json_object"}},
        )

    def test_generate_falls_back_to_output_items_when_output_text_is_missing(self):
        create_mock = mock.MagicMock(return_value=_fake_response_from_output("fallback text"))
        stub = _stub_openai_module(create_mock)

        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            provider = OpenAISecurityProvider()
            with mock.patch.dict(sys.modules, {"openai": stub}):
                result = provider._generate([{"role": "user", "content": "hi"}])

        self.assertEqual(result, "fallback text")

    def test_generate_uses_explicit_max_tokens_override_when_given(self):
        create_mock = mock.MagicMock(return_value=_fake_response("hello from openai"))
        stub = _stub_openai_module(create_mock)

        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            provider = OpenAISecurityProvider()
            with mock.patch.dict(sys.modules, {"openai": stub}):
                provider._generate([{"role": "user", "content": "hi"}], max_tokens=1536)

        create_mock.assert_called_once_with(
            model=DEFAULT_MODEL,
            input=[{"role": "user", "content": "hi"}],
            max_output_tokens=1536,
            store=False,
            text={"format": {"type": "json_object"}},
        )

    def test_client_is_constructed_once_and_cached_across_calls(self):
        create_mock = mock.MagicMock(return_value=_fake_response("hi"))
        client_factory = mock.MagicMock(
            side_effect=lambda api_key: mock.MagicMock(
                responses=types.SimpleNamespace(create=create_mock)
            )
        )
        stub = _stub_openai_module(create_mock, client_factory=client_factory)

        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            provider = OpenAISecurityProvider()
            with mock.patch.dict(sys.modules, {"openai": stub}):
                provider._generate([{"role": "user", "content": "hi"}])
                provider._generate([{"role": "user", "content": "hi again"}])

        client_factory.assert_called_once_with(api_key="test-key")


class RateLimitTests(unittest.TestCase):
    def test_generate_raises_rate_limit_error_on_429_status_code(self):
        sdk_error = Exception("rate limited")
        sdk_error.status_code = 429
        create_mock = mock.MagicMock(side_effect=sdk_error)
        stub = _stub_openai_module(create_mock)

        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            provider = OpenAISecurityProvider()
            with (
                mock.patch.dict(sys.modules, {"openai": stub}),
                self.assertRaises(RateLimitError),
            ):
                provider._generate([{"role": "user", "content": "hi"}])

    def test_generate_reraises_non_429_errors_unchanged(self):
        sdk_error = Exception("server exploded")
        sdk_error.status_code = 500
        create_mock = mock.MagicMock(side_effect=sdk_error)
        stub = _stub_openai_module(create_mock)

        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            provider = OpenAISecurityProvider()
            with (
                mock.patch.dict(sys.modules, {"openai": stub}),
                self.assertRaises(Exception) as ctx,
            ):
                provider._generate([{"role": "user", "content": "hi"}])

        self.assertIs(ctx.exception, sdk_error)


if __name__ == "__main__":
    unittest.main()
