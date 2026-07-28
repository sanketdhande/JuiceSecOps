from __future__ import annotations

import sys
import types
import unittest
from unittest import mock

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


if __name__ == "__main__":
    unittest.main()
