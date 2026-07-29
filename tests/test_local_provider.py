from __future__ import annotations

import sys
import types
import unittest
from unittest import mock

from juicesecops.providers.local import (
    DEFAULT_FILENAME,
    DEFAULT_MODEL,
    DEFAULT_REPO_ID,
    LocalSecurityProvider,
    _fold_system_into_user,
    _resolve,
)


class ResolveModelTests(unittest.TestCase):
    def test_default_model_resolves_to_default_repo_and_filename(self):
        repo_id, filename = _resolve(DEFAULT_MODEL)
        self.assertEqual(repo_id, DEFAULT_REPO_ID)
        self.assertEqual(filename, DEFAULT_FILENAME)

    def test_explicit_repo_filename_string_is_accepted(self):
        repo_id, filename = _resolve("some/repo:*.gguf")
        self.assertEqual(repo_id, "some/repo")
        self.assertEqual(filename, "*.gguf")

    def test_missing_colon_raises(self):
        with self.assertRaises(ValueError):
            _resolve("not-a-valid-model-id")

    def test_missing_filename_after_colon_raises(self):
        with self.assertRaises(ValueError):
            _resolve("some/repo:")


class FoldSystemIntoUserTests(unittest.TestCase):
    def test_folds_leading_system_message_into_first_user_turn(self):
        # Regression test: some GGUF chat templates (Gemma's in particular)
        # hard-reject a leading "system" role with
        # ValueError: System role not supported.
        messages = [
            {"role": "system", "content": "You are a security triage model."},
            {"role": "user", "content": "Assess this finding."},
        ]
        folded = _fold_system_into_user(messages)
        self.assertEqual(len(folded), 1)
        self.assertEqual(folded[0]["role"], "user")
        self.assertIn("You are a security triage model.", folded[0]["content"])
        self.assertIn("Assess this finding.", folded[0]["content"])

    def test_leaves_messages_without_leading_system_role_unchanged(self):
        messages = [{"role": "user", "content": "hello"}]
        self.assertEqual(_fold_system_into_user(messages), messages)

    def test_preserves_messages_after_the_folded_pair(self):
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "turn 1"},
            {"role": "assistant", "content": "reply"},
        ]
        folded = _fold_system_into_user(messages)
        self.assertEqual(len(folded), 2)
        self.assertEqual(folded[1], {"role": "assistant", "content": "reply"})


def _stub_llama_cpp_module(create_chat_completion_mock, from_pretrained_mock=None):
    # LocalSecurityProvider._load_llm() does `from llama_cpp import Llama`
    # lazily, so the real `llama_cpp` package (a compiled C++ extension)
    # doesn't need to be installed to unit-test the surrounding logic --
    # inject a stand-in module into sys.modules instead.
    module = types.ModuleType("llama_cpp")

    class FakeLlama:
        @classmethod
        def from_pretrained(cls, **kwargs):
            if from_pretrained_mock is not None:
                from_pretrained_mock(**kwargs)
            instance = mock.MagicMock()
            instance.create_chat_completion = create_chat_completion_mock
            return instance

    module.Llama = FakeLlama
    return module


class GenerateTests(unittest.TestCase):
    def test_generate_downloads_default_gguf_and_parses_choice_content(self):
        create_mock = mock.MagicMock(
            return_value={"choices": [{"message": {"content": "hello from local"}}]}
        )
        from_pretrained_mock = mock.MagicMock()
        stub = _stub_llama_cpp_module(create_mock, from_pretrained_mock)

        provider = LocalSecurityProvider()
        with mock.patch.dict(sys.modules, {"llama_cpp": stub}):
            result = provider._generate([{"role": "user", "content": "hi"}])

        self.assertEqual(result, "hello from local")
        from_pretrained_mock.assert_called_once_with(
            repo_id=DEFAULT_REPO_ID,
            filename=DEFAULT_FILENAME,
            n_ctx=4096,
            n_threads=mock.ANY,
            verbose=False,
        )
        create_mock.assert_called_once_with(
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=256,
            temperature=0,
        )

    def test_generate_uses_explicit_max_tokens_override_when_given(self):
        create_mock = mock.MagicMock(
            return_value={"choices": [{"message": {"content": "hello from local"}}]}
        )
        stub = _stub_llama_cpp_module(create_mock)

        provider = LocalSecurityProvider()
        with mock.patch.dict(sys.modules, {"llama_cpp": stub}):
            provider._generate([{"role": "user", "content": "hi"}], max_tokens=1536)

        create_mock.assert_called_once_with(
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=1536,
            temperature=0,
        )

    def test_folds_system_message_before_sending(self):
        create_mock = mock.MagicMock(return_value={"choices": [{"message": {"content": "ok"}}]})
        stub = _stub_llama_cpp_module(create_mock)

        provider = LocalSecurityProvider()
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "turn"},
        ]
        with mock.patch.dict(sys.modules, {"llama_cpp": stub}):
            provider._generate(messages)

        sent_messages = create_mock.call_args.kwargs["messages"]
        self.assertEqual(len(sent_messages), 1)
        self.assertEqual(sent_messages[0]["role"], "user")

    def test_llm_is_constructed_once_and_cached_across_calls(self):
        create_mock = mock.MagicMock(return_value={"choices": [{"message": {"content": "ok"}}]})
        from_pretrained_mock = mock.MagicMock()
        stub = _stub_llama_cpp_module(create_mock, from_pretrained_mock)

        provider = LocalSecurityProvider()
        with mock.patch.dict(sys.modules, {"llama_cpp": stub}):
            provider._generate([{"role": "user", "content": "hi"}])
            provider._generate([{"role": "user", "content": "hi again"}])

        from_pretrained_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
