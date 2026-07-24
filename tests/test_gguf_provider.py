from __future__ import annotations

import unittest

from juicesecops.providers.gguf import (
    DEFAULT_MODEL_ALIAS,
    GGUF_MODEL_CHOICES,
    _fold_system_into_user,
    _resolve,
)


class FoldSystemIntoUserTests(unittest.TestCase):
    def test_folds_leading_system_message_into_first_user_turn(self):
        # Regression test: some GGUF chat templates (Gemma's in particular)
        # hard-reject a leading "system" role with
        # ValueError: System role not supported. _generate() must never
        # send a bare system-first message list to create_chat_completion.
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


class ResolveModelTests(unittest.TestCase):
    def test_default_alias_resolves_to_a_registered_choice(self):
        self.assertIn(DEFAULT_MODEL_ALIAS, GGUF_MODEL_CHOICES)
        repo_id, filename = _resolve(DEFAULT_MODEL_ALIAS)
        self.assertTrue(repo_id)
        self.assertTrue(filename)

    def test_explicit_repo_filename_string_bypasses_the_alias_table(self):
        repo_id, filename = _resolve("some/repo:*.gguf")
        self.assertEqual(repo_id, "some/repo")
        self.assertEqual(filename, "*.gguf")

    def test_unknown_alias_without_colon_raises(self):
        with self.assertRaises(ValueError):
            _resolve("not-a-known-alias")


if __name__ == "__main__":
    unittest.main()
