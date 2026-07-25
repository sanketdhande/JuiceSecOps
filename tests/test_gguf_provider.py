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
    def test_alias_table_is_intentionally_empty(self):
        # Every previous alias (foundation-sec-8b-reasoning,
        # foundation-sec-8b, qwen-coder-7b, codegemma-7b) was removed on
        # 2026-07-25 after all four hit the CI job's 120-minute timeout in
        # both openweight comparison workflows -- see the module-level
        # comment above GGUF_MODEL_CHOICES. Re-add this assertion's
        # counterpart once a working alias exists again.
        self.assertEqual(GGUF_MODEL_CHOICES, {})

    def test_default_alias_no_longer_resolves(self):
        # DEFAULT_MODEL_ALIAS is left dangling on purpose while the table
        # is empty, so --provider gguf with no --model-id fails fast and
        # explicitly rather than silently picking a model known to time
        # out.
        with self.assertRaises(ValueError):
            _resolve(DEFAULT_MODEL_ALIAS)

    def test_explicit_repo_filename_string_bypasses_the_alias_table(self):
        repo_id, filename = _resolve("some/repo:*.gguf")
        self.assertEqual(repo_id, "some/repo")
        self.assertEqual(filename, "*.gguf")

    def test_unknown_alias_without_colon_raises(self):
        with self.assertRaises(ValueError):
            _resolve("not-a-known-alias")


if __name__ == "__main__":
    unittest.main()
