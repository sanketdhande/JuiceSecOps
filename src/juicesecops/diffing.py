from __future__ import annotations

# Step 2 of the pipeline (see pipeline.py): turns a git diff of --target-repo
# into the list of CodeChange objects that get handed to
# provider.review_change() -- this is what feeds the LLM/heuristic
# change-review stage. If this returns [], the LLM stage has nothing to look
# at and produces zero "llm-diff" findings.
import subprocess
from pathlib import Path

from .models import CodeChange
from .policy import Policy


def _run_git(repo_path: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _match_priority(path: str, policy: Policy) -> int | None:
    """Rank a path by how it matched policy scope.

    Explicit ``include_paths`` entries are ranked ahead of generic
    ``include_extensions`` matches, in the order they are declared, so that a
    file budget (``max_changed_files``) is spent on the security-relevant
    directories operators called out by name (e.g. ``routes/``, ``lib/``)
    before it is spent on incidental matches like stray ``.md`` files that
    happen to share an allowed extension.
    """
    for index, prefix in enumerate(policy.include_paths):
        if path == prefix or path.startswith(prefix):
            return index
    suffix = Path(path).suffix
    if suffix and suffix in policy.include_extensions:
        return len(policy.include_paths)
    return None


def collect_changes(
    repo_path: str | Path,
    policy: Policy,
    base_ref: str | None = None,
    head_ref: str = "HEAD",
) -> list[CodeChange]:
    repo = Path(repo_path)
    # base_ref=None means "diff the working tree against HEAD". A freshly
    # cloned repo (as in CI) has no uncommitted edits, so that diff is always
    # empty. The CI workflow / pipeline scripts instead pass base_ref = git's
    # empty-tree object hash, which makes every tracked file show up as
    # "added" -- i.e. a one-time baseline review of the whole checkout.
    diff_target = [head_ref, "--"] if base_ref is None else [base_ref, head_ref, "--"]
    name_status = _run_git(repo, ["diff", "--name-status", *diff_target])

    # Rank every changed/added file by _match_priority before touching git
    # again, then only diff the top max_changed_files -- keeps this cheap
    # even when "everything" is in scope (empty-tree baseline scan).
    candidates: list[tuple[int, int, str, str]] = []
    for order, line in enumerate(name_status.splitlines()):
        if not line.strip():
            continue
        parts = line.split("\t", maxsplit=1)
        if len(parts) != 2:
            continue
        status, path = parts
        priority = _match_priority(path, policy)
        if priority is None:
            continue
        candidates.append((priority, order, status, path))
    candidates.sort(key=lambda item: (item[0], item[1]))

    changes: list[CodeChange] = []
    for _priority, _order, status, path in candidates[: policy.max_changed_files]:
        diff_args = ["diff", "--unified=3", *diff_target, "--", path]
        diff = _run_git(repo, diff_args).strip()
        if not diff:
            continue
        snippet = ""
        if status != "D":
            try:
                if base_ref is None:
                    snippet = (repo / path).read_text(encoding="utf-8", errors="ignore")
                else:
                    snippet = _run_git(repo, ["show", f"{head_ref}:{path}"])
            except (OSError, subprocess.CalledProcessError):
                snippet = ""
        changes.append(
            CodeChange(
                path=path,
                status=status,
                diff=diff[: policy.max_diff_chars],
                snippet=snippet[: policy.max_snippet_chars],
            )
        )
    return changes
