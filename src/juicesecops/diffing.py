from __future__ import annotations

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
    diff_target = [head_ref, "--"] if base_ref is None else [base_ref, head_ref, "--"]
    name_status = _run_git(repo, ["diff", "--name-status", *diff_target])

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
