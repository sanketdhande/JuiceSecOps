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


def _is_relevant(path: str, policy: Policy) -> bool:
    suffix = Path(path).suffix
    if suffix and suffix in policy.include_extensions:
        return True
    return any(path == prefix or path.startswith(prefix) for prefix in policy.include_paths)


def collect_changes(
    repo_path: str | Path,
    policy: Policy,
    base_ref: str | None = None,
    head_ref: str = "HEAD",
) -> list[CodeChange]:
    repo = Path(repo_path)
    diff_target = [head_ref, "--"] if base_ref is None else [base_ref, head_ref, "--"]
    name_status = _run_git(repo, ["diff", "--name-status", *diff_target])
    changes: list[CodeChange] = []
    for line in name_status.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", maxsplit=1)
        if len(parts) != 2:
            continue
        status, path = parts
        if not _is_relevant(path, policy):
            continue
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
        if len(changes) >= policy.max_changed_files:
            break
    return changes
