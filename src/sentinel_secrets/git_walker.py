import subprocess
from pathlib import Path

from .scanner import Finding, scan_content

def walk_working_tree(repo_path: str) -> list[Finding]:
    result = subprocess.run(
         [
            "git",
            "-C",
            repo_path,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
         capture_output=True,
         text=True,
         check=True,
    )

    findings: list[Finding] = []

    for relative_path in result.stdout.splitlines():
        file_path = Path(repo_path) / relative_path

        try:
            content = file_path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            continue

        findings.extend(
            scan_content(
                content,
                source=relative_path
            )
        )

    return findings



def walk_history(repo_path: str) -> list[Finding]:
    result = subprocess.run(
        [
            "git",
            "-C",
            repo_path,
            "log",
            "-p",
            "--all",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    findings: list[Finding] = []
    current_commit: str | None = None
    added_lines: list[str] = []

    def flush_commit() -> None:
        nonlocal added_lines

        if current_commit is None or not added_lines:
            added_lines = []
            return

        content = "\n".join(added_lines)

        findings.extend(
            scan_content(
                content,
                source=f'commit {current_commit}'
            )
        )

        added_lines = []

    for line in result.stdout.splitlines():
        if line.startswith('commit '):
            flush_commit()

            commit_hash = line.split()[1]
            current_commit = commit_hash[:8]

        elif line.startswith('+') and not line.startswith('+++'):
            added_lines.append(line[1:])

    flush_commit()

    return findings
