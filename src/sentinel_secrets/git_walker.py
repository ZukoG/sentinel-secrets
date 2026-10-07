import subprocess
from pathlib import Path

from .scanner import Finding, scan_content

def walk_working_tree(repo_path: str) -> list[Finding]:
    result = subprocess.run(
         [
            "git",
            # The scanned repo's own config must not be able to run commands.
            "-c",
            "core.fsmonitor=false",
            "-C",
            repo_path,
            "ls-files",
            # NUL-separated raw paths; the default output escapes non-ASCII names.
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
         capture_output=True,
         encoding="utf-8",
         errors="replace",
         check=True,
    )

    findings: list[Finding] = []

    for relative_path in result.stdout.split("\0"):
        if not relative_path:
            continue

        file_path = Path(repo_path) / relative_path

        try:
            raw = file_path.read_bytes()
        except OSError:
            continue

        # Same rule git uses: a NUL byte near the start means binary. Anything
        # else is text, even if it isn't valid UTF-8 (e.g. Latin-1 .properties).
        if b"\0" in raw[:8000]:
            continue

        content = raw.decode("utf-8", errors="replace")

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
            # The scanned repo's own config must not be able to run commands.
            "-c",
            "core.fsmonitor=false",
            "-C",
            repo_path,
            "log",
            "-p",
            "--all",
            "--no-textconv",
            "--no-ext-diff",
        ],
        capture_output=True,
        # Git output is UTF-8; the platform default (cp1252 on Windows) isn't.
        encoding="utf-8",
        errors="replace",
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
