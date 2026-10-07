import shutil
import subprocess

import pytest

from sentinel_secrets.git_walker import walk_working_tree, walk_history

pytestmark = pytest.mark.skipif(
    shutil.which('git') is None,
    reason='git is not available on PATH',
)

def _run_git(*args: str, cwd: str) -> None:
    subprocess.run(
        ['git', '-C', cwd, *args],
        check=True,
        capture_output=True,
        text=True,
    )

@pytest.fixture
def git_repo(tmp_path) -> str:
    repo = str(tmp_path)

    _run_git("init", cwd=repo)

    _run_git(
        "config",
        "user.email",
        "test@example.com",
        cwd=repo,
    )

    _run_git(
        "config",
        "user.name",
        "Test User",
        cwd=repo,
    )

    # First commit: clean file, current secret, and binary file.
    (tmp_path / "clean.py").write_text(
        "print('Hello, world!')\n",
        encoding="utf-8",
    )

    (tmp_path / "current_secret.py").write_text(
        "aws_key = AKIAIOSFODNN7PUEXAMPLE\n",
        encoding="utf-8",
    )

    (tmp_path / "image.png").write_bytes(
        b"\x89PNG\xff\xfe\x00\x01broken bytes here"
    )

    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "Initial commit", cwd=repo)

    # Second commit: add a secret that will later be removed.
    (tmp_path / "removed_secret.py").write_text(
        "token = ghp_" + "a" * 36 + "\n",
        encoding="utf-8",
    )

    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "Add temporary secret", cwd=repo)

    # Third commit: remove the GitHub token.
    (tmp_path / "removed_secret.py").unlink()

    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "Remove temporary secret", cwd=repo)

    return repo


def test_working_tree_finds_current_secret(git_repo: str) -> None:
    findings = walk_working_tree(git_repo)

    assert len(findings) == 1
    assert findings[0].source == "current_secret.py"
    assert findings[0].rule_name == "AWS Access Key ID"


def test_working_tree_skips_binary_file(git_repo: str) -> None:
    findings = walk_working_tree(git_repo)

    assert all(finding.source != "image.png" for finding in findings)


def test_history_finds_removed_github_token(git_repo: str) -> None:
    findings = walk_history(git_repo)

    assert any(
        finding.rule_name == "GitHub Token"
        for finding in findings
    )


def test_history_finds_aws_key(git_repo: str) -> None:
    findings = walk_history(git_repo)

    assert any(
        finding.rule_name == "AWS Access Key ID"
        for finding in findings
    )


def test_history_sources_are_commit_references(git_repo: str) -> None:
    findings = walk_history(git_repo)

    assert findings
    assert all(
        finding.source.startswith("commit ")
        for finding in findings
    )


def _init_repo(path) -> str:
    path.mkdir()
    repo = str(path)

    _run_git("init", cwd=repo)
    _run_git("config", "user.email", "test@example.com", cwd=repo)
    _run_git("config", "user.name", "Test User", cwd=repo)

    return repo


def test_scanned_repo_config_cannot_run_commands(tmp_path) -> None:
    repo_path = tmp_path / "repo"
    repo = _init_repo(repo_path)
    marker = tmp_path / "marker"

    (repo_path / ".gitattributes").write_text(
        "*.txt diff=probe\n",
        encoding="utf-8",
    )
    (repo_path / "a.txt").write_text("one\n", encoding="utf-8")
    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "one", cwd=repo)

    (repo_path / "a.txt").write_text("one\ntwo\n", encoding="utf-8")
    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "two", cwd=repo)

    # Hostile config goes in last, so the setup commands above can't trigger it.
    touch = f"touch \"{marker.as_posix()}\""
    _run_git(
        "config",
        "diff.probe.textconv",
        f"sh -c '{touch}; cat \"$1\"' --",
        cwd=repo,
    )
    _run_git("config", "core.fsmonitor", f"sh -c '{touch}' --", cwd=repo)

    walk_working_tree(repo)
    walk_history(repo)

    assert not marker.exists()


def test_history_survives_non_utf8_and_non_ascii_text(tmp_path) -> None:
    repo_path = tmp_path / "repo"
    repo = _init_repo(repo_path)

    # UTF-8 "Á" breaks cp1252 decoding (Windows); a bare Latin-1 byte
    # breaks strict UTF-8 decoding (Linux).
    (repo_path / "names.py").write_bytes(
        'name = "Álvaro"\n'.encode("utf-8")
        + b"city = caf\xe9\n"
        + b"aws_key = AKIAIOSFODNN7EXAMPLE\n"
    )
    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "add names", cwd=repo)

    findings = walk_history(repo)

    assert any(
        finding.rule_name == "AWS Access Key ID"
        for finding in findings
    )


def test_working_tree_scans_files_with_non_ascii_names(tmp_path) -> None:
    repo_path = tmp_path / "repo"
    repo = _init_repo(repo_path)

    (repo_path / "café.py").write_text(
        "aws_key = AKIAIOSFODNN7EXAMPLE\n",
        encoding="utf-8",
    )
    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "add file", cwd=repo)

    findings = walk_working_tree(repo)

    assert [finding.source for finding in findings] == ["café.py"]


def test_working_tree_scans_text_that_is_not_utf8(tmp_path) -> None:
    repo_path = tmp_path / "repo"
    repo = _init_repo(repo_path)

    (repo_path / "app.properties").write_bytes(
        b"greeting=caf\xe9\n"
        b"aws_key=AKIAIOSFODNN7EXAMPLE\n"
    )
    _run_git("add", "-A", cwd=repo)
    _run_git("commit", "-m", "add properties", cwd=repo)

    findings = walk_working_tree(repo)

    assert [finding.source for finding in findings] == ["app.properties"]
