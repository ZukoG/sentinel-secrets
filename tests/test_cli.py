import json
import shutil
import subprocess

import pytest

from sentinel_secrets.cli import main
from sentinel_secrets.git_walker import walk_working_tree, walk_history
from sentinel_secrets.baseline import fingerprint, save_baseline


def _run_git(repo, *args):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _git_available():
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(
    not _git_available(),
    reason="git is not installed",
)


@pytest.fixture
def repo_with_secrets(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _run_git(repo, "init")
    _run_git(repo, "config", "user.name", "Test User")
    _run_git(repo, "config", "user.email", "test@example.com")

    config_file = repo / "config.txt"
    config_file.write_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n",
        encoding="utf-8",
    )

    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "Add AWS secret")

    github_file = repo / "github.txt"
    github_file.write_text(
        "token=ghp_" + "a" * 36 + "\n",
        encoding="utf-8",
    )

    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "Add GitHub token")

    github_file.unlink()

    _run_git(repo, "add", "-u")
    _run_git(repo, "commit", "-m", "Remove GitHub token")

    return str(repo)


@pytest.fixture
def clean_repo(tmp_path):
    repo = tmp_path / "clean_repo"
    repo.mkdir()

    _run_git(repo, "init")
    _run_git(repo, "config", "user.name", "Test User")
    _run_git(repo, "config", "user.email", "test@example.com")

    clean_file = repo / "README.txt"
    clean_file.write_text(
        "This repository contains no secrets.\n",
        encoding="utf-8",
    )

    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "Initial clean commit")

    return str(repo)


def test_main_returns_1_when_findings_exist(repo_with_secrets):
    assert main([repo_with_secrets]) == 1


def test_main_returns_0_for_clean_repo(clean_repo):
    assert main([clean_repo]) == 0


def test_main_json_output(repo_with_secrets, capsys):
    assert main([repo_with_secrets, "--output", "json"]) == 1

    output = capsys.readouterr().out
    data = json.loads(output)

    assert data
    assert isinstance(data, list)


def test_no_history_skips_history_findings(repo_with_secrets, capsys):
    main([repo_with_secrets, "--no-history"])

    output_without_history = capsys.readouterr().out

    assert "AWS Access Key ID" in output_without_history
    assert "GitHub Token" not in output_without_history

    main([repo_with_secrets])

    output_with_history = capsys.readouterr().out

    assert "AWS Access Key ID" in output_with_history
    assert "GitHub Token" in output_with_history


def test_baseline_suppresses_findings(repo_with_secrets, tmp_path):
    findings = walk_working_tree(repo_with_secrets)
    findings += walk_history(repo_with_secrets)

    fingerprints = {
        fingerprint(finding)
        for finding in findings
    }

    baseline_path = tmp_path / "baseline.json"
    save_baseline(str(baseline_path), fingerprints)

    assert main(
        [
            repo_with_secrets,
            "--baseline",
            str(baseline_path),
        ]
    ) == 0


def test_history_and_no_history_are_mutually_exclusive(
    repo_with_secrets,
):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                repo_with_secrets,
                "--history",
                "--no-history",
            ]
        )

    assert exc.value.code == 2