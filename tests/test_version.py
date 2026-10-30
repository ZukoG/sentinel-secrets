import tomllib
from pathlib import Path

import sentinel_secrets

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_package_version_matches_pyproject() -> None:
    with PYPROJECT.open("rb") as file:
        expected = tomllib.load(file)["project"]["version"]

    assert sentinel_secrets.__version__ == expected
