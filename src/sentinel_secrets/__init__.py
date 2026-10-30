"""sentinel-secrets: a passive scanner for secrets leaked into a git repository."""

from importlib.metadata import version

# Read from the installed package's metadata, which comes from
# pyproject.toml, so the version only has to be changed in one place.
__version__ = version("sentinel-secrets")
