# Changelog

All notable changes to sentinel-secrets are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-30

### Added

- A signature for Stripe live secret keys (`sk_live_`) and restricted
  keys (`rk_live_`), at HIGH severity. Test-mode keys are not reported,
  since they cannot touch real payments
  ([#43](https://github.com/ZukoG/sentinel-secrets/issues/43)).
- `SECURITY.md`: a security policy covering supported versions, how to
  report a vulnerability privately through GitHub's reporting form, and
  what counts as a vulnerability in this tool
  ([#39](https://github.com/ZukoG/sentinel-secrets/issues/39)).
- Dependabot configuration: weekly pull requests when the GitHub Actions
  in CI or the Python dev tools (pytest, bandit, pip-audit) fall behind
  ([#37](https://github.com/ZukoG/sentinel-secrets/issues/37)).
- Links to the security policy and this changelog from the README
  ([#45](https://github.com/ZukoG/sentinel-secrets/issues/45)).

### Fixed

- `sentinel_secrets.__version__` reported 0.1.0 instead of the real
  version. It is now read from the package metadata, so it always matches
  `pyproject.toml`
  ([#46](https://github.com/ZukoG/sentinel-secrets/issues/46)).

## [1.0.1] - 2026-10-19

### Added

- Step-by-step setup in the README for Windows, macOS, and Linux, from
  opening a terminal and installing Python and Git to running a first
  scan.
- A "Reading the results" section explaining each column of the report
  and what to do if a real secret turns up.
- Troubleshooting for common setup problems: Python or Git not found,
  PowerShell blocking scripts, an inactive virtual environment, and older
  Python versions.
- A clickable table of contents in the README.
- A CI job that runs the README's setup commands as written on Windows,
  macOS, and Linux on every change.

### Fixed

- Console report columns now widen to fit long rule names and file paths
  instead of pushing the rest of the row out of line
  ([#32](https://github.com/ZukoG/sentinel-secrets/issues/32)).

Detection behaviour is unchanged from 1.0.0.

## [1.0.0] - 2026-10-07

First release: a passive command-line scanner for secrets committed to a
git repository, in both its current files and its full commit history.

### Added

- Signatures for AWS access key IDs, GitHub tokens, Slack tokens, private
  key headers, and quoted or unquoted secret assignments (`api_key`,
  `secret`, `token`, `password`).
- Shannon entropy detection for unlabeled high-entropy strings that no
  signature names.
- History scanning: every commit's changes are checked, so a secret that
  was committed and later deleted is still reported, with the commit that
  introduced it.
- Baselines: `--update-baseline` records current findings as SHA-256
  fingerprints, and `--baseline` leaves them out of later scans.
- Console table or JSON output (`--output json`), with matched values cut
  to their first 6 characters.
- `--no-history` to scan only the current files.
- CI-friendly exit codes: 0 clean, 1 findings, 2 when the scan could not
  run.
- CI on Python 3.11 to 3.14, with bandit and pip-audit.

### Security

- Scanning a repository could run commands from that repository's own git
  configuration. Every git call now disables those settings
  ([#17](https://github.com/ZukoG/sentinel-secrets/issues/17)).

### Fixed

- Unquoted secrets in `.env` and `.properties` files were never matched
  ([#15](https://github.com/ZukoG/sentinel-secrets/issues/15)).
- Entropy flagged code identifiers, shell paths, and lock files as
  secrets ([#16](https://github.com/ZukoG/sentinel-secrets/issues/16)).
- Files with non-ASCII names, and text files that are not valid UTF-8,
  were silently skipped
  ([#21](https://github.com/ZukoG/sentinel-secrets/issues/21),
  [#23](https://github.com/ZukoG/sentinel-secrets/issues/23)).
- Non-ASCII text in history, an invalid repository path, and redirected
  output could crash the scan or return the wrong exit code
  ([#20](https://github.com/ZukoG/sentinel-secrets/issues/20),
  [#22](https://github.com/ZukoG/sentinel-secrets/issues/22),
  [#25](https://github.com/ZukoG/sentinel-secrets/issues/25)).
- One secret could be reported twice
  ([#24](https://github.com/ZukoG/sentinel-secrets/issues/24)).

[Unreleased]: https://github.com/ZukoG/sentinel-secrets/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/ZukoG/sentinel-secrets/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/ZukoG/sentinel-secrets/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ZukoG/sentinel-secrets/releases/tag/v1.0.0
