# sentinel-secrets

[![CI](https://github.com/ZukoG/sentinel-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/ZukoG/sentinel-secrets/actions/workflows/ci.yml)

A command-line tool I built to scan a git repository, both its current
files and its full commit history, for secrets that shouldn't be there:
API keys, access tokens, private keys, and other credentials committed by
accident.

It's passive and read-only. It reads files and git history on disk and
reports what it finds. It never sends anything over the network, never
tries to check whether a found key is live, and never modifies the
repository it scans.

## Why history matters

Deleting a committed secret doesn't remove it. The file disappears from
the working tree, but the commit that added it is still in the history,
and anyone who clones the repository gets that history too. That's why
sentinel-secrets scans every commit's changes as well as the current files:
a token added in one commit and removed in the next is still reported,
along with the commit that introduced it.

## What it detects

| Rule | Severity | How |
|---|---|---|
| Private Key Header | CRITICAL | PEM headers such as `-----BEGIN RSA PRIVATE KEY-----` |
| AWS Access Key ID | HIGH | `AKIA` followed by 16 uppercase letters or digits |
| GitHub Token | HIGH | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` followed by 36 characters |
| Slack Token | HIGH | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` tokens |
| Generic Secret Assignment | MEDIUM | `api_key`, `secret`, `token`, or `password` assigned a quoted value of 16+ characters |
| High Entropy String | MEDIUM | Any token of 20+ characters scoring above 4.5 bits per character of Shannon entropy |

Signatures catch known formats precisely. Entropy catches random-looking
strings that no signature names, such as a raw API key with no prefix. When
both flag the same value, only the signature match is reported. The
reasoning behind this approach is in
[ADR 0001](docs/adr/0001-regex-and-entropy-over-ml-detection.md).

## Install

Requires Python 3.11 or newer and `git` on your `PATH`. There are no
runtime dependencies.

```bash
git clone https://github.com/ZukoG/sentinel-secrets.git
cd sentinel-secrets
python -m venv .venv
```

Activate the virtual environment (Windows PowerShell, then Linux/macOS):

```bash
.venv\Scripts\Activate.ps1
```

```bash
source .venv/bin/activate
```

Then install:

```bash
pip install -e .
```

## Usage

```
sentinel-secrets [-h] [--baseline BASELINE] [--output {console,json}]
                 [--history | --no-history]
                 repo_path
```

| Option | Default | Meaning |
|---|---|---|
| `repo_path` | | Path to the git repository to scan |
| `--history` / `--no-history` | `--history` | Include or skip scanning every commit's changes |
| `--output` | `console` | `console` for a table, `json` for machine-readable output |
| `--baseline` | none | JSON file of accepted findings to leave out of the results |

**Exit codes:** `0` when no findings remain, `1` when any do, `2` for
invalid arguments. That makes it usable as a gate in a CI pipeline.

## Walkthrough

These are real runs against a small demo repository: three files with
secrets in them, plus a GitHub token that was committed and then deleted
in a later commit.

```
$ sentinel-secrets demo-repo
SEVERITY   RULE                      SOURCE                         LINE   MATCHED
HIGH       AWS Access Key ID         app/config.py                  2      AKIAIO...
MEDIUM     Generic Secret Assignment app/settings.py                1      api_ke...
CRITICAL   Private Key Header        deploy/id_rsa                  1      -----B...
HIGH       GitHub Token              commit 0df1182f                1      ghp_Zt...
HIGH       AWS Access Key ID         commit 8281a723                2      AKIAIO...
MEDIUM     Generic Secret Assignment commit 8281a723                4      api_ke...
CRITICAL   Private Key Header        commit 8281a723                5      -----B...
```

The first three rows are files in the working tree. The rest come from
history: the GitHub token no longer exists in any file, but commit
`0df1182f` still contains it. Matched text is always cut to its first 6
characters, so the report never prints a whole secret. Line numbers on
history findings count lines added in that commit, not lines in a file.

Skipping history only reports the current files:

```
$ sentinel-secrets demo-repo --no-history
SEVERITY   RULE                      SOURCE                         LINE   MATCHED
HIGH       AWS Access Key ID         app/config.py                  2      AKIAIO...
MEDIUM     Generic Secret Assignment app/settings.py                1      api_ke...
CRITICAL   Private Key Header        deploy/id_rsa                  1      -----B...
```

JSON output, for feeding into other tools (first entry shown):

```
$ sentinel-secrets demo-repo --no-history --output json
[
  {
    "source": "app/config.py",
    "line_number": 2,
    "rule_name": "AWS Access Key ID",
    "severity": "HIGH",
    "matched_text": "AKIAIO..."
  },
  ...
]
```

A repository with nothing to report:

```
$ sentinel-secrets clean-demo
No findings.
```

## Accepting findings with a baseline

Some findings are false positives, or known and accepted. A baseline file
records them so they stop being reported. It stores SHA-256 fingerprints
only, never the secrets themselves.

The CLI can read a baseline but can't write one yet
([#18](https://github.com/ZukoG/sentinel-secrets/issues/18)). Until it can,
create one with a few lines of Python. This example accepts every current
Private Key Header finding:

```python
from sentinel_secrets.git_walker import walk_working_tree
from sentinel_secrets.baseline import fingerprint, save_baseline

accepted = [f for f in walk_working_tree("demo-repo") if f.rule_name == "Private Key Header"]
save_baseline("baseline.json", {fingerprint(f) for f in accepted})
```

Then pass it in:

```
$ sentinel-secrets demo-repo --no-history --baseline baseline.json
SEVERITY   RULE                      SOURCE                         LINE   MATCHED
HIGH       AWS Access Key ID         app/config.py                  2      AKIAIO...
MEDIUM     Generic Secret Assignment app/settings.py                1      api_ke...
```

## Known limitations

> **Only scan repositories you cloned yourself.** In v1.0.0, git reads the
> scanned repository's own `.git/config`, and certain settings there can
> make a scan run arbitrary commands. Cloning never copies that file, so a
> fresh clone is safe; a repository folder received as-is (a zip, a shared
> drive) may not be. Tracked in
> [#17](https://github.com/ZukoG/sentinel-secrets/issues/17).

Other limitations, all measured against a real repository and written up in
[THREAT_MODEL.md](docs/THREAT_MODEL.md):

- **Unquoted secrets are missed.** `KEY=value` lines, the usual syntax in
  `.properties` and `.env` files, don't match the generic signature
  ([#15](https://github.com/ZukoG/sentinel-secrets/issues/15)).
- **Entropy is noisy on real code.** On an existing codebase, expect a first
  run to flag long paths, dotted identifiers, and lock file hashes. Baseline
  them once ([#16](https://github.com/ZukoG/sentinel-secrets/issues/16)).
- **Human-readable passwords and unknown token formats can slip through**
  when they match no signature and aren't random enough for entropy.

## How it works

```
cli.py ──> git_walker.py ──> scanner.py ──> baseline.py ──> report.py
             │                 │
             │                 ├── patterns.py   (regex signatures)
             │                 └── entropy.py    (Shannon entropy)
             │
             ├── walk_working_tree: git ls-files, every non-ignored file
             └── walk_history:      git log -p, every commit's added lines
```

1. `git_walker.py` asks git for the files to scan (`git ls-files
   --exclude-standard`, so `.gitignore` is respected by git itself) and for
   every commit's diff (`git log -p --all`). Binary files are skipped.
2. `scanner.py` checks each line against every signature, then checks the
   remaining tokens for high entropy, truncating anything it matches before
   creating a finding.
3. `baseline.py` drops findings whose fingerprint is already accepted.
4. `report.py` prints the rest as a table or as JSON.

## Development

```bash
pip install -e ".[dev]"
pytest
```

CI runs on every pull request and push to `main`: the test suite on Python
3.11, 3.12, 3.13, and 3.14, [bandit](https://bandit.readthedocs.io/) for
static analysis, and [pip-audit](https://pypi.org/project/pip-audit/) for
dependency vulnerabilities.

## Documentation

- [Software Requirements Specification](docs/SRS.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [ADR 0001: Regex signatures plus entropy analysis over ML-based detection](docs/adr/0001-regex-and-entropy-over-ml-detection.md)

Companion project to
[sentinel-secscan](https://github.com/ZukoG/sentinel-secscan), a passive web
security assessment platform.

## License

[MIT](LICENSE)
