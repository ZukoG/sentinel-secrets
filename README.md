# sentinel-secrets

[![CI](https://github.com/ZukoG/sentinel-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/ZukoG/sentinel-secrets/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Release](https://img.shields.io/github/v/release/ZukoG/sentinel-secrets)](https://github.com/ZukoG/sentinel-secrets/releases/latest)

🔐 A command-line tool I built to scan a git repository, both its current
files and its full commit history, for secrets that shouldn't be there:
API keys, access tokens, private keys, and other credentials committed by
accident.

It's passive and read-only. It reads files and git history on disk and
reports what it finds:

- 📴 It never sends anything over the network
- 🚫 It never tries to check whether a found key is live
- 🔒 It never modifies the repository it scans

## 🕰️ Why history matters

Deleting a committed secret doesn't remove it. The file disappears from
the working tree, but the commit that added it is still in the history,
and anyone who clones the repository gets that history too. That's why
sentinel-secrets scans every commit's changes as well as the current files:
a token added in one commit and removed in the next is still reported,
along with the commit that introduced it.

## 🔍 What it detects

| Rule | Severity | How |
|---|---|---|
| Private Key Header | 🔴 CRITICAL | PEM headers such as `-----BEGIN RSA PRIVATE KEY-----` |
| AWS Access Key ID | 🟠 HIGH | `AKIA` followed by 16 uppercase letters or digits |
| GitHub Token | 🟠 HIGH | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` followed by 36 characters |
| Slack Token | 🟠 HIGH | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` tokens |
| Generic Secret Assignment | 🟡 MEDIUM | `api_key`, `secret`, `token`, or `password` assigned a quoted value of 16+ characters |
| Unquoted Secret Assignment | 🟡 MEDIUM | The same names assigned an unquoted value of 16+ characters mixing letters and digits, as in `.env` and `.properties` files |
| High Entropy String | 🟡 MEDIUM | Any token of 20+ characters scoring above 4.5 bits per character of Shannon entropy |

Signatures catch known formats precisely. Entropy catches random-looking
strings that no signature names, such as a raw API key with no prefix. Each
secret is reported once, under its most specific rule. Dependency lock
files (`package-lock.json`, `yarn.lock`, `poetry.lock`, and similar) are
skipped, since their integrity hashes are random by design. The reasoning
behind this approach is in
[ADR 0001](docs/adr/0001-regex-and-entropy-over-ml-detection.md).

## 📦 Install

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

## 🚀 Usage

```
sentinel-secrets [-h] [--baseline BASELINE] [--update-baseline PATH]
                 [--output {console,json}] [--history | --no-history]
                 repo_path
```

| Option | Default | Meaning |
|---|---|---|
| `repo_path` | | Path to the git repository to scan |
| `--history` / `--no-history` | `--history` | Include or skip scanning every commit's changes |
| `--output` | `console` | `console` for a table, `json` for machine-readable output |
| `--baseline` | none | JSON file of accepted findings to leave out of the results |
| `--update-baseline` | none | Add every current finding to this baseline file and exit |

**Exit codes:**

- ✅ `0` when no findings remain
- ❌ `1` when any do
- ⚠️ `2` when the scan couldn't run (invalid arguments, a path that isn't a
  git repository, or `git` not installed)

A failed scan never exits with `1`, so a CI gate can't mistake a typo for a
secrets problem.

## 💻 Walkthrough

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

A repository with nothing to report, and a path that isn't a repository:

```
$ sentinel-secrets clean-demo
No findings.

$ sentinel-secrets not-a-repo
sentinel-secrets: error: fatal: not a git repository (or any of the parent directories): .git
```

## ✅ Accepting findings with a baseline

Some findings are false positives, or known and accepted. A baseline file
records them so they stop being reported. It stores SHA-256 fingerprints
only, never the secrets themselves.

After reviewing a scan, accept everything it currently reports:

```
$ sentinel-secrets demo-repo --update-baseline baseline.json
Added 7 finding(s) to baseline.json

$ sentinel-secrets demo-repo --baseline baseline.json
No findings.
```

From then on, only new secrets show up. After adding a file containing a
Slack token:

```
$ sentinel-secrets demo-repo --baseline baseline.json
SEVERITY   RULE                      SOURCE                         LINE   MATCHED
HIGH       Slack Token               app/slack.py                   1      xoxb-2...
```

Running `--update-baseline` again adds new findings and keeps the existing
entries.

## ⚠️ Known limitations

All measured and written up in [THREAT_MODEL.md](docs/THREAT_MODEL.md):

- **Human-readable passwords and unknown token formats can slip through**
  when they match no signature and aren't random enough for entropy.
- **Hex-encoded secrets aren't caught by entropy.** Hex scores at most 4
  bits per character, under the 4.5 threshold.
- **Deliberately hidden secrets aren't caught.** A secret split across
  string concatenation or encoded on purpose is out of scope; this tool
  targets accidental commits.
- **Very large histories are held in memory** while being scanned. Tested
  so far against a repository of around a hundred commits.

## ⚙️ How it works

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
   every commit's diff (`git log -p --all`). Lock files are excluded, and a
   file is only treated as binary if it contains a NUL byte, the same rule
   git uses. Settings in the scanned repository's own git config that could
   run a command are disabled, so scanning a repository someone hands you
   can't execute anything.
2. `scanner.py` checks each line against every signature, then checks the
   remaining tokens for high entropy, truncating anything it matches before
   creating a finding.
3. `baseline.py` drops findings whose fingerprint is already accepted.
4. `report.py` prints the rest as a table or as JSON.

## 🛠️ Development

```bash
pip install -e ".[dev]"
pytest
```

CI runs on every pull request and push to `main`: the test suite on Python
3.11, 3.12, 3.13, and 3.14, [bandit](https://bandit.readthedocs.io/) for
static analysis, and [pip-audit](https://pypi.org/project/pip-audit/) for
dependency vulnerabilities.

## 📚 Documentation

- 📋 [Software Requirements Specification](docs/SRS.md)
- 🛡️ [Threat Model](docs/THREAT_MODEL.md)
- 🧭 [ADR 0001: Regex signatures plus entropy analysis over ML-based detection](docs/adr/0001-regex-and-entropy-over-ml-detection.md)

Companion project to
[sentinel-secscan](https://github.com/ZukoG/sentinel-secscan), a passive web
security assessment platform.

## 📄 License

[MIT](LICENSE)
