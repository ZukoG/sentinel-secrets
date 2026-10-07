# Software Requirements Specification: sentinel-secrets

Version 1.0.0

## 1. Purpose

I'm building sentinel-secrets to scan a git repository for secrets that
were committed into it, either sitting in the current working tree or
buried somewhere in past commit history, and to report them so they can
be rotated and removed. It's a companion project to
[sentinel-secscan](https://github.com/ZukoG/sentinel-secscan), scoped
down to a single week and a single concern.

## 2. Scope

### 2.1 In scope

- Scanning a local git repository's working tree files
- Scanning a local git repository's commit history (diffs across commits)
- Detecting known secret formats via regex signatures (cloud provider keys,
  VCS/chat platform tokens, private key headers, named secret assignments)
- Detecting unnamed high-entropy strings that don't match a known format
- Suppressing confirmed false positives via a baseline/allowlist file
- Reporting findings to the console and as JSON, with matched secret
  values truncated rather than printed in full

### 2.2 Out of scope

- Validating whether a found key is actually live (no calls to any cloud
  provider or service to check a key's status)
- Auto-remediation: this tool never rotates, revokes, or removes a secret
  it finds, only reports it
- Scanning anything that isn't a local git repository (no remote scanning,
  no scanning of non-git directories)
- Any network activity of any kind. This tool never sends what it finds
  anywhere.

## 3. Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | The tool shall detect known secret formats in scanned content using named regex signatures: AWS access key IDs, GitHub tokens, Slack tokens, PEM private key headers, and quoted or unquoted assignments to names like `api_key`, `secret`, `token`, or `password`. |
| FR-2 | The tool shall flag high-entropy strings that don't match a known signature. A token is flagged when it is at least 20 characters long and scores above 4.5 bits per character. Lines are split into tokens on whitespace, quotes, brackets, and assignment punctuation, plus `.` and `$`, so dotted identifiers and shell variables are scored as separate words. Both thresholds are parameters of `is_high_entropy` but are not exposed as CLI flags in v1.0.0. |
| FR-3 | The tool shall scan every file in the working tree that git does not ignore, including untracked files and files with non-ASCII names, respecting `.gitignore`. A file is treated as binary and skipped only if it contains a NUL byte near the start, the same rule git uses; any other file is scanned as text, even if it isn't valid UTF-8. |
| FR-4 | The tool shall scan the full commit history by walking each commit's added lines, so a secret committed and later removed is still caught. |
| FR-5 | The tool shall support a baseline file recording accepted findings by fingerprint, a SHA-256 hash of the finding's source, rule name, and truncated matched text, and shall exclude any current finding that matches an entry in it. The CLI shall be able to create or extend a baseline from the current findings. |
| FR-6 | The tool shall report findings to the console in a readable format and, optionally, as JSON. |
| FR-7 | Any output, in any format, shall truncate the matched secret value rather than printing it in full. Truncation happens when a finding is created, keeping the first 6 characters, so the full value never travels past the line it was found on. |
| FR-8 | The tool shall be runnable from the command line against a target repository path, with flags to select the baseline file, update a baseline file, choose the output format, and choose whether history scanning is included. |
| FR-9 | The tool shall exit with status 1 when findings remain after baseline filtering and 0 when none do, so it can gate a CI pipeline elsewhere. Invalid arguments, a path that isn't a git repository, and a missing `git` executable exit with status 2 and a readable message, never a traceback. |
| FR-10 | Dependency lock files (`package-lock.json`, `yarn.lock`, `poetry.lock`, `.terraform.lock.hcl`, and similar) shall be excluded from both the working tree and history scans, since their integrity hashes are random by design. |

## 4. Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR-1 | The tool makes no network calls under any circumstance. |
| NFR-2 | The tool never modifies the repository it scans. It only runs read-only git commands (`git ls-files`, `git log`). |
| NFR-3 | The tool must run against a repository with a few hundred commits in well under a minute on ordinary hardware. Measured so far: a real repository with 106 commits and 92 tracked files took 1.3 seconds for a full working tree and history scan. A repository with a few hundred commits hasn't been measured directly yet. |
| NFR-4 | Every reported finding must include enough context to locate it without re-running the scan. Working tree findings carry a file path and line number. History findings carry the short hash of the commit that introduced the secret, plus a line number relative to that commit's added lines rather than to a file. |
| NFR-5 | Scanning a repository must never execute commands defined by that repository's own configuration. Git settings that can name a command (`core.fsmonitor`, textconv and external diff drivers) are disabled for every git call the tool makes. |
| NFR-6 | Output must not depend on the platform's default text encoding. Git output is decoded as UTF-8, and reports are written as UTF-8 even when redirected to a file or pipe. |

## 5. Detection Approach

Detection combines two independent techniques, deliberately, rather than
relying on either alone:

- **Signature matching** catches secrets in known formats (an AWS access
  key, a GitHub token, a PEM private key header) with high precision and
  near-zero false positives, but only for formats I've explicitly written
  a pattern for.
- **Entropy analysis** catches the gap signature matching can't: a
  generic, unlabeled high-randomness string (a raw API key with no
  recognizable prefix) that no fixed pattern would ever match, at the
  cost of a higher false-positive rate on things like hashes and encoded
  binary data.

Each secret is reported once. Signatures are checked from most specific to
most generic, and a match that overlaps one already reported on the same
line is skipped, so a quoted GitHub token is reported as a GitHub Token
rather than also as a generic assignment. Entropy is only checked for
tokens no signature has already matched.

The baseline file (FR-5) exists specifically to make that entropy
false-positive cost manageable in practice, rather than avoiding entropy
detection altogether. The reasoning behind this approach is recorded in
[ADR 0001](adr/0001-regex-and-entropy-over-ml-detection.md), and its
measured limitations in [THREAT_MODEL.md](THREAT_MODEL.md).

## 6. Non-Goals

Explicitly not attempted, and not planned for later within this project's
one-week scope: a web UI, a hosted/service version of the scanner,
machine-learning-based detection, or integration with a specific CI
platform beyond the GitHub Actions workflow this repository ships with
for its own use.

## 7. Open Questions

None outstanding as of v1.0.0.
