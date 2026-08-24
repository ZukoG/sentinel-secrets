# Software Requirements Specification — sentinel-secrets

Version 0.1.0

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
  VCS/chat platform tokens, private key headers)
- Detecting unnamed high-entropy strings that don't match a known format
- Suppressing confirmed false positives via a baseline/allowlist file
- Reporting findings to the console and as JSON, with matched secret
  values truncated/redacted rather than printed in full

### 2.2 Out of scope

- Validating whether a found key is actually live (no calls to any cloud
  provider or service to check a key's status)
- Auto-remediation: this tool never rotates, revokes, or removes a secret
  it finds, only reports it
- Scanning anything that isn't a local git repository (no remote scanning,
  no scanning of non-git directories)
- Any network activity of any kind — this tool never sends what it finds
  anywhere

## 3. Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | The tool shall detect known secret formats in scanned content using named regex signatures. |
| FR-2 | The tool shall flag high-entropy strings that don't match a known signature, using a configurable entropy threshold. |
| FR-3 | The tool shall scan every file in the working tree, respecting `.gitignore`. |
| FR-4 | The tool shall scan the full commit history by walking each commit's diff, so a secret committed and later removed is still caught. |
| FR-5 | The tool shall support a baseline file recording accepted findings by fingerprint (file, rule, hash of the matched text), and shall exclude any current finding that matches an entry in it. |
| FR-6 | The tool shall report findings to the console in a readable format and, optionally, as JSON. |
| FR-7 | Any output, in any format, shall truncate or redact the actual matched secret value rather than printing it in full. |
| FR-8 | The tool shall be runnable from the command line against a target repository path, with flags to select the baseline file, output format, and whether history scanning is included. |
| FR-9 | The tool shall exit with a nonzero status code when findings exist, so it can gate a CI pipeline elsewhere. |

## 4. Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR-1 | The tool makes no network calls under any circumstance. |
| NFR-2 | The tool never modifies the repository it scans. |
| NFR-3 | The tool must run against a repository with a few hundred commits in well under a minute on ordinary hardware. |
| NFR-4 | Every reported finding must include enough context (file path, line number where applicable, rule name) to locate and fix it without re-running the scan. |

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

The baseline file (FR-5) exists specifically to make that entropy
false-positive cost manageable in practice, rather than avoiding entropy
detection altogether.

## 6. Non-Goals

Explicitly not attempted, and not planned for later within this project's
one-week scope: a web UI, a hosted/service version of the scanner,
machine-learning-based detection, or integration with a specific CI
platform beyond the GitHub Actions workflow this repository ships with
for its own use.

## 7. Open Questions

None outstanding as of v0.1.0. This section will be updated if a design
decision is deferred during the build.
