# Security Policy

sentinel-secrets is a security tool that people point at their own
repositories, so a flaw in it can put those repositories at risk. If you
find one, I would like to hear about it privately first.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | Yes, fixes are released as 1.1.x patch versions |
| Earlier than 1.1.0 | No, please upgrade to the latest release |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it
privately instead:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the form and submit it. Only you and I can see the report.

Direct link: <https://github.com/ZukoG/sentinel-secrets/security/advisories/new>
(you need to be signed in to GitHub).

Useful things to include:

- The version (`pip show sentinel-secrets`), your operating system, and
  your Python and git versions.
- The exact command you ran.
- A minimal repository or file that reproduces the problem. Please use
  fake secrets, never real ones.
- What happened, and what you expected to happen.

## What happens next

This is a project I maintain on my own, so these are best-effort targets
rather than guarantees:

- **Within 7 days:** I acknowledge the report and tell you whether I can
  reproduce it.
- **Once confirmed:** I work on a fix with a regression test, keep you
  updated on progress, and release it as a patch version.
- **After the fix ships:** the issue is published as a GitHub security
  advisory and recorded in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
  You are credited for the report unless you would rather not be.

## What counts as a vulnerability

The tool promises to be passive, offline, and read-only (see
[docs/SRS.md](docs/SRS.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).
Anything that breaks one of those promises is in scope, for example:

- **Running code from a scanned repository.** Scanning must never execute
  anything the repository controls, such as commands hidden in its own git
  configuration. This has happened once and was fixed
  ([T-1](docs/THREAT_MODEL.md#t-1-scanning-a-repository-ran-commands-from-its-own-git-config-high-fixed)).
- **Revealing a full secret.** Reports, JSON output, and baseline files must
  never contain more than the first 6 characters of a match.
- **Making a network connection.** The tool must never contact any service.
- **Changing the scanned repository** in any way.
- **Silently skipping files or losing the report** on crafted input, so a
  scan looks clean when it isn't.

## What is not a vulnerability

These are still welcome, as a normal
[issue](https://github.com/ZukoG/sentinel-secrets/issues):

- **A secret the tool misses.** Detection gaps are expected and documented
  as known limitations (T-3 and T-4 in the threat model). A new signature
  suggestion, with a fake example, is a feature request.
- **A false positive.** Use a baseline file to accept it.
- **A vulnerability in a dependency** such as pytest or bandit. Those are
  dev tools only and are kept current by Dependabot. Please report the flaw
  itself to that project.

If you used this tool and found a **real secret in someone else's
repository**, please report it to that repository's owner, not here.
