# ADR 0001: Regex signatures plus entropy analysis over ML-based detection

- **Status:** Accepted
- **Date:** 2026-08-24 (decided while building the detection core, written
  up at v1.0.0)

## Context

sentinel-secrets needs to decide, line by line, whether a piece of text
is a secret. Whatever approach I picked had to fit a few hard constraints
from the SRS:

- **No network calls, ever (NFR-1).** Detection has to run fully offline.
  That rules out any hosted classification service, and any approach that
  confirms a finding by calling the provider.
- **Explainable findings.** Every finding needs a rule name that tells the
  person reading the report *why* it was flagged (NFR-4), and something
  they can reason about when deciding whether to baseline it.
- **Standard library only for the detection core.** No dependency without
  a specific reason, and the project had one week.
- **Unit-testable with plain strings.** I wanted to verify detection by
  feeding in a known secret and a known non-secret and asserting the
  result, with no model files, fixtures, or randomness involved.

## Decision

Detection combines two independent techniques, both in the standard
library (`re`, `math`):

1. **Regex signatures** (`patterns.py`) for secrets with a known format:
   AWS access key IDs, GitHub tokens, Slack tokens, PEM private key
   headers, and generic quoted and unquoted `api_key`/`secret`/`token`/`password`
   assignments. Each signature carries a name and a severity.
2. **Shannon entropy** (`entropy.py`) for everything a signature can't
   name: any token of 20 or more characters scoring above 4.5 bits per
   character gets flagged as a High Entropy String.

Each secret is reported once: signatures run from most specific to most
generic, a match overlapping one already reported is skipped, and entropy
only looks at tokens no signature matched. A baseline file absorbs the false
positives entropy inevitably produces, so they're triaged once rather than
on every run.

## Alternatives considered

**An ML classifier trained on secret and non-secret strings.** This is the
direction some commercial scanners take, and it can catch secrets with no
fixed format that are too short or too low-entropy for the entropy check.
I rejected it for this project because it breaks almost every constraint
above: it needs a labeled training set I don't have, a model file and
probably a heavy dependency, and its output is a probability rather than a
named rule a reader can reason about. Its results are also much harder to
test deterministically. The extra recall wasn't worth that for a one-week
tool, and it would have turned a detection problem into a data problem.

**Regex signatures only.** Precise and nearly free of false positives, but
blind to any secret without a recognizable prefix, such as a raw API key or
a random password. Those are exactly the cases worth catching, so on its
own this misses too much.

**Entropy only.** Catches unlabeled random strings, but on its own it
can't name what it found, flags plenty of non-secrets, and misses
structured secrets that happen to score below the threshold. Signatures
cover that weakness well, which is why the two together are stronger than
either one alone.

**Wrapping an existing tool** (gitleaks, detect-secrets, TruffleHog).
These are mature and would detect more than this project does. But the
point of this project is to build and understand the detection myself,
and wrapping one would add a dependency while hiding the part worth
learning.

## Consequences

**Positive**

- Detection runs fully offline with no dependencies, and each finding has
  a clear rule name and severity.
- Every rule is deterministic and tested directly with plain strings, 65
  tests across Python 3.11 to 3.14 in CI.
- Adding coverage for a new token format is a single new `Signature`
  entry and a pair of tests. Closing the unquoted-assignment gap (T-2) took
  exactly that.
- Fast: a real repository with 106 commits and 92 files scanned in 1.3
  seconds.

**Negative**, measured against a real repository and recorded in
[THREAT_MODEL.md](../THREAT_MODEL.md):

- **Gaps in signature coverage go unnoticed until someone looks.** A secret
  format with no signature and modest entropy is simply missed (T-3). The
  first version missed unquoted `.properties`/`.env` values entirely, which
  only came to light by scanning a real repository (T-2, fixed in
  [#15](https://github.com/ZukoG/sentinel-secrets/issues/15)).
- **Entropy needs tuning against real code, not just test strings.** The
  first version produced 125 entropy findings on that repository and no
  real secrets, because dotted identifiers and shell paths read as random
  tokens. Splitting on `.` and `$` and excluding lock files brought that to
  zero (T-5, [#16](https://github.com/ZukoG/sentinel-secrets/issues/16)),
  at the cost of no longer catching bcrypt hashes by accident.
- **Hex secrets are invisible to entropy.** Hex tops out at 4 bits per
  character, so a random hex key never reaches the 4.5 threshold (T-3).
- **The thresholds are judgment calls.** 4.5 bits and 20 characters sit
  between ordinary English (a test sentence measured 4.32) and base64-like
  randomness (up to 6), but no single threshold separates secrets from
  non-secrets cleanly. A human-readable secret measured 4.33, almost
  identical to that English sentence, which is why T-2 needed a signature
  rather than a lower threshold.
  Both are function parameters, so they can be tuned without changing the
  approach.
