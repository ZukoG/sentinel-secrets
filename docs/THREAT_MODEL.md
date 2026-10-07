# Threat Model: sentinel-secrets

Version 1.0.0

A deliberately lightweight threat model, sized to a one-week, single-purpose
CLI rather than a full STRIDE walkthrough. It covers three questions:

1. What can this tool fail to catch? (false negatives)
2. What risk does running this tool create for the person running it?
3. Can the tool's own output become a place secrets leak to?

Every finding below is based on the code as it ships in v1.0.0, and the
detection gaps are backed by a real scan, not hypotheticals. Measured
against a real repository (106 commits, 92 tracked files), the tool
produced 125 findings in 3.7 seconds, none of which were real secrets, and
it missed one known secret. Both results are written up below.

## 1. Assets and trust boundaries

**What's being protected:** credentials committed to a git repository,
and the machine of whoever runs the scan.

**Trust boundaries:**

- **The scanned repository is untrusted input.** That includes its file
  contents, its commit history, and its local `.git/config`. The tool
  treats file contents as plain text, but it hands the repository path to
  `git`, and git reads that repository's configuration.
- **The output destination is outside the tool's control.** The console,
  a redirected file, or a CI log may be visible to more people than the
  repository itself.
- **The person running the tool and their `PATH` are trusted.** If an
  attacker already controls the environment the tool runs in, nothing
  this tool does can protect against that.

## 2. Security properties by design

These hold for v1.0.0 and are covered by tests or verified in code:

| Property | How |
|---|---|
| No network activity | No network code anywhere in the package. It never validates whether a found key is live and never sends findings anywhere. |
| Read-only | Only `git ls-files` and `git log` are run. Nothing is written to the scanned repository. |
| The full secret never leaves the line it was found on | `scanner.py` truncates matched text to its first 6 characters when the `Finding` is created, so reports, JSON output, and the baseline only ever see the truncated form. `test_format_console_preserves_redaction` checks this end to end. |
| The baseline file holds no secrets | It stores SHA-256 fingerprints of source, rule name, and the already-truncated text. Nothing in it can be reversed into the original secret. |
| No shell involved in subprocess calls | Every git call passes a fixed argument list with no `shell=True`, so a repository path can't inject shell syntax. |
| Least-privilege CI | The GitHub Actions workflow token is `contents: read`. |

## 3. Findings

Severity reflects impact and how realistic the scenario is for a tool like
this one.

| ID | Finding | Severity | Status |
|---|---|---|---|
| T-1 | Scanning a repository runs commands from its own git config | High | Open, [#17](https://github.com/ZukoG/sentinel-secrets/issues/17) |
| T-2 | Unquoted secret assignments are missed | Medium | Open, [#15](https://github.com/ZukoG/sentinel-secrets/issues/15) |
| T-3 | Secrets with no signature and low entropy are missed | Medium | Accepted |
| T-4 | Deliberately obfuscated secrets are missed | Low | Accepted, out of scope |
| T-5 | Entropy detection is noisy on real code | Low | Open, [#16](https://github.com/ZukoG/sentinel-secrets/issues/16) |
| T-6 | Output reveals the first 6 characters of each match | Low | Accepted |
| T-7 | `git` is resolved through `PATH` | Low | Accepted |
| T-8 | History output is held fully in memory | Low | Accepted |

### T-1: Scanning a repository runs commands from its own git config (High)

git honors the scanned repository's local `.git/config`, and two settings
there can name an arbitrary command that runs during a normal scan:

- `diff.<driver>.textconv`, paired with a `.gitattributes` entry. `git log
  -p` runs textconv drivers by default, so `walk_history` executes it.
- `core.fsmonitor`. git runs it when reading the index, so `walk_working_tree`'s
  `git ls-files` executes it.

I verified both with a harmless probe command that writes a marker file:
after a normal scan, both markers existed.

**Who is exposed:** cloning never copies `.git/config`, so a repository
you cloned yourself is safe. The risk is scanning a repository folder
received as-is, such as a zip, a shared drive, or a copied directory. For
a secrets scanner that's a realistic scenario, like auditing a project
someone sent over, which is why this is rated High despite the precondition.

**Mitigation:** passing `-c core.fsmonitor=false` to both git calls and
adding `--no-textconv --no-ext-diff` to `git log`. I verified this against
the same probe repository: neither marker appeared. Not yet applied in
v1.0.0. Until it is, only scan repositories you cloned yourself.

### T-2: Unquoted secret assignments are missed (Medium)

The Generic Secret Assignment signature only matches quoted values
(`secret = "..."`). Unquoted `KEY=value` lines, the normal syntax in
`.properties` and `.env` files, are missed. Those are two of the most
common places real secrets get committed.

Found by scanning a real repository: a `.properties` line setting a JWT
signing secret with a human-readable default produced no finding. Entropy
didn't catch it either, since the value scored about 4.33 bits per
character, under the 4.5 threshold. The same value in quotes is flagged
immediately.

### T-3: Secrets with no signature and low entropy are missed (Medium)

Detection is two-sided: a value is caught if it matches one of five
signatures, or if it's long and random enough. A secret that is neither
gets through, including human-readable passwords (`Summer2024!`), and
credentials from any provider not covered by `patterns.py`. New providers
and token formats appear constantly, so a fixed signature list is always
somewhat out of date.

I accept this as inherent to the approach chosen in
[ADR 0001](adr/0001-regex-and-entropy-over-ml-detection.md). Adding a
signature is cheap when a gap is found; T-2 is an example of one worth
closing.

### T-4: Deliberately obfuscated secrets are missed (Low)

A secret split across string concatenation (`"AKIA" + "..."`), spread over
multiple lines, reversed, or otherwise encoded on purpose won't match a
signature, and may not look random enough per token to trip entropy
either. This tool targets accidental commits, not someone actively
hiding a credential from it, so I consider this out of scope.

### T-5: Entropy detection is noisy on real code (Low)

The same real-repository scan produced 125 entropy findings and zero real
secrets: shell paths built from variables (`$TMP_DOWNLOAD_DIR/...`), fully
qualified identifiers (`Standard14Fonts.FontName.HELVETICA_BOLD`), and a
dependency lock file hash. The main cause is that token extraction doesn't
split on `.`, `/`, or `$`, so a long path or identifier is scored as one
random-looking token. Lock file hashes really are random, so they need a
path-based ignore rather than better tokenizing.

Rated Low because it's noise, not a leak: the baseline file suppresses
accepted findings so they don't come back on later runs. The real cost is
that a first run on an existing codebase takes manual triage, and alert
fatigue can make a real finding easier to overlook.

### T-6: Output reveals the first 6 characters of each match (Low)

Truncation keeps the first 6 characters so a finding is recognizable. For
signature matches this is almost entirely the public, fixed prefix
(`AKIAIO`, `ghp_aa`, `-----B`), which gives away nothing secret. For
entropy findings it's 6 characters of the raw value itself. That reduces
the remaining search space somewhat but doesn't make a long random secret
guessable. Worth remembering when output ends up in a public CI log.

### T-7: `git` is resolved through `PATH` (Low)

bandit reports 5 low-severity findings, all in `git_walker.py` and all
about invoking `git` through `subprocess`: importing `subprocess` (B404),
calling it without a shell (B603), and using a partial executable path
(B607). The first two are expected for a tool that wraps git; calls use a
fixed argument list, which is the safe pattern. The third means whatever
`git` comes first on `PATH` gets run. Anyone who can change `PATH` already
controls the environment, so I accept this, and CI reports these findings
without failing the build.

### T-8: History output is held fully in memory (Low)

`walk_history` captures the entire `git log -p --all` output before
processing it. A very large repository could use a lot of memory or take a
long time. Binary changes show up as a one-line "Binary files differ" in
the log, so only text diffs contribute, but streaming the output line by
line would remove the issue. Accepted for v1.0.0, which has only been
measured against a repository of around a hundred commits.

## 4. Out of scope

- Verifying whether a found credential is live. Deliberately excluded, see
  the SRS's out-of-scope section.
- Protecting secrets after they're found. Rotation and history rewriting
  are the user's job; this tool only reports.
- An attacker who already controls the machine or environment running the
  scan.
