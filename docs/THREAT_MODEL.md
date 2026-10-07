# Threat Model: sentinel-secrets

Version 1.0.0

A deliberately lightweight threat model, sized to a one-week, single-purpose
CLI rather than a full STRIDE walkthrough. It covers three questions:

1. What can this tool fail to catch? (false negatives)
2. What risk does running this tool create for the person running it?
3. Can the tool's own output become a place secrets leak to?

Every finding below is based on the code as it ships in v1.0.0, and the
detection gaps are backed by real scans, not hypotheticals. Writing the
first version of this document turned up enough real problems that I
fixed them before releasing, so several findings below are marked Fixed,
with the evidence kept rather than deleted.

The clearest before-and-after is a scan of a real repository (106 commits,
92 tracked files). Before the fixes it produced 125 findings, every one a
false positive, and missed the one real secret in it. After the fixes it
produces 2 findings, both that real secret (once in the file, once in the
commit that added it), in 1.3 seconds.

## 1. Assets and trust boundaries

**What's being protected:** credentials committed to a git repository,
and the machine of whoever runs the scan.

**Trust boundaries:**

- **The scanned repository is untrusted input.** That includes its file
  contents, file names, commit history, and local `.git/config`. The tool
  treats file contents as plain text, but it hands the repository path to
  `git`, and git reads that repository's configuration.
- **The output destination is outside the tool's control.** The console,
  a redirected file, or a CI log may be visible to more people than the
  repository itself.
- **The person running the tool and their `PATH` are trusted.** If an
  attacker already controls the environment the tool runs in, nothing
  this tool does can protect against that.

## 2. Security properties by design

These hold for v1.0.0 and are covered by tests:

| Property | How |
|---|---|
| No network activity | No network code anywhere in the package. It never validates whether a found key is live and never sends findings anywhere. |
| Read-only | Only `git ls-files` and `git log` are run. Nothing is written to the scanned repository. |
| The scanned repository can't run commands | Every git call disables `core.fsmonitor`, and `git log` runs with `--no-textconv --no-ext-diff`, so settings in the scanned repository's own config can't name a command that gets executed. |
| The full secret never leaves the line it was found on | `scanner.py` truncates matched text to its first 6 characters when the `Finding` is created, so reports, JSON output, and the baseline only ever see the truncated form. |
| The baseline file holds no secrets | It stores SHA-256 fingerprints of source, rule name, and the already-truncated text. Nothing in it can be reversed into the original secret. |
| No shell involved in subprocess calls | Every git call passes a fixed argument list with no `shell=True`, so a repository path can't inject shell syntax. |
| Failures are never mistaken for results | A path that isn't a repository, or a missing `git`, exits with status 2, never 1, which is reserved for "findings exist". |
| Least-privilege CI | The GitHub Actions workflow token is `contents: read`. |

## 3. Findings

Severity reflects impact and how realistic the scenario is for a tool like
this one.

| ID | Finding | Severity | Status |
|---|---|---|---|
| T-1 | Scanning a repository ran commands from its own git config | High | Fixed, [#17](https://github.com/ZukoG/sentinel-secrets/issues/17) |
| T-2 | Unquoted secret assignments were missed | Medium | Fixed, [#15](https://github.com/ZukoG/sentinel-secrets/issues/15) |
| T-3 | Secrets with no signature and low entropy are missed | Medium | Accepted |
| T-4 | Deliberately obfuscated secrets are missed | Low | Accepted, out of scope |
| T-5 | Entropy detection was noisy on real code | Low | Fixed, [#16](https://github.com/ZukoG/sentinel-secrets/issues/16) |
| T-6 | Output reveals the first 6 characters of each match | Low | Accepted |
| T-7 | `git` is resolved through `PATH` | Low | Accepted |
| T-8 | History output is held fully in memory | Low | Accepted |
| T-9 | Some files were silently skipped | High | Fixed, [#21](https://github.com/ZukoG/sentinel-secrets/issues/21), [#23](https://github.com/ZukoG/sentinel-secrets/issues/23) |
| T-10 | Some inputs crashed the scan or lost the report | Medium | Fixed, [#20](https://github.com/ZukoG/sentinel-secrets/issues/20), [#22](https://github.com/ZukoG/sentinel-secrets/issues/22), [#25](https://github.com/ZukoG/sentinel-secrets/issues/25) |
| T-11 | One secret could be reported twice | Low | Fixed, [#24](https://github.com/ZukoG/sentinel-secrets/issues/24) |

### T-1: Scanning a repository ran commands from its own git config (High, Fixed)

git honors the scanned repository's local `.git/config`, and two settings
there can name an arbitrary command that ran during a normal scan:

- `diff.<driver>.textconv`, paired with a `.gitattributes` entry. `git log
  -p` runs textconv drivers by default, so `walk_history` executed it.
- `core.fsmonitor`. git runs it when reading the index, so `walk_working_tree`'s
  `git ls-files` executed it.

I verified both with a harmless probe command that writes a marker file:
after a normal scan, both markers existed. Cloning never copies
`.git/config`, so the exposure was scanning a repository folder received
as-is, such as a zip or a shared drive. For a secrets scanner that's a
realistic scenario, like auditing a project someone sent over.

**Fix:** every git call now passes `-c core.fsmonitor=false`, and `git log`
adds `--no-textconv --no-ext-diff`. `test_scanned_repo_config_cannot_run_commands`
builds the same kind of hostile repository and asserts the marker is never
created; it fails against the old code.

### T-2: Unquoted secret assignments were missed (Medium, Fixed)

The Generic Secret Assignment signature only matches quoted values
(`secret = "..."`). Unquoted `KEY=value` lines, the normal syntax in
`.properties` and `.env` files, were missed, and those are two of the most
common places real secrets get committed. A real repository's `.properties`
file setting a JWT signing secret with a human-readable default produced no
finding: no signature matched, and the value scored about 4.33 bits per
character, under the entropy threshold.

**Fix:** a new Unquoted Secret Assignment signature. Matching any unquoted
`token = something` would flag ordinary code, so the value must be at least
16 characters, mix letters and digits, and not be followed by `(` (a
function call). Against the same real repository it catches the JWT secret
and adds no other findings.

### T-3: Secrets with no signature and low entropy are missed (Medium, Accepted)

Detection is two-sided: a value is caught if it matches a signature, or if
it's long and random enough. A secret that is neither gets through:

- **Human-readable passwords** (`Summer2024!`) and short values, unless
  they appear in a named assignment that a signature covers.
- **Hex-encoded secrets.** A hex string can score at most 4 bits per
  character, under the 4.5 threshold, so a random 64-character hex key
  (measured at 3.79) is never flagged by entropy. Lowering the threshold
  for hex would flag every commit hash and checksum in a repository.
- **bcrypt hashes** (`$2b$12$...`). Their alphabet includes `.`, which is
  now a token separator (see T-5), so they split into pieces too short to
  flag. They were only ever caught by accident, and a bcrypt hash isn't a
  credential itself, but a leaked one can be cracked offline.
- **Any provider not covered by a signature.** New token formats appear
  constantly, so a fixed signature list is always somewhat out of date.

I accept this as inherent to the approach chosen in
[ADR 0001](adr/0001-regex-and-entropy-over-ml-detection.md). Adding a
signature is cheap when a gap matters, as T-2 showed.

### T-4: Deliberately obfuscated secrets are missed (Low, Accepted)

A secret split across string concatenation (`"AKIA" + "..."`), spread over
multiple lines, reversed, or otherwise encoded on purpose won't match a
signature, and may not look random enough per token to trip entropy
either. This tool targets accidental commits, not someone actively
hiding a credential from it, so I consider this out of scope.

### T-5: Entropy detection was noisy on real code (Low, Fixed)

The real-repository scan produced 125 entropy findings and zero real
secrets. Looking at the actual flagged tokens, they fell into three groups:
shell paths built from variables (`$TMP_DOWNLOAD_DIR/$distributionUrlName`),
dotted identifiers (`Standard14Fonts.FontName.HELVETICA_BOLD`), and a
dependency lock file hash.

**Fix:** token extraction now also splits on `.` and `$`, which breaks the
first two groups into ordinary words, and dependency lock files are
excluded from both scans by name, since their hashes really are random.
After the fix, the same repository produced no entropy findings at all.

`/` is deliberately not a separator. AWS secret access keys and other
base64 secrets contain it, and splitting there would cut them into pieces
too short to flag. Tests check that an AWS secret key and a JWT are still
caught. The one known cost is bcrypt hashes, recorded under T-3.

### T-6: Output reveals the first 6 characters of each match (Low, Accepted)

Truncation keeps the first 6 characters so a finding is recognizable. For
signature matches this is almost entirely the public, fixed prefix
(`AKIAIO`, `ghp_aa`, `-----B`) or the variable name (`api_ke`), which gives
away nothing secret. For entropy findings it's 6 characters of the raw
value itself. That reduces the remaining search space somewhat but doesn't
make a long random secret guessable. Worth remembering when output ends up
in a public CI log.

### T-7: `git` is resolved through `PATH` (Low, Accepted)

bandit reports 6 low-severity findings, all about `subprocess`: importing it
(B404, in `git_walker.py`, and in `cli.py`, which only imports it to catch
git's error type), calling it without a shell (B603), and using a partial
executable path (B607). The first two are expected for a tool that wraps
git, and the calls use a fixed argument list, which is the safe pattern.
The third means whatever `git` comes first on `PATH` gets run. Anyone who
can change `PATH` already controls the environment, so I accept this, and
CI reports these findings without failing the build.

### T-8: History output is held fully in memory (Low, Accepted)

`walk_history` captures the entire `git log -p --all` output before
processing it. A very large repository could use a lot of memory or take a
long time. Binary changes show up as a one-line "Binary files differ" in
the log, so only text diffs contribute, but streaming the output line by
line would remove the issue. Accepted for v1.0.0, which has only been
measured against a repository of around a hundred commits.

### T-9: Some files were silently skipped (High, Fixed)

Two bugs made the working tree scan skip files without any message, which
is the worst failure a secrets scanner can have: a clean report that isn't
actually clean.

- **Non-ASCII file names** ([#21](https://github.com/ZukoG/sentinel-secrets/issues/21)).
  `git ls-files` escapes them by default (`café.py` became
  `"caf\303\251.py"`), the escaped string wasn't a real path, and the read
  failure was swallowed. Fixed by using `git ls-files -z`, which prints raw
  paths.
- **Text files that aren't valid UTF-8** ([#23](https://github.com/ZukoG/sentinel-secrets/issues/23)).
  Any decoding failure was treated as "binary". Java `.properties` files are
  traditionally Latin-1, and a `.properties` file containing `café` and an
  AWS key produced "No findings." with exit status 0. Fixed by using git's
  own binary rule, a NUL byte near the start, and decoding everything else
  with replacement characters.

### T-10: Some inputs crashed the scan or lost the report (Medium, Fixed)

- **Non-ASCII text in history** ([#20](https://github.com/ZukoG/sentinel-secrets/issues/20)).
  git output was decoded with the platform default encoding, cp1252 on
  Windows, which can't decode some UTF-8 bytes. The scan crashed. Git
  output is now always decoded as UTF-8.
- **An invalid repository path** ([#22](https://github.com/ZukoG/sentinel-secrets/issues/22))
  printed a traceback and exited with status 1, the "findings exist" code,
  so a mistyped path in CI looked like a secrets problem. It now prints
  git's message and exits with status 2.
- **Redirected output** ([#25](https://github.com/ZukoG/sentinel-secrets/issues/25)).
  On Windows, redirected output used cp1252, so a finding in a file named
  `設定.py` crashed the report and left the output file empty. Reports are
  now always written as UTF-8.

### T-11: One secret could be reported twice (Low, Fixed)

Signature matches weren't checked against each other, so
`GITHUB_TOKEN = "ghp_..."` was reported as both a GitHub Token and a
Generic Secret Assignment ([#24](https://github.com/ZukoG/sentinel-secrets/issues/24)).
Not a leak, but duplicates inflate reports and make triage harder.
Signatures are now checked from most specific to most generic, and an
overlapping later match is skipped.

## 4. Out of scope

- Verifying whether a found credential is live. Deliberately excluded, see
  the SRS's out-of-scope section.
- Protecting secrets after they're found. Rotation and history rewriting
  are the user's job; this tool only reports.
- An attacker who already controls the machine or environment running the
  scan.
