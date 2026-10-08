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

## 📑 Contents

- [🕰️ Why history matters](#️-why-history-matters)
- [🔍 What it detects](#-what-it-detects)
- [🏁 Getting started](#-getting-started)
  - [Step 1: Open a terminal](#step-1-open-a-terminal)
  - [Step 2: Check that Python and Git are installed](#step-2-check-that-python-and-git-are-installed)
  - [Step 3: Download sentinel-secrets](#step-3-download-sentinel-secrets)
  - [Step 4: Set it up](#step-4-set-it-up)
  - [Step 5: Run your first scan](#step-5-run-your-first-scan)
  - [Using it again later](#using-it-again-later)
- [📖 Reading the results](#-reading-the-results)
- [🚀 Usage](#-usage)
- [💻 Walkthrough](#-walkthrough)
- [✅ Accepting findings with a baseline](#-accepting-findings-with-a-baseline)
- [🩹 Troubleshooting](#-troubleshooting)
- [⚠️ Known limitations](#️-known-limitations)
- [⚙️ How it works](#️-how-it-works)
- [🛠️ Development](#️-development)
- [📚 Documentation](#-documentation)
- [📄 License](#-license)

## 🕰️ Why history matters

Deleting a committed secret doesn't remove it. The file disappears from
the working tree, but the commit that added it is still in the history,
and anyone who clones the repository gets that history too. That's why
sentinel-secrets scans every commit's changes as well as the current files:
a token added in one commit and removed in the next is still reported,
along with the commit that introduced it.

<sub>[⬆️ Back to contents](#-contents)</sub>

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

<sub>[⬆️ Back to contents](#-contents)</sub>

## 🏁 Getting started

No programming knowledge needed. Follow the steps in order, and wherever
the instructions differ between operating systems, use the part for yours:
🪟 **Windows**, 🍎 **macOS**, or 🐧 **Linux**.

Every command goes into a **terminal**: type it (or copy and paste it),
then press **Enter**.

### Step 1: Open a terminal

A terminal is a window where you type commands instead of clicking.

- 🪟 **Windows:** press the **Windows key**, type `PowerShell`, and click
  **Windows PowerShell**.
- 🍎 **macOS:** press **Cmd + Space**, type `Terminal`, and press **Enter**.
- 🐧 **Linux:** press **Ctrl + Alt + T**, or open **Terminal** from your
  applications menu.

### Step 2: Check that Python and Git are installed

sentinel-secrets needs **Python 3.11 or newer** and **Git**. Check whether
you already have them:

🪟 **Windows:**

```powershell
python --version
git --version
```

🍎 **macOS** and 🐧 **Linux:**

```bash
python3 --version
git --version
```

✅ **You're set if** you see something like `Python 3.12.4` (any version
3.11 or higher) and `git version 2.45.1`. Skip to
[Step 3](#step-3-download-sentinel-secrets).

❌ **If either command says "not found" or "not recognized"**, or Python is
older than 3.11, install what's missing:

<details>
<summary>🪟 <b>Installing on Windows</b></summary>

1. **Python:** go to [python.org/downloads](https://www.python.org/downloads/),
   download the latest version, and run the installer. **If it shows a box
   labelled "Add python.exe to PATH", tick it** before clicking
   **Install Now**. Without it, the `python` command won't work.
2. **Git:** go to [git-scm.com/downloads/win](https://git-scm.com/downloads/win),
   download the installer, and run it. The default options are fine, so you
   can keep clicking **Next**.
3. **Close PowerShell and open it again** so it picks up the new programs,
   then repeat the checks above.

</details>

<details>
<summary>🍎 <b>Installing on macOS</b></summary>

1. **Python:** go to [python.org/downloads](https://www.python.org/downloads/),
   download the latest macOS installer, and run it.
2. **Git:** type `git --version` in Terminal. If Git isn't installed, macOS
   offers to install the **Command Line Developer Tools**. Click **Install**
   and wait for it to finish.
3. **Close Terminal and open it again**, then repeat the checks above.

</details>

<details>
<summary>🐧 <b>Installing on Linux</b></summary>

**Ubuntu or Debian:**

```bash
sudo apt update
sudo apt install python3 python3-venv git
```

**Fedora:**

```bash
sudo dnf install python3 git
```

Type your password when asked; nothing appears on screen while you type
it, which is normal. Then repeat the checks above. If your Python is older
than 3.11 (Ubuntu 22.04 ships 3.10), see
[Troubleshooting](#-troubleshooting).

</details>

### Step 3: Download sentinel-secrets

This makes a copy of the project in a new folder called `sentinel-secrets`,
then moves the terminal into it. The commands are the same on every
operating system:

```bash
git clone https://github.com/ZukoG/sentinel-secrets.git
cd sentinel-secrets
```

✅ You should see a few lines ending in `done.` and no error.

### Step 4: Set it up

This creates a private space for sentinel-secrets (a *virtual
environment*, kept in a folder named `.venv`) and installs it there, so it
doesn't affect anything else on your computer.

🪟 **Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

> If the second command shows an error saying **running scripts is
> disabled on this system**, run this once, then try the second command
> again:
>
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```
>
> It only changes the setting for your own user account, letting
> PowerShell run scripts you created yourself, like the one above.

🍎 **macOS** and 🐧 **Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

✅ **It worked if** your terminal line now starts with `(.venv)` and you see
`Successfully installed sentinel-secrets-1.0.0`. A notice afterwards about
a new version of pip being available is normal and safe to ignore.

### Step 5: Run your first scan

Type `sentinel-secrets`, a space, then the location of the project folder
you want to scan. That folder must be a git repository (a project that was
downloaded with `git clone` or created with `git init`).

🪟 **Windows:**

```powershell
sentinel-secrets C:\Users\YourName\Documents\my-project
```

🍎 **macOS:**

```bash
sentinel-secrets /Users/yourname/Documents/my-project
```

🐧 **Linux:**

```bash
sentinel-secrets /home/yourname/my-project
```

Replace the example location with your own. Two shortcuts that work on
every operating system:

- 💡 **Drag and drop:** type `sentinel-secrets ` (with a space at the end),
  then drag the project folder from your file manager into the terminal
  window. Its full location is typed in for you.
- 💡 **Spaces in the location:** wrap it in quotes, for example
  `sentinel-secrets "C:\Users\Your Name\my project"`.

You'll see either `No findings.` 🎉 or a table of findings. The next
section explains how to read it.

### Using it again later

Each time you open a new terminal, move into the `sentinel-secrets` folder
and switch the virtual environment back on before scanning.

🪟 **Windows:**

```powershell
cd sentinel-secrets
.venv\Scripts\Activate.ps1
sentinel-secrets C:\path\to\your\project
```

🍎 **macOS** and 🐧 **Linux:**

```bash
cd sentinel-secrets
source .venv/bin/activate
sentinel-secrets /path/to/your/project
```

<sub>[⬆️ Back to contents](#-contents)</sub>

## 📖 Reading the results

Each row of the table is one possible secret:

| Column | Meaning |
|---|---|
| **SEVERITY** | How serious it is: 🔴 `CRITICAL`, 🟠 `HIGH`, or 🟡 `MEDIUM` |
| **RULE** | What kind of secret it looks like |
| **SOURCE** | The file it's in, or `commit abc12345` if it's in the project's history |
| **LINE** | The line number to look at |
| **MATCHED** | The first 6 characters of what was found. The full secret is never printed |

**🚨 If a finding is a real secret:**

1. **Treat it as stolen.** Go to the service it belongs to (AWS, GitHub,
   Slack, and so on) and revoke it or generate a new one. This is the step
   that actually protects you.
2. **Remove it from the code** and load it from an environment variable or
   a config file that git ignores instead.
3. **Remember that deleting it isn't enough on its own.** Old commits still
   contain it, which is exactly why step 1 matters most.

If a finding isn't a real secret (a test value, for example), you can
[accept it with a baseline](#-accepting-findings-with-a-baseline) so it
stops being reported.

<sub>[⬆️ Back to contents](#-contents)</sub>

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

<sub>[⬆️ Back to contents](#-contents)</sub>

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

<sub>[⬆️ Back to contents](#-contents)</sub>

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

<sub>[⬆️ Back to contents](#-contents)</sub>

## 🩹 Troubleshooting

<details>
<summary><b>"python" or "git" is not recognized / command not found</b></summary>

The program isn't installed, or the terminal was opened before it was
installed. Follow the install steps in
[Step 2](#step-2-check-that-python-and-git-are-installed), then close the
terminal and open a new one.

🪟 On Windows, if typing `python` opens the Microsoft Store instead, Python
from python.org isn't installed yet, or **"Add python.exe to PATH"** was
left unticked. Run the python.org installer again, choose **Modify**, and
make sure that option is on.

</details>

<details>
<summary><b>"running scripts is disabled on this system" (Windows)</b></summary>

PowerShell blocks the activation script by default. Run this once, then
try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

</details>

<details>
<summary><b>"sentinel-secrets" is not recognized / command not found</b></summary>

The virtual environment isn't switched on in this terminal. Your terminal
line should start with `(.venv)`. Follow
[Using it again later](#using-it-again-later) to switch it on.

</details>

<details>
<summary><b>"not a git repository"</b></summary>

The folder you gave isn't a git repository, or the location has a typo.
Check the location, and use the folder that contains the project's hidden
`.git` folder (usually the project's main folder).

</details>

<details>
<summary><b>"requires a different Python"</b></summary>

Your Python is older than 3.11. On Windows and macOS, install the latest
version from [python.org/downloads](https://www.python.org/downloads/).
On Ubuntu 22.04, which ships Python 3.10, install 3.11 alongside it and use
it to create the virtual environment:

```bash
sudo apt install python3.11 python3.11-venv
python3.11 -m venv .venv
```

Then continue from `source .venv/bin/activate` in
[Step 4](#step-4-set-it-up).

</details>

<sub>[⬆️ Back to contents](#-contents)</sub>

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

<sub>[⬆️ Back to contents](#-contents)</sub>

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

<sub>[⬆️ Back to contents](#-contents)</sub>

## 🛠️ Development

With the virtual environment switched on (see
[Step 4](#step-4-set-it-up)), install the test tools and run the tests.
The commands are the same on every operating system:

```bash
pip install -e ".[dev]"
pytest
```

CI runs on every pull request and push to `main`: the test suite on Python
3.11, 3.12, 3.13, and 3.14, the Getting started steps above on Windows,
macOS, and Linux, [bandit](https://bandit.readthedocs.io/) for static
analysis, and [pip-audit](https://pypi.org/project/pip-audit/) for
dependency vulnerabilities.

<sub>[⬆️ Back to contents](#-contents)</sub>

## 📚 Documentation

- 📋 [Software Requirements Specification](docs/SRS.md)
- 🛡️ [Threat Model](docs/THREAT_MODEL.md)
- 🧭 [ADR 0001: Regex signatures plus entropy analysis over ML-based detection](docs/adr/0001-regex-and-entropy-over-ml-detection.md)

Companion project to
[sentinel-secscan](https://github.com/ZukoG/sentinel-secscan), a passive web
security assessment platform.

## 📄 License

[MIT](LICENSE)

<sub>[⬆️ Back to contents](#-contents)</sub>
