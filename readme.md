# Scanee

**Static application security scanner with taint analysis and optional AI-assisted triage**

Scanee analyzes local source-code projects and selected configuration/dependency files for potential security issues. It provides a command-line interface (CLI), reports, baselines, and an optional local web dashboard.

> **Important:** Scanee is currently a source-code/project scanner, not a live website or URL vulnerability scanner. Entering `https://example.com` will not crawl or test that website. The dashboard's path field expects a path on the computer running Scanee.

## Easy start

Choose the instructions for your operating system. You do not need to install Git if you already have the project folder or ZIP archive.

### Windows (PowerShell)

1. Extract the Scanee ZIP to a folder such as `C:\scanee`.
2. Open PowerShell and run these commands one at a time:

```powershell
cd C:\scanee
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe cli.py init
.\.venv\Scripts\python.exe cli.py scan . -o report.html
```

3. Open `report.html` from the Scanee folder in your browser.

To start the browser dashboard instead, run:

```powershell
.\.venv\Scripts\python.exe cli.py serve --host 127.0.0.1 --port 8000
```

Then visit <http://127.0.0.1:8000>. Keep the PowerShell window open while using it. Press `Ctrl+C` to stop the dashboard.

If `py` is not recognized, install Python 3.9 or newer and ensure Python is added to PATH. If PowerShell activation is restricted, the commands above still work because they call the virtual environment's Python executable directly.

### Linux (Ubuntu/Debian)

1. Extract the ZIP, or `cd` into the folder that contains `cli.py`.
2. Install Python tooling and the project requirements:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip
cd ~/scanee
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python cli.py init
.venv/bin/python cli.py scan . -o report.html
```

3. Open `report.html` in a browser. If you are connected to a remote server over SSH, download the report to your computer to view it.

Start the dashboard locally with:

```bash
.venv/bin/python cli.py serve --host 127.0.0.1 --port 8000
```

On a remote VPS, keep the dashboard bound to `127.0.0.1` and create an SSH tunnel from your own computer:

```powershell
ssh -L 8000:127.0.0.1:8000 youruser@YOUR_SERVER_IP
```

Replace `youruser` and `YOUR_SERVER_IP` with your SSH username and server address. Keep the SSH session and dashboard running, then open <http://127.0.0.1:8000> on your computer.

> **Security warning:** Do not expose the dashboard directly to the public internet. It currently has no authentication and allows scans of paths accessible to the process. Run it only on a trusted machine or through a protected SSH tunnel. The ZIP upload and extraction workflow also needs further hardening before accepting untrusted uploads.

## What Scanee scans

- **Source code:** pattern-based checks and limited taint/data-flow analysis for supported languages.
- **Secrets:** likely API keys, tokens, private keys, credentials, and high-entropy strings.
- **Application security patterns:** selected injection, XSS, authentication, cryptography, file handling, deserialization, and configuration issues.
- **Project artifacts:** selected sensitive files such as environment files, backups, and private keys.
- **Dependencies:** supported package manifests/lockfiles checked against OSV.dev for known vulnerabilities.
- **Optional external tools:** integrations may use Semgrep, Bandit, Gitleaks, Trivy, and Gosec if those tools are installed and available.
- **Optional AI review:** finding triage, logic review, and suggested patches through a Venice-compatible API endpoint.

Coverage depends on the language, framework, file types, rules, dependencies, and optional tools available. Scanee cannot guarantee that every vulnerability will be found or that every reported finding is exploitable.

## Requirements

- Python 3.9 or newer
- `requirements.txt` installs the Python packages used by this version, including PyYAML, Flask, Requests, Semgrep, and Bandit.
- Git is only needed if cloning the repository.
- Gitleaks, Trivy, and Gosec are separate optional command-line tools; installing Python requirements does not install these binaries.
- Network access is needed for OSV dependency lookups and AI analysis. Dependency lookups can be disabled with `--no-deps`.

## Installation from the repository

```bash
git clone https://github.com/mowais28/scanee.git
cd scanee
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python cli.py init
```

On Windows, replace the last Python path with `.venv\Scripts\python.exe`, or use the Windows commands in **Easy start** above.

## CLI usage

General syntax:

```bash
python3 cli.py scan <project-path> [options]
```

If you use a virtual environment, run `.venv/bin/python` on Linux/macOS or `.venv\Scripts\python.exe` on Windows instead of `python3`.

### Common scan commands

Scan the current directory and write the default HTML report (`scanee-report.html`):

```bash
python3 cli.py scan .
```

Scan a project directory and choose the HTML report name:

```bash
python3 cli.py scan /path/to/your/app -o report.html
```

Windows example:

```powershell
.\.venv\Scripts\python.exe cli.py scan "C:\Projects\myapp" -o report.html
```

Generate other report formats:

```bash
python3 cli.py scan . -f json -o report.json
python3 cli.py scan . -f sarif -o report.sarif
python3 cli.py scan . -f md -o report.md
```

Use optional external scanners that are installed on the machine:

```bash
python3 cli.py scan . --tools -o tools-report.html
```

Skip online dependency checks:

```bash
python3 cli.py scan . --no-deps -o local-report.html
```

Report high and critical findings (the severity filter includes the selected severity and more severe findings):

```bash
python3 cli.py scan . --min-severity high -o high-risk.html
```

Exclude paths using glob patterns (repeat the option as needed):

```bash
python3 cli.py scan . --exclude '*/tests/*' --exclude '*.min.js'
```

See all commands and options:

```bash
python3 cli.py --help
python3 cli.py scan --help
python3 cli.py serve --help
```

## Web dashboard

Run locally:

```bash
python3 cli.py serve --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. The dashboard can accept a ZIP upload or a local path on the computer running Scanee. It does not accept a URL for live website testing.

**Do not bind the dashboard to `0.0.0.0` or expose it publicly in its current state.** It has no login, accepts local paths, and processes uploaded ZIP files. For a production service, implement authentication/authorization, strict path allowlists, archive extraction safeguards, upload and resource limits, job cleanup, request protections, and process/container isolation first.

## AI-powered analysis (optional)

AI analysis requires a valid API key for a Venice-compatible chat-completions endpoint. Review the provider's data policies before sending code or finding context to an external service.

Linux/macOS:

```bash
export VENICE_API_KEY="YOUR_API_KEY"
export scanee_MODEL="llama-3.3-70b"
# Optional custom compatible endpoint:
# export VENICE_API_URL="https://your-compatible-endpoint/v1/chat/completions"
python3 cli.py scan . --ai --logic -o ai-report.html
```

Windows PowerShell:

```powershell
$env:VENICE_API_KEY = "YOUR_API_KEY"
$env:scanee_MODEL = "llama-3.3-70b"
# Optional custom compatible endpoint:
# $env:VENICE_API_URL = "https://your-compatible-endpoint/v1/chat/completions"
.\.venv\Scripts\python.exe cli.py scan . --ai --logic -o ai-report.html
```

`--logic` is intended to be used with `--ai`. AI output may be inaccurate and must be reviewed. Avoid scanning confidential repositories with AI enabled unless external transmission is approved.

## Suggested fixes

The `fix` command creates a text file containing AI-generated patch suggestions. It does **not** automatically apply the patches to your project.

```bash
python3 cli.py fix /path/to/your/app --limit 10 -o suggested-fixes.txt
```

AI credentials are required. Review suggestions manually, apply them in a branch or copy of your project, run tests, and scan again.

## Configuration

Create `.scanee.yml` in the current directory:

```bash
python3 cli.py init
```

If it already exists, use `python3 cli.py init --force` only if you intend to replace it. The configuration supports engines, severity, exclusions, optional tools, job count, and dependency lookup settings. See the generated `.scanee.yml` and `cli.py` for the options supported by the installed version.

## Baseline scanning

Save a baseline from a scan:

```bash
python3 cli.py scan . --write-baseline .scanee-baseline.json -o baseline-report.html
```

Compare later scans against it:

```bash
python3 cli.py scan . --baseline .scanee-baseline.json -o comparison-report.html
```

A baseline helps distinguish previously known findings from newly observed findings. Review baseline contents and keep them in a trusted location.

## Output formats

| Format | Option | Purpose |
|---|---|---|
| HTML | `-f html` (default) | Browser-readable report |
| JSON | `-f json` | Custom processing and integrations |
| SARIF | `-f sarif` | Compatible code-scanning platforms |
| Markdown | `-f md` | Pull requests, documentation, and reviews |

## Detection coverage

The rules and analysis target multiple languages and formats, including Python, PHP, JavaScript, TypeScript, Ruby, Go, Java, C#, Kotlin, C/C++, HTML, Jinja, Twig, Vue, YAML, Terraform, Dockerfiles, shell, SQL, and Nginx/Apache configuration. Actual coverage varies by rule and framework.

Categories include selected injection risks, XSS, secrets, authentication and session patterns, cryptography, file handling, deserialization, configuration, dependency vulnerabilities, and exposed artifacts. Application-logic review is AI-assisted and is not a substitute for manual authorization testing.

## How taint analysis works

Taint analysis attempts to trace potentially untrusted input through supported assignments, concatenation, and string interpolation toward sensitive operations (sinks). It recognizes selected sources, sinks, and sanitizers. Its analysis is limited and may not follow flows across all functions, modules, frameworks, or files.

## Limitations and safe use

- Static analysis cannot see every runtime behavior or guarantee vulnerability detection.
- Pattern-based rules can produce false positives and false negatives.
- AI triage and fixes can be incorrect or incomplete.
- Dependency lookups and external integrations may require internet access and separate tools.
- A clean report is not a security certification and does not replace code review, dynamic testing, penetration testing, or monitoring.
- Run scans with the least privileges needed and only scan code you own or are authorized to assess.
- Treat reports as sensitive: they may contain file paths, code excerpts, and secret-like values. Store and share them carefully.

## Contributing

Contributions are welcome, particularly new rules, test cases for true and false positives, language/framework improvements, documentation, and performance work. Include tests for both vulnerable and safe examples when adding detection rules.


<div> <sub>Built for people who would rather find it before an attacker does.</sub> </div>

**Use scanee to identify potential security issues earlier in the development lifecycle.**

