"""scanee core — engines, taint analysis, scoring, baseline."""

from __future__ import annotations
import bisect, fnmatch, hashlib, json, math, os, re, shutil, subprocess, sys, time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path

from rules import RULES

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_SCORE = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.1}
SEV_CVSS = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "1.0"}
MAX_SIZE = 3 * 1024 * 1024
VERSION = "2.0.0"


@dataclass
class Finding:
    rule: str
    severity: str
    category: str
    file: str
    line: int
    message: str
    snippet: str = ""
    cwe: str = ""
    fix: str = ""
    tool: str = "builtin"
    confidence: str = "medium"
    path: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    @property
    def fp(self):
        norm = re.sub(r"\s+", " ", self.snippet)[:80]
        return hashlib.sha1(f"{self.rule}|{self.file}|{norm}".encode()).hexdigest()[:16]

    def cvss(self):
        return SEV_CVSS[self.severity]


# ============================== WALKER ==============================
LANG_MAP = {
    ".py": "py", ".php": "php", ".phtml": "php", ".php5": "php", ".inc": "php",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "ts", ".tsx": "ts",
    ".rb": "rb", ".go": "go", ".java": "java", ".cs": "cs", ".kt": "java",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c",
    ".html": "html", ".htm": "html", ".twig": "twig", ".vue": "vue", ".svelte": "html",
    ".yml": "yaml", ".yaml": "yaml", ".tf": "tf", ".tfvars": "tf",
    ".json": "json", ".toml": "toml", ".ini": "ini", ".conf": "conf",
    ".sh": "sh", ".bash": "sh", ".zsh": "sh", ".sql": "sql", ".xml": "xml",
}
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "bower_components",
             "__pycache__", ".venv", "venv", "env", ".tox", "dist", "build",
             ".next", ".nuxt", "target", "obj", "coverage", ".idea", ".vscode",
             ".mypy_cache", ".pytest_cache", ".terraform"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".gz", ".exe",
            ".dll", ".so", ".dylib", ".pyc", ".class", ".jar", ".o", ".min.js"}


def lang_of(p: Path) -> str:
    n = p.name.lower()
    if n == "dockerfile" or n.startswith("dockerfile."):
        return "docker"
    if n.startswith(".env"):
        return "env"
    if n in ("gemfile", "rakefile"):
        return "rb"
    if n == "makefile":
        return "sh"
    return LANG_MAP.get(p.suffix.lower(), "")


def load_gitignore(root: Path):
    pats = []
    for g in root.rglob(".gitignore"):
        if any(part in SKIP_DIRS for part in g.parts):
            continue
        try:
            for line in g.read_text("utf-8", "replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pats.append(line.rstrip("/"))
        except OSError:
            pass
    return pats


def is_ignored(rel: str, pats) -> bool:
    for p in pats:
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*") or fnmatch.fnmatch(rel, "*/" + p):
            return True
    return False


def walk(root: Path, excludes=(), respect_gitignore=True):
    gpat = load_gitignore(root) if respect_gitignore else []
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d not in excludes]
        for f in filenames:
            p = Path(dirpath) / f
            if p.suffix.lower() in SKIP_EXT and not p.name.endswith(".min.js"):
                continue
            rel = str(p.relative_to(root))
            if is_ignored(rel, gpat):
                continue
            if any(fnmatch.fnmatch(rel, x) or fnmatch.fnmatch(f, x) for x in excludes):
                continue
            out.append(p)
    return out


# ============================== SUPPRESSION ==============================
SUPPRESS = re.compile(r"(?:#|//|/\*|\*|<!--|--)\s*scanee:\s*ignore(?::([\w\-,\s]+))?", re.I)


def suppressed_lines(text: str):
    """line number -> set of rule ids (or '*' for all)"""
    out = defaultdict(set)
    for i, line in enumerate(text.splitlines(), 1):
        m = SUPPRESS.search(line)
        if m:
            ids = [x.strip() for x in (m.group(1) or "*").split(",") if x.strip()]
            for ln in (i, i + 1, i - 1):
                out[ln].update(ids or ["*"])
    return out


def is_suppressed(sup, line, rule):
    s = sup.get(line)
    return bool(s) and ("*" in s or rule in s)


# ============================== ENGINE: RULES ==============================
_rxc = {}
def _rx(p):
    if p not in _rxc:
        _rxc[p] = re.compile(p)
    return _rxc[p]


def _linemap(text):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def engine_rules(path, root, min_sev):
    out = []
    try:
        raw = path.read_bytes()
    except OSError:
        return out
    if len(raw) > MAX_SIZE or b"\x00" in raw[:8192]:
        return out
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    starts = _linemap(text)
    rel = str(path.relative_to(root))
    lang = lang_of(path)
    sup = suppressed_lines(text)

    for r in RULES:
        if r["langs"] and lang not in r["langs"]:
            continue
        if SEV_ORDER[r["sev"]] > SEV_ORDER[min_sev]:
            continue
        try:
            rx = _rx(r["pat"])
        except re.error:
            continue
        n = 0
        for m in rx.finditer(text):
            ln = bisect.bisect_right(starts, m.start())
            if is_suppressed(sup, ln, r["id"]):
                continue
            out.append(Finding(r["id"], r["sev"], r["cat"], rel, ln, r["msg"],
                               (lines[ln - 1].strip()[:220] if 0 < ln <= len(lines) else ""),
                               r["cwe"], r["fix"], "rules"))
            n += 1
            if n >= r["maxhits"]:
                break
    return out


# ============================== ENGINE: ENTROPY ==============================
STR_LIT = re.compile(r"""['"]([A-Za-z0-9+/=_\-\.]{20,120})['"]""")
HEXY = re.compile(r"^[0-9a-fA-F]+$")
PLACEHOLDER = re.compile(r"(?i)(xxxx|your_|changeme|placeholder|example|dummy|test_|_here|todo|<|\{\{)")


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def engine_entropy(path, root, known):
    try:
        text = path.read_text("utf-8", "replace")
    except OSError:
        return []
    rel = str(path.relative_to(root))
    lines = text.splitlines()
    sup = suppressed_lines(text)
    out = []
    for m in STR_LIT.finditer(text):
        s = m.group(1)
        h = entropy(s)
        if h < 4.3 or PLACEHOLDER.search(s):
            continue
        ln = text.count("\n", 0, m.start()) + 1
        if (rel, ln) in known or is_suppressed(sup, ln, "high-entropy-string"):
            continue
        ctx = lines[ln - 1] if 0 < ln <= len(lines) else ""
        if not re.search(r"(?i)(key|secret|token|pass|pwd|auth|salt|sign|cred|hash|iv|api)", ctx) and HEXY.match(s):
            continue
        out.append(Finding("high-entropy-string", "medium", "secrets", rel, ln,
                           f"High-entropy string (H={h:.2f}) — likely a secret",
                           ctx.strip()[:220], "CWE-798", "Move to env / secret store", "entropy"))
    return out


# ============================== ENGINE: TAINT ==============================
SOURCES = {
    "py": [r"\brequest\.(?:args|form|values|json|data|cookies|headers|files|get_json)\b",
           r"\brequest\.get\s*\(", r"\bsys\.argv\b", r"\bos\.environ\b", r"\binput\s*\(",
           r"\brequest\.query_params\b", r"\brequest\.path_params\b"],
    "php": [r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b", r"\$_FILES\b",
            r"\$_SERVER\[['\"]HTTP", r"\$argv\b", r"\bgetenv\s*\("],
    "js": [r"\breq\.(?:query|body|params|cookies|headers)\b",
           r"\brequest\.(?:query|body|params)\b", r"\bctx\.request\b",
           r"\bwindow\.location\b", r"\bdocument\.(?:URL|cookie|referrer)\b",
           r"\bprocess\.argv\b", r"\bprocess\.env\b"],
    "rb": [r"\bparams\b", r"\brequest\.(?:params|query_parameters|body|headers)\b"],
    "java": [r"\bgetParameter\s*\(", r"\bgetHeader\s*\(", r"\bgetQueryString\s*\(", r"\bgetCookies\s*\("],
    "go": [r"\br\.URL\.Query\b", r"\br\.FormValue\b", r"\br\.Form\b", r"\br\.Body\b"],
}

SINKS = [
    ("sql", ["py"], [r"\.(?:execute|executemany|raw)\s*\("], "CWE-89", "SQL injection"),
    ("sql", ["php"], [r"(?:mysql_query|mysqli_query|->query|->exec)\s*\("], "CWE-89", "SQL injection"),
    ("sql", ["js", "ts"], [r"(?:\.query|\.execute|\.raw)\s*\("], "CWE-89", "SQL injection"),
    ("sql", ["rb"], [r"\.(?:where|find_by_sql|execute)\s*\("], "CWE-89", "SQL injection"),
    ("sql", ["java"], [r"\.(?:executeQuery|executeUpdate|createQuery)\s*\("], "CWE-89", "SQL injection"),
    ("cmd", ["py"], [r"\bos\.system\s*\(", r"subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True"], "CWE-78", "Command injection"),
    ("cmd", ["php"], [r"\b(?:shell_exec|system|exec|passthru|popen)\s*\("], "CWE-78", "Command injection"),
    ("cmd", ["js", "ts"], [r"child_process\.(?:exec|execSync)\s*\("], "CWE-78", "Command injection"),
    ("cmd", ["rb"], [r"\bsystem\s*\(|\bexec\s*\(|`"], "CWE-78", "Command injection"),
    ("xss", ["php"], [r"\b(?:echo|print)\b"], "CWE-79", "Reflected XSS"),
    ("xss", ["js", "ts"], [r"\.innerHTML\s*=", r"document\.write\s*\(", r"dangerouslySetInnerHTML"], "CWE-79", "DOM XSS"),
    ("xss", ["py"], [r"render_template_string\s*\(", r"mark_safe\s*\(", r"Markup\s*\("], "CWE-79", "XSS / SSTI"),
    ("path", ["php"], [r"\b(?:include|require|file_get_contents|readfile|fopen|unlink)\s*\(?\s*"], "CWE-22", "Path traversal / LFI"),
    ("path", ["py"], [r"\bopen\s*\(", r"\bos\.(?:remove|unlink|rename)\s*\("], "CWE-22", "Path traversal"),
    ("path", ["js", "ts"], [r"\bfs\.(?:readFile|readFileSync|createReadStream|unlink)\s*\("], "CWE-22", "Path traversal"),
]

SANITIZERS = {
    "sql": [r"\bint\s*\(", r"\bfloat\s*\(", r"\(int\)", r"\bintval\s*\(", r"filter_var\s*\(",
            r"\bparseInt\s*\(", r"\bNumber\s*\(", r"\bInteger\.parseInt"],
    "xss": [r"htmlspecialchars\s*\(", r"htmlentities\s*\(", r"\bescape\s*\(", r"DOMPurify",
            r"\.textContent\b", r"encodeURIComponent", r"html\.escape\s*\(", r"\be\s*\("],
    "path": [r"\bbasename\s*\(", r"\brealpath\s*\(", r"os\.path\.abspath", r"\bfnmatch\b"],
    "cmd": [r"escapeshellarg\s*\(", r"escapeshellcmd\s*\(", r"shlex\.quote", r"\bquote\s*\("],
}

ASSIGN = re.compile(r"""^\s*(?:let|var|const|my|our|local|\$)?\s*([A-Za-z_$][\w$]*)\s*(?:\.[\w\[\]'\"$]+)*\s*=\s*(?!=)""")


def _assigned(line):
    m = ASSIGN.match(line)
    return m.group(1) if m else None


def _var_re(v):
    return re.compile(r"(?<![\w$])" + re.escape(v) + r"(?![\w$])")


def engine_taint(path, root, min_sev):
    lang = lang_of(path)
    if lang not in SOURCES:
        return []
    try:
        text = path.read_text("utf-8", "replace")
    except OSError:
        return []
    if len(text) > MAX_SIZE:
        return []
    lines = text.splitlines()
    rel = str(path.relative_to(root))
    sup = suppressed_lines(text)

    src_pats = [(_rx(p), p) for p in SOURCES[lang]]
    sinks = [(k, [_rx(p) for p in pats], cwe, msg)
             for k, langs, pats, cwe, msg in SINKS if lang in langs]
    if not sinks:
        return []

    taint = {}          # var -> {"line":n, "src":str, "kinds":set(), "safe":set()}

    def scan_line(i, line):
        for rx, pat in src_pats:
            m = rx.search(line)
            if m:
                return m.group(0)[:40]
        return None

    # pass 1 — direct sources
    for i, line in enumerate(lines, 1):
        s = scan_line(i, line)
        if not s:
            continue
        v = _assigned(line)
        if v:
            taint[v] = {"line": i, "src": s, "kinds": set(k for k, *_ in sinks), "safe": set()}

    # pass 2 — propagation (3 rounds)
    for _ in range(3):
        for i, line in enumerate(lines, 1):
            v = _assigned(line)
            if not v:
                continue
            hits = [t for t, d in taint.items() if t != v and _var_re(t).search(line)]
            if not hits:
                continue
            kinds, safe, origin = set(), set(), None
            for t in hits:
                kinds |= taint[t]["kinds"]
                safe |= taint[t]["safe"]
                origin = origin or taint[t]["line"]
            for k, pats in SANITIZERS.items():
                if any(_rx(p).search(line) for p in pats):
                    safe.add(k)
            if v not in taint or len(kinds) > len(taint[v]["kinds"]):
                taint[v] = {"line": i, "src": f"via {hits[0]}", "kinds": kinds, "safe": safe, "origin": origin}

    # pass 3 — sinks
    out = []
    for i, line in enumerate(lines, 1):
        if line.strip().startswith(("#", "//")):
            continue
        for kind, pats, cwe, msg in sinks:
            if not any(p.search(line) for p in pats):
                continue
            for v, d in taint.items():
                if not _var_re(v).search(line):
                    continue
                if kind in d["safe"]:
                    continue
                rule = f"taint-{kind}"
                if is_suppressed(sup, i, rule):
                    continue
                src_line = d["line"]
                if src_line == i:
                    continue
                out.append(Finding(
                    rule, "high", {"sql": "injection", "cmd": "injection", "xss": "xss",
                                   "path": "path"}[kind], rel, i,
                    f"{msg} — {d['src']} (line {src_line}) reaches this sink unescaped",
                    line.strip()[:220], cwe, "Use parameterised queries / escaping / basename()",
                    "taint", "high",
                    path=[{"line": src_line, "code": lines[src_line - 1].strip()[:160]},
                          {"line": i, "code": line.strip()[:160]}],
                ))
                break
    return out


# ============================== ENGINE: ARTIFACTS ==============================
ARTIFACTS = [
    (".git/config", "high", "Git repo exposed — full source and history leak", "Deny .git at the web server"),
    (".env", "critical", ".env present in the tree", "Ensure it is not web-accessible"),
    (".env.local", "high", "Local env file present", ""),
    ("id_rsa", "critical", "SSH private key deployed", ""),
    ("wp-config.php.bak", "critical", "WP config backup — DB creds in plaintext", ""),
    (".htpasswd", "high", "htpasswd — crackable hashes", ""),
    ("phpinfo.php", "medium", "phpinfo() left in production", ""),
    (".DS_Store", "info", "macOS metadata", ""),
    ("Thumbs.db", "info", "Windows metadata", ""),
]
ARTIFACT_GLOBS = [
    ("*.bak", "high", "Backup file — often served as plain text", "Block *.bak server-side"),
    ("*.old", "medium", "Old file left behind", ""),
    ("*.orig", "medium", "Merge artifact", ""),
    ("*.save", "medium", "Editor save file", ""),
    ("*.swp", "low", "Vim swap file", ""),
    ("*.sql", "high", "Raw SQL dump — entire database", "Move out of webroot"),
    ("*.sql.gz", "high", "Compressed SQL dump", ""),
    ("*.zip", "medium", "Archive in the tree", ""),
    ("*.tar.gz", "medium", "Archive in the tree", ""),
    ("*~", "low", "Editor backup", ""),
    ("*.log", "low", "Log file may leak paths and tokens", ""),
    ("*.pem", "high", "Certificate/key file in the tree", ""),
]


def engine_artifacts(root):
    out = []
    for rel, sev, msg, fix in ARTIFACTS:
        if (root / rel).exists():
            out.append(Finding("artifact:" + rel, sev, "artifacts", rel, 0, msg, rel, "CWE-538", fix, "artifacts"))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            p = Path(dirpath) / f
            for pat, sev, msg, fix in ARTIFACT_GLOBS:
                if p.match(pat):
                    out.append(Finding("artifact:" + pat, sev, "artifacts", str(p.relative_to(root)), 0,
                                       msg, p.name, "CWE-538", fix, "artifacts"))
                    break
    return out[:100]


# ============================== ENGINE: DEPENDENCIES ==============================
def _pip(t):
    return [("PyPI", m.group(1), m.group(2)) for m in
            re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)", t, re.M)]


def _pkgjson(t):
    out = []
    try:
        d = json.loads(t)
    except Exception:
        return out
    for sec in ("dependencies", "devDependencies"):
        for n, v in (d.get(sec) or {}).items():
            v = re.sub(r"^[\^~>=<\s]+", "", str(v)).split(" ")[0]
            if re.match(r"^[0-9]", v):
                out.append(("npm", n, v))
    return out


def _composer(t):
    out = []
    try:
        d = json.loads(t)
    except Exception:
        return out
    for sec in ("require", "require-dev"):
        for n, v in (d.get(sec) or {}).items():
            v = re.sub(r"^[\^~>=<\s]+", "", str(v)).split(" ")[0].split("|")[0]
            if re.match(r"^[0-9]", v):
                out.append(("Packagist", n, v))
    return out


def _gemlock(t):
    return [("RubyGems", m.group(1), m.group(2))
            for m in re.finditer(r"^\s{4}([A-Za-z0-9_\-]+)\s\(([0-9][^\)]*)\)", t, re.M)]


def _gomod(t):
    return [("Go", m.group(1), m.group(2).lstrip("v"))
            for m in re.finditer(r"^\s*([\w.\-]+/[\w.\-/]+)\s+v([0-9][\w.\-+]*)", t, re.M)]


def _cargo(t):
    out = []
    for blk in t.split("[[package]]")[1:]:
        n = re.search(r'name\s*=\s*"([^"]+)"', blk)
        v = re.search(r'version\s*=\s*"([^"]+)"', blk)
        if n and v:
            out.append(("crates.io", n.group(1), v.group(1)))
    return out


MANIFESTS = {"requirements.txt": _pip, "package.json": _pkgjson, "composer.json": _composer,
             "Gemfile.lock": _gemlock, "go.mod": _gomod, "Cargo.lock": _cargo}


def osv_lookup(pairs, timeout=30, verbose=True):
    import urllib.request
    out = []
    for i in range(0, len(pairs), 200):
        chunk = pairs[i:i + 200]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": e}, "version": v}
                                       for e, n, v in chunk]}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.load(r)
        except Exception as ex:
            if verbose:
                print(f"  ! OSV unreachable ({ex}) — skipping dependency CVEs", file=sys.stderr)
            return out
        for (e, n, v), res in zip(chunk, data.get("results", [])):
            for vuln in (res.get("vulns") or []):
                out.append((e, n, v, vuln))
    return out


def _sev_from_osv(vuln):
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.lower() in ("critical", "high", "moderate", "medium", "low"):
        return {"moderate": "medium"}.get(ds.lower(), ds.lower())
    for s in (vuln.get("severity") or []):
        m = re.search(r"/([0-9.]+)$", s.get("score", ""))
        if m:
            v = float(m.group(1))
            return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
    return "medium"


def engine_deps(root, verbose=True):
    pairs, origin = [], {}
    for name, fn in MANIFESTS.items():
        for p in root.rglob(name):
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            try:
                for e, n, v in fn(p.read_text("utf-8", "replace")):
                    pairs.append((e, n, v))
                    origin[(e, n, v)] = str(p.relative_to(root))
            except OSError:
                pass
    pairs = list(dict.fromkeys(pairs))
    if not pairs:
        return []
    if verbose:
        print(f"  OSV: checking {len(pairs)} packages...")
    out = []
    for e, n, v, vuln in osv_lookup(pairs, verbose=verbose):
        cve = next((a for a in (vuln.get("aliases") or []) if a.startswith("CVE-")), vuln.get("id", ""))
        out.append(Finding("dep:" + vuln.get("id", "?"), _sev_from_osv(vuln), "dependencies",
                           origin.get((e, n, v), "?"), 0,
                           f"{n}@{v} — {vuln.get('summary', cve)}", "", "CWE-1104",
                           f"Upgrade {n}", "osv", "high", [],
                           {"cve": cve, "advisory": vuln.get("id", "")}))
    return out


# ============================== ENGINE: EXTERNAL TOOLS ==============================
def _run(cmd, cwd, timeout=420):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout)
        return p.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def _have(x):
    return shutil.which(x) is not None


def eng_semgrep(root):
    if not _have("semgrep"):
        return []
    raw = _run(["semgrep", "--json", "--quiet", "--config", "auto", "--metrics", "off", "."], root)
    out = []
    try:
        for r in json.loads(raw).get("results", []):
            s = (r.get("extra", {}).get("severity") or "warning").lower()
            out.append(Finding("semgrep:" + r.get("check_id", "?"),
                               {"error": "high", "warning": "medium", "info": "info"}.get(s, "medium"),
                               "sast", r["path"], r["start"]["line"],
                               r.get("extra", {}).get("message", ""),
                               (r.get("extra", {}).get("lines", "") or "").strip()[:220],
                               "", "", "semgrep", "high"))
    except Exception:
        pass
    return out


def eng_bandit(root):
    if not _have("bandit"):
        return []
    raw = _run(["bandit", "-r", "-q", "-f", "json", "."], root)
    out = []
    try:
        for r in json.loads(raw).get("results", []):
            out.append(Finding("bandit:" + r.get("test_id", "?"),
                               r.get("issue_severity", "MEDIUM").lower(), "sast",
                               r["filename"], r.get("line_number", 0), r.get("issue_text", ""),
                               (r.get("code", "") or "").strip()[:220], "", "", "bandit", "high"))
    except Exception:
        pass
    return out


def eng_gitleaks(root):
    if not _have("gitleaks"):
        return []
    raw = _run(["gitleaks", "detect", "--no-git", "-f", "json", "-r", "-", "-s", "."], root)
    out = []
    try:
        for r in (json.loads(raw) or []):
            out.append(Finding("gitleaks:" + str(r.get("RuleID", "?")), "high", "secrets",
                               r.get("File", "?"), r.get("StartLine", 0),
                               r.get("Description", "secret"), str(r.get("Match", ""))[:120],
                               "CWE-798", "", "gitleaks", "high"))
    except Exception:
        pass
    return out


def eng_trivy(root):
    if not _have("trivy"):
        return []
    raw = _run(["trivy", "fs", "--format", "json", "--quiet", "-s", "vuln,secret,misconfig", "."], root)
    out = []
    try:
        for res in json.loads(raw).get("Results", []):
            for v in (res.get("Vulnerabilities") or []):
                out.append(Finding("trivy:" + v.get("VulnerabilityID", "?"),
                                   (v.get("Severity") or "MEDIUM").lower(), "dependencies",
                                   res.get("Target", "?"), 0,
                                   f"{v.get('PkgName')}@{v.get('InstalledVersion')} — {v.get('Title','')}",
                                   "", "CWE-1104", f"Upgrade to {v.get('FixedVersion','?')}",
                                   "trivy", "high", [], {"cve": v.get("VulnerabilityID", "")}))
            for m in (res.get("Misconfigurations") or []):
                out.append(Finding("trivy:" + m.get("ID", "?"),
                                   (m.get("Severity") or "MEDIUM").lower(), "config",
                                   res.get("Target", "?"), (m.get("CauseMetadata") or {}).get("StartLine", 0),
                                   m.get("Title", ""), "", "", m.get("Resolution", ""), "trivy", "medium"))
    except Exception:
        pass
    return out


def eng_gosec(root):
    if not _have("gosec"):
        return []
    raw = _run(["gosec", "-fmt=json", "-quiet", "./..."], root)
    out = []
    try:
        for i in json.loads(raw).get("Issues", []):
            out.append(Finding("gosec:" + i.get("rule_id", "?"), i.get("severity", "MEDIUM").lower(),
                               "sast", i.get("file", "?"), int(i.get("line", 0) or 0),
                               i.get("details", ""), (i.get("code", "") or "").strip()[:220],
                               "", "", "gosec", "medium"))
    except Exception:
        pass
    return out


EXTERNAL = [("semgrep", eng_semgrep), ("bandit", eng_bandit), ("gitleaks", eng_gitleaks),
            ("trivy", eng_trivy), ("gosec", eng_gosec)]


# ============================== SCORING / BASELINE ==============================
def dedupe(findings):
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: (SEV_ORDER[x.severity], x.file, x.line, x.rule)):
        k = (f.rule, f.file, f.line, f.message[:70])
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def score(findings):
    risk = sum(SEV_SCORE[f.severity] for f in findings)
    s = max(0.0, 100.0 - risk)
    g = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 55 else "D" if s >= 35 else "F"
    return round(s, 1), g, round(risk, 1)


def load_baseline(path):
    try:
        return set(json.loads(Path(path).read_text()).get("fps", []))
    except Exception:
        return set()


def save_baseline(path, findings):
    Path(path).write_text(json.dumps({"version": VERSION, "fps": sorted(f.fp for f in findings)}, indent=2))


def apply_baseline(findings, fps):
    for f in findings:
        if f.fp in fps:
            f.extra["baseline"] = True
    return [f for f in findings if f.fp not in fps]


# ============================== ORCHESTRATOR ==============================
ENGINES = {
    "rules": lambda p, r, m: engine_rules(p, r, m),
    "entropy": None,
    "taint": lambda p, r, m: engine_taint(p, r, m),
}


def scan(target: Path, cfg: dict, progress=None):
    t0 = time.time()
    findings = []
    min_sev = cfg.get("min_severity", "info")
    use = set(cfg.get("engines") or ["rules", "entropy", "taint", "artifacts", "deps"])

    if target.is_file():
        files = [target]
        root = target.parent
    else:
        root = target
        files = walk(root, set(cfg.get("exclude") or []), cfg.get("respect_gitignore", True))

    def tick(msg):
        if progress:
            progress(msg)

    tick(f"{len(files)} files")
    done = 0
    secret_keys = set()

    def work(p):
        nonlocal done
        res = []
        if "rules" in use:
            res += engine_rules(p, root, min_sev)
        if "taint" in use:
            res += engine_taint(p, root, min_sev)
        done += 1
        if progress and done % 40 == 0:
            progress(f"{done}/{len(files)} files")
        return res

    with ThreadPoolExecutor(max_workers=cfg.get("jobs", 8)) as ex:
        for r in ex.map(work, files):
            findings += r

    if "entropy" in use:
        secret_keys = {(f.file, f.line) for f in findings if f.category == "secrets"}
        for p in files:
            findings += engine_entropy(p, root, secret_keys)

    if "artifacts" in use and target.is_dir():
        tick("artifacts")
        findings += engine_artifacts(root)

    if "deps" in use and not cfg.get("no_deps") and target.is_dir():
        tick("dependencies")
        findings += engine_deps(root, verbose=not cfg.get("quiet"))

    if cfg.get("tools"):
        for name, fn in EXTERNAL:
            tick(name)
            findings += fn(root)

    findings = [f for f in findings if SEV_ORDER[f.severity] <= SEV_ORDER[min_sev]]
    findings = dedupe(findings)
    return findings, root, time.time() - t0