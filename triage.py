"""LLM triage — false-positive filtering, logic review, auto-fix. Venice API."""

from __future__ import annotations
import json, os, re, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor

API = os.environ.get("VENICE_API_URL", "https://api.venice.ai/api/v1/chat/completions")
KEY = os.environ.get("VENICE_API_KEY", "")
MODEL = os.environ.get("scanee_MODEL", "llama-3.3-70b")


def _chat(messages, model=None, json_mode=True, timeout=120, max_tokens=2000):
    if not KEY:
        raise RuntimeError("VENICE_API_KEY not set")
    body = {"model": model or MODEL, "messages": messages,
            "temperature": 0.1, "max_tokens": max_tokens}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(API, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + KEY})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.load(r)
    return d["choices"][0]["message"]["content"]


def _ctx(root, f, span=6):
    try:
        lines = (root / f.file).read_text("utf-8", "replace").splitlines()
    except OSError:
        return f.snippet
    a, b = max(0, f.line - 1 - span), min(len(lines), f.line + span)
    return "\n".join(f"{i+1:>5}| {lines[i]}" for i in range(a, b))


TRIAGE_PROMPT = """You are a senior application security engineer reviewing static-analysis findings.

For each finding decide:
- "true_positive": is this a real exploitable issue in the given code?
- "confidence": 0.0-1.0
- "severity": critical|high|medium|low|info  (adjust if the tool got it wrong)
- "reason": one short sentence
- "fix": a concrete one-line fix, or "" if none

Be strict: downgrade or drop findings that are clearly safe in context
(constants, already-sanitised values, test code, framework guarantees).
Reply with JSON: {"verdicts":[{"i":0,"true_positive":true,"confidence":0.9,"severity":"high","reason":"...","fix":"..."}]}"""


def triage(findings, root, batch=10, workers=4):
    if not KEY:
        return findings
    todo = [f for f in findings if f.tool in ("rules", "entropy", "taint")][:120]
    if not todo:
        return findings

    def do(chunk, offset):
        items = []
        for i, f in enumerate(chunk):
            items.append(f"--- finding {i} ---\nrule: {f.rule}\nseverity: {f.severity}\n"
                         f"file: {f.file}:{f.line}\nmessage: {f.message}\ncode:\n{_ctx(root, f)}")
        try:
            raw = _chat([{"role": "system", "content": TRIAGE_PROMPT},
                         {"role": "user", "content": "\n\n".join(items)}])
            return offset, json.loads(raw).get("verdicts", [])
        except Exception as e:
            print(f"  ! triage batch failed: {e}", file=sys.stderr)
            return offset, []

    chunks = [(todo[i:i + batch], i) for i in range(0, len(todo), batch)]
    verdicts = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for offset, vs in ex.map(lambda c: do(*c), chunks):
            for v in vs:
                verdicts[offset + v.get("i", 0)] = v

    out = []
    for i, f in enumerate(todo):
        v = verdicts.get(i)
        if not v:
            out.append(f)
            continue
        if not v.get("true_positive", True):
            f.extra["dropped_reason"] = v.get("reason", "")
            f.extra["confidence"] = v.get("confidence", 0)
            if v.get("confidence", 0) >= 0.65:
                continue
        if v.get("severity") in ("critical", "high", "medium", "low", "info"):
            f.severity = v["severity"]
        if v.get("fix"):
            f.fix = v["fix"]
        f.confidence = "high" if v.get("confidence", 0) > 0.75 else "medium"
        f.extra["ai_reason"] = v.get("reason", "")
        out.append(f)
    return out + [f for f in findings if f not in todo]


LOGIC_PROMPT = """You are a security auditor. Read this file and list logic-level
security flaws that pattern-matching tools miss: broken access control, missing
ownership checks, IDOR, race conditions, unvalidated redirects, missing rate
limits, privilege escalation, insecure state handling.

Reply JSON: {"flaws":[{"line":N,"severity":"high|medium|low","title":"...","why":"...","fix":"..."}]}
Only real issues. Empty list is fine."""


def logic_review(root, files, limit=25):
    if not KEY:
        return []
    from core import Finding
    cands = []
    for p in files:
        try:
            t = p.read_text("utf-8", "replace")
        except OSError:
            continue
        if 200 < len(t) < 60000 and re.search(r"(route|view|controller|handler|app\.(get|post)|def |function )", t):
            cands.append(p)
    cands = cands[:limit]
    if not cands:
        return []

    def one(p):
        rel = str(p.relative_to(root))
        try:
            raw = _chat([{"role": "system", "content": LOGIC_PROMPT},
                         {"role": "user", "content": f"file: {rel}\n\n{p.read_text('utf-8','replace')[:24000]}"}])
            flaws = json.loads(raw).get("flaws", [])
        except Exception:
            return []
        return [Finding("logic:" + re.sub(r"\W+", "-", f.get("title", "flaw").lower())[:40],
                        f.get("severity", "medium"), "logic", rel, int(f.get("line", 0) or 0),
                        f.get("title", "") + " — " + f.get("why", ""), "", "", f.get("fix", ""),
                        "llm", "medium") for f in flaws]

    out = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(one, cands):
            out += r
    return out


FIX_PROMPT = """Fix the security issue below with the smallest possible change.
Reply JSON: {"code":"<the corrected lines only>","note":"<what you changed, one line>"}"""


def autofix(root, finding, span=12):
    if not KEY:
        return None
    try:
        lines = (root / finding.file).read_text("utf-8", "replace").splitlines()
    except OSError:
        return None
    a, b = max(0, finding.line - 1 - span), min(len(lines), finding.line + span)
    block = "\n".join(lines[a:b])
    try:
        raw = _chat([{"role": "system", "content": FIX_PROMPT},
                     {"role": "user", "content": f"issue: {finding.message}\nrule: {finding.rule}\n"
                                                 f"file: {finding.file}\ncode:\n{block}"}])
        return json.loads(raw)
    except Exception:
        return None