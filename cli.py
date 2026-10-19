#!/usr/bin/env python3
"""scanee — CLI."""
from __future__ import annotations
import argparse, json, os, sys, time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core, report

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_CFG = {
    "engines": ["rules", "entropy", "taint", "artifacts", "deps"],
    "min_severity": "info", "exclude": [], "tools": False,
    "respect_gitignore": True, "jobs": 8, "no_deps": False,
}


def load_cfg(path=".scanee.yml", overrides=None):
    cfg = dict(DEFAULT_CFG)
    p = Path(path)
    if p.is_file():
        if yaml:
            try:
                cfg.update(yaml.safe_load(p.read_text()) or {})
            except Exception as e:
                print(f"! bad config {p}: {e}", file=sys.stderr)
        else:
            print("! pyyaml not installed, ignoring .scanee.yml", file=sys.stderr)
    cfg.update(overrides or {})
    return cfg


def cmd_scan(a):
    cfg = load_cfg(a.config, {
        "min_severity": a.min_severity, "exclude": a.exclude, "tools": a.tools,
        "no_deps": a.no_deps, "quiet": a.quiet,
    })
    if a.ai:
        cfg["ai"] = True
    target = Path(a.path).resolve()
    if not target.exists():
        sys.exit(f"not found: {target}")

    def prog(m):
        if not a.quiet:
            print(f"  · {m}", file=sys.stderr)

    findings, root, elapsed = core.scan(target, cfg, prog)

    if a.ai:
        import triage
        prog("LLM triage...")
        findings = triage.triage(findings, root)
        if a.logic and target.is_dir():
            prog("LLM logic review...")
            findings += triage.logic_review(root, core.walk(root, set(cfg.get("exclude") or [])))
        findings = core.dedupe(findings)

    base_fps = core.load_baseline(a.baseline) if a.baseline else set()
    if a.baseline and Path(a.baseline).is_file():
        shown = core.apply_baseline(findings, base_fps)
    else:
        shown = findings
    if a.write_baseline:
        core.save_baseline(a.write_baseline, findings)

    shown = [f for f in shown if core.SEV_ORDER[f.severity] <= core.SEV_ORDER[a.min_severity]]

    if a.format == "json":
        Path(a.out).write_text(report.render_json(shown, root, elapsed))
    elif a.format == "sarif":
        Path(a.out).write_text(report.render_sarif(shown, root))
    elif a.format == "md":
        Path(a.out).write_text(report.render_md(shown, root))
    else:
        Path(a.out).write_text(report.render_html(shown, root, elapsed,
                                                  {"when": datetime.now().strftime("%Y-%m-%d %H:%M")}))
    if not a.quiet:
        print(report.render_terminal(shown, root, elapsed))
        print(f"\n  report → {a.out}\n")

    if a.fail_on:
        thr = core.SEV_ORDER[a.fail_on]
        if any(core.SEV_ORDER[f.severity] <= thr for f in shown):
            sys.exit(1)


def cmd_fix(a):
    import triage
    target = Path(a.path).resolve()
    findings, root, _ = core.scan(target, load_cfg(a.config, {"tools": False}))
    findings = [f for f in findings if f.file.endswith(tuple(a.only or [".py", ".php", ".js", ".ts", ".rb", ".java", ".go"]))]
    findings = [f for f in findings if core.SEV_ORDER[f.severity] <= 1][:a.limit]
    if not findings:
        sys.exit("nothing to fix")
    patches = []
    for f in findings:
        r = triage.autofix(root, f)
        if not r:
            continue
        patches.append(f"{'='*70}\n{f.severity.upper()} · {f.rule}\n{f.file}:{f.line}\n{f.message}\n"
                       f"{'-'*70}\n{r.get('code','')}\n{'-'*70}\nnote: {r.get('note','')}\n")
        print(f"  fixed {f.file}:{f.line} — {f.rule}")
    out = a.out or "scanee-fixes.txt"
    Path(out).write_text("\n".join(patches))
    print(f"\n{len(patches)} patches → {out}")


def cmd_init(a):
    if Path(".scanee.yml").exists() and not a.force:
        sys.exit(".scanee.yml already exists (use --force)")
    Path(".scanee.yml").write_text("""# scanee config
engines: [rules, entropy, taint, artifacts, deps]
min_severity: info
exclude:
  - "*.min.js"
  - "*/migrations/*"
  - "*/tests/*"
tools: false          # set true to also run semgrep/bandit/gitleaks/trivy/gosec
respect_gitignore: true
jobs: 8
no_deps: false

# llm:
#   enabled: true
#   model: llama-3.3-70b
""")
    print("wrote .scanee.yml")


def main():
    ap = argparse.ArgumentParser(prog="scanee", description="VIP static security scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a path")
    s.add_argument("path")
    s.add_argument("-o", "--out", default="scanee-report.html")
    s.add_argument("-f", "--format", choices=["html", "json", "sarif", "md"], default="html")
    s.add_argument("--min-severity", choices=list(core.SEV_ORDER), default="info")
    s.add_argument("--exclude", action="append", default=[])
    s.add_argument("--tools", action="store_true", help="run external scanners too")
    s.add_argument("--no-deps", action="store_true", help="skip OSV network lookup")
    s.add_argument("--ai", action="store_true", help="LLM triage (needs VENICE_API_KEY)")
    s.add_argument("--logic", action="store_true", help="LLM logic review (needs --ai)")
    s.add_argument("--baseline", default=".scanee-baseline.json")
    s.add_argument("--write-baseline", default=None)
    s.add_argument("--fail-on", choices=list(core.SEV_ORDER), default=None)
    s.add_argument("--config", default=".scanee.yml")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="LLM-generated patches")
    f.add_argument("path")
    f.add_argument("-o", "--out", default=None)
    f.add_argument("--limit", type=int, default=10)
    f.add_argument("--only", action="append", default=[])
    f.add_argument("--config", default=".scanee.yml")
    f.set_defaults(func=cmd_fix)

    i = sub.add_parser("init", help="write a default config")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    w = sub.add_parser("serve", help="web dashboard")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--host", default="127.0.0.1")
    w.set_defaults(func=lambda a: __import__("web").run(a.host, a.port))

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()