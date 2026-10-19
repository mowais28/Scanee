"""Report writers: html, sarif, json, md, terminal."""
from __future__ import annotations
import html, json
from collections import Counter
from pathlib import Path
from core import SEV_ORDER, score

C = {"critical": "#ff4d4d", "high": "#ff8c42", "medium": "#ffd93d", "low": "#6bcb77", "info": "#6e7681"}


def cwe_url(c):
    return f"https://cwe.mitre.org/data/definitions/{c[4:]}.html" if c and c.startswith("CWE-") else ""


def render_json(findings, root, elapsed):
    s, g, risk = score(findings)
    return json.dumps({"version": "2.0.0", "root": str(root), "elapsed": round(elapsed, 2),
                       "score": s, "grade": g, "risk": risk,
                       "summary": dict(Counter(f.severity for f in findings)),
                       "findings": [{"rule": f.rule, "severity": f.severity, "category": f.category,
                                     "file": f.file, "line": f.line, "message": f.message,
                                     "snippet": f.snippet, "cwe": f.cwe, "fix": f.fix,
                                     "tool": f.tool, "confidence": f.confidence,
                                     "path": f.path, "extra": f.extra} for f in findings]}, indent=2)


def render_md(findings, root):
    s, g, _ = score(findings)
    out = [f"# Security Report\n", f"**Grade {g}** · score {s}/100 · {len(findings)} findings\n",
           f"`{root}`\n"]
    for sev in ("critical", "high", "medium", "low", "info"):
        grp = [f for f in findings if f.severity == sev]
        if not grp:
            continue
        out.append(f"\n## {sev.upper()} ({len(grp)})\n")
        for f in grp:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            out.append(f"- **{f.message}** — `{loc}`")
            if f.fix:
                out.append(f"  - _fix:_ {f.fix}")
            if f.cwe:
                out.append(f"  - {f.cwe} · {cwe_url(f.cwe)}")
    return "\n".join(out)


def render_sarif(findings, root):
    rules, idx, results = [], {}, []
    for f in findings:
        if f.rule not in idx:
            idx[f.rule] = len(rules)
            rules.append({"id": f.rule, "name": f.rule,
                          "shortDescription": {"text": f.message[:200]},
                          "helpUri": cwe_url(f.cwe) or "https://owasp.org/www-project-top-ten/",
                          "properties": {"security-severity": f.cvss(), "tags": [f.category]}})
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.file}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": max(1, f.line), "snippet": {"text": f.snippet[:400]}}
        results.append({"ruleId": f.rule, "ruleIndex": idx[f.rule],
                        "level": {"critical": "error", "high": "error", "medium": "warning",
                                  "low": "note", "info": "note"}[f.severity],
                        "message": {"text": f.message + (f"\n\nFix: {f.fix}" if f.fix else "")},
                        "locations": [loc],
                        "properties": {"confidence": f.confidence, "tool": f.tool}})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "scanee", "version": "2.0.0",
                                                     "informationUri": "https://github.com/",
                                                     "rules": rules}},
                                 "results": results}]}, indent=2)


def render_terminal(findings, root, elapsed):
    try:
        from colorama import init; init()
    except ImportError:
        pass
    A = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m",
         "low": "\033[92m", "info": "\033[90m"}
    R = "\033[0m"; B = "\033[1m"; D = "\033[90m"
    c = Counter(f.severity for f in findings)
    s, g, _ = score(findings)
    out = [f"\n{B}scanee{R} {D}{root}{R}\n"]
    for sev in ("critical", "high", "medium", "low", "info"):
        if c.get(sev):
            out.append(f"  {A[sev]}{c[sev]:>4} {sev.upper()}{R}")
    out.append(f"\n  grade {B}{g}{R}  score {s}/100   {D}{len(findings)} findings in {elapsed:.1f}s{R}\n")
    for f in findings:
        if SEV_ORDER[f.severity] > 2:
            continue
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out.append(f"  {A[f.severity]}{f.severity[:4].upper():<4}{R} {f.message[:74]}")
        out.append(f"       {D}{loc}{R}")
    return "\n".join(out)


CSS = """
*{box-sizing:border-box}
body{background:#080b10;color:#c9d1d9;font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0}
.w{max-width:1180px;margin:0 auto;padding:32px 24px 80px}
h1{font-size:26px;margin:0 0 2px;letter-spacing:-.5px}
.sub{color:#5a6472;font-size:13px;font-family:ui-monospace,monospace;word-break:break-all}
.top{display:flex;gap:26px;align-items:center;flex-wrap:wrap;margin:24px 0 30px;background:#0d1218;border:1px solid #1c232c;border-radius:14px;padding:22px}
.ring{position:relative;width:112px;height:112px;flex-shrink:0}
.ring svg{transform:rotate(-90deg)}
.ring .val{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .val b{font-size:30px;line-height:1}
.ring .val span{font-size:10px;color:#5a6472;letter-spacing:.1em}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:10px;flex:1;min-width:280px}
.st{background:#0a0e13;border:1px solid #1c232c;border-radius:9px;padding:11px 13px}
.st b{display:block;font-size:21px;line-height:1.2}
.st span{font-size:10px;color:#5a6472;text-transform:uppercase;letter-spacing:.08em}
.bar{display:flex;gap:7px;margin-bottom:18px;flex-wrap:wrap;align-items:center}
.bar button,.bar input{background:#0d1218;color:#c9d1d9;border:1px solid #1c232c;padding:6px 13px;border-radius:7px;cursor:pointer;font-size:12.5px;font-family:inherit}
.bar button:hover{background:#161e27;border-color:#2d3743}
.bar button.on{background:#1f6feb22;border-color:#1f6feb;color:#79b8ff}
.bar input{cursor:text;min-width:190px}
.f{border:1px solid #1c232c;border-left:3px solid #444;border-radius:9px;margin-bottom:7px;background:#0b1015;overflow:hidden;transition:border-color .12s}
.f:hover{border-color:#2d3743}
.f.critical{border-left-color:#ff4d4d}.f.high{border-left-color:#ff8c42}
.f.medium{border-left-color:#ffd93d}.f.low{border-left-color:#6bcb77}.f.info{border-left-color:#3d4752}
.h{padding:11px 15px;cursor:pointer;display:flex;gap:11px;align-items:baseline}
.h:hover{background:#0e141a}
.bdg{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:3px 7px;border-radius:4px;background:#161e27;flex-shrink:0}
.f.critical .bdg{background:#ff4d4d22;color:#ff8080}.f.high .bdg{background:#ff8c4222;color:#ffab6b}
.f.medium .bdg{background:#ffd93d22;color:#ffd93d}.f.low .bdg{background:#6bcb7722;color:#6bcb77}
.msg{flex:1}.loc{color:#58a6ff;font-size:12px;font-family:ui-monospace,monospace;flex-shrink:0}
.d{padding:0 15px 14px;display:none;font-size:13px}
.d.open{display:block}
pre{background:#05080c;border:1px solid #161e27;border-radius:7px;padding:11px;overflow:auto;font-size:12px;font-family:ui-monospace,monospace;margin:9px 0;color:#8b949e;max-height:340px}
.fix{color:#6bcb77;font-size:12.5px;margin-top:7px}
.meta{color:#5a6472;font-size:11px;font-family:ui-monospace,monospace;display:flex;gap:12px;flex-wrap:wrap}
.meta a{color:#58a6ff;text-decoration:none}
.tp{background:#05080c;border:1px dashed #2d3743;border-radius:7px;padding:9px;margin:9px 0;font-family:ui-monospace,monospace;font-size:11.5px}
.tp .arrow{color:#ff8c42;padding-left:18px}
.ai{background:#1f6feb11;border-left:2px solid #1f6feb;padding:8px 11px;border-radius:5px;font-size:12.5px;margin:8px 0;color:#9fb6cd}
.empty{text-align:center;padding:70px 20px;color:#5a6472}
.baseline{opacity:.45}
"""


def render_html(findings, root, elapsed, meta=None):
    meta = meta or {}
    c = Counter(f.severity for f in findings)
    s, g, risk = score(findings)
    cats = Counter(f.category for f in findings)
    tools = Counter(f.tool for f in findings)
    e = html.escape
    col = C["critical"] if s < 55 else C["high"] if s < 75 else C["medium"] if s < 90 else C["low"]
    circ = 2 * 3.14159 * 48
    h = [f"""<!doctype html><html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — grade {g}</title><style>{CSS}</style><div class="w">
<h1>Security Report</h1>
<div class="sub">{e(str(root))} · {len(findings)} findings · {elapsed:.1f}s · {e(meta.get('when',''))}</div>
<div class="top">
<div class="ring"><svg width="112" height="112"><circle cx="56" cy="56" r="48" fill="none" stroke="#161e27" stroke-width="9"/>
<circle cx="56" cy="56" r="48" fill="none" stroke="{col}" stroke-width="9" stroke-linecap="round"
 stroke-dasharray="{circ:.1f}" stroke-dashoffset="{circ*(1-s/100):.1f}"/></svg>
<div class="val"><b style="color:{col}">{g}</b><span>GRADE</span></div></div>
<div class="stats">
<div class="st"><b style="color:{C['critical']}">{c.get('critical',0)}</b><span>critical</span></div>
<div class="st"><b style="color:{C['high']}">{c.get('high',0)}</b><span>high</span></div>
<div class="st"><b style="color:{C['medium']}">{c.get('medium',0)}</b><span>medium</span></div>
<div class="st"><b style="color:{C['low']}">{c.get('low',0)}</b><span>low</span></div>
<div class="st"><b style="color:{C['info']}">{c.get('info',0)}</b><span>info</span></div>
<div class="st"><b>{s:.0f}</b><span>score /100</span></div>
<div class="st"><b>{risk:.0f}</b><span>risk pts</span></div>
</div></div>
<div class="sub" style="margin-bottom:18px">categories: {' · '.join(f'{e(k)} {v}' for k,v in cats.most_common())}
<br>engines: {' · '.join(f'{e(k)} {v}' for k,v in tools.most_common())}</div>
<div class="bar"><button class="on" data-f="all">all</button>"""]
    for sev in ("critical", "high", "medium", "low", "info"):
        h.append(f'<button data-f="{sev}">{sev} ({c.get(sev,0)})</button>')
    h.append('<input id="q" placeholder="search rule / file / message...">')
    h.append('<button data-f="hideai">hide AI-dropped</button></div>')

    if not findings:
        h.append('<div class="empty">No findings. Ship it.</div>')

    for f in findings:
        cwe = f'<a href="{cwe_url(f.cwe)}" target="_blank">{e(f.cwe)}</a>' if f.cwe else ""
        loc = f"{e(f.file)}{':' + str(f.line) if f.line else ''}"
        base = ' baseline' if f.extra.get("baseline") else ''
        h.append(f'<div class="f {f.severity}{base}" data-sev="{f.severity}" data-tool="{e(f.tool)}" '
                 f'data-txt="{e((f.rule+" "+f.file+" "+f.message).lower())}">'
                 f'<div class="h" onclick="this.nextElementSibling.classList.toggle(\'open\')">'
                 f'<span class="bdg">{f.severity}</span><span class="msg">{e(f.message)}</span>'
                 f'<span class="loc">{loc}</span></div><div class="d">'
                 f'<div class="meta"><span>{e(f.rule)}</span><span>{e(f.category)}</span>'
                 f'<span>via {e(f.tool)}</span><span>conf {e(f.confidence)}</span>{cwe}</div>')
        if f.path:
            h.append('<div class="tp">')
            for i, step in enumerate(f.path):
                if i:
                    h.append('<div class="arrow">↓</div>')
                h.append(f'<div>line {step["line"]}: {e(step["code"])}</div>')
            h.append('</div>')
        elif f.snippet:
            h.append(f'<pre>{e(f.snippet)}</pre>')
        if f.extra.get("ai_reason"):
            h.append(f'<div class="ai">AI: {e(f.extra["ai_reason"])}</div>')
        if f.extra.get("dropped_reason"):
            h.append(f'<div class="ai">AI dropped: {e(f.extra["dropped_reason"])}</div>')
        if f.extra.get("cve"):
            h.append(f'<div class="meta"><span>{e(f.extra["cve"])}</span>'
                     f'<a href="https://osv.dev/vulnerability/{e(f.extra.get("advisory",""))}" target="_blank">advisory</a></div>')
        if f.fix:
            h.append(f'<div class="fix">fix → {e(f.fix)}</div>')
        h.append('</div></div>')

    h.append("""</div><script>
var sev='all';
function apply(){
  document.querySelectorAll('.f').forEach(function(x){
    var ok = (sev==='all' || x.dataset.sev===sev);
    if(sev==='hideai' && x.dataset.tool!=='llm') ok = !!x.querySelector('.ai');
    if(sev==='hideai'){ ok = !x.innerText.includes('AI dropped'); }
    var q=document.getElementById('q').value.toLowerCase();
    if(q && x.dataset.txt.indexOf(q)<0) ok=false;
    x.style.display = ok?'':'none';
  });
}
document.querySelectorAll('.bar button[data-f]').forEach(function(b){
  b.onclick=function(){
    sev=b.dataset.f;
    document.querySelectorAll('.bar button[data-f]').forEach(function(y){y.classList.remove('on')});
    b.classList.add('on'); apply();
  };
});
document.getElementById('q').oninput=apply;
document.querySelectorAll('.d').forEach(function(d,i){ if(i<4) d.classList.add('open'); });
</script></html>""")
    return "".join(h)