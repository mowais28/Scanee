"""scanee dashboard — live SSE progress."""
from __future__ import annotations
import json, os, queue, tempfile, threading, zipfile
from datetime import datetime
from pathlib import Path
from flask import Flask, Response, request, redirect, url_for

import core, report

app = Flask(__name__)
JOBS = {}


def run_job(jid, target, cfg):
    q = JOBS[jid]
    try:
        findings, root, elapsed = core.scan(Path(target), cfg, progress=lambda m: q.put(("log", m)))
        html = report.render_html(findings, root, elapsed, {"when": datetime.now().strftime("%d %b %H:%M")})
        q.put(("done", {"html": html, "count": len(findings)}))
    except Exception as e:
        q.put(("error", str(e)))
    q.put(("end", None))


@app.route("/")
def index():
    return PAGE


@app.route("/scan", methods=["POST"])
def start():
    import uuid
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = queue.Queue()
    target = (request.form.get("path") or "").strip()
    if request.files.get("code"):
        tmp = tempfile.mkdtemp(prefix="vs_")
        zp = os.path.join(tmp, "u.zip")
        request.files["code"].save(zp)
        with zipfile.ZipFile(zp) as z:
            for m in z.namelist():
                if ".." not in m:
                    z.extract(m, tmp)
        os.unlink(zp)
        entries = os.listdir(tmp)
        target = os.path.join(tmp, entries[0]) if len(entries) == 1 and os.path.isdir(os.path.join(tmp, entries[0])) else tmp
    if not target or not os.path.exists(target):
        return {"error": f"not found: {target}"}, 400
    cfg = {"engines": ["rules", "entropy", "taint", "artifacts", "deps"],
           "min_severity": "info", "tools": request.form.get("tools") == "1", "quiet": True}
    threading.Thread(target=run_job, args=(jid, target, cfg), daemon=True).start()
    return {"job": jid}


@app.route("/stream/<jid>")
def stream(jid):
    q = JOBS.get(jid)
    if not q:
        return Response("data: {\"error\":\"no job\"}\n\n", mimetype="text/event-stream")

    def gen():
        while True:
            kind, payload = q.get()
            if kind == "end":
                yield f"event: end\ndata: {{}}\n\n"
                break
            if kind == "log":
                yield f"event: log\ndata: {json.dumps(payload)}\n\n"
            elif kind == "done":
                yield "event: done\ndata: " + json.dumps({"count": payload["count"]}) + "\n\n"
                yield "event: html\ndata: " + json.dumps(payload["html"]) + "\n\n"
            elif kind == "error":
                yield f"event: error\ndata: {json.dumps(payload)}\n\n"
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>scanee</title><style>
body{background:#080b10;color:#c9d1d9;font:14px/1.6 -apple-system,Segoe UI,sans-serif;margin:0}
.w{max-width:640px;margin:70px auto;padding:0 20px}
h1{font-size:27px;margin:0 0 4px;letter-spacing:-.5px}
.sub{color:#5a6472;font-size:13px;margin-bottom:26px}
.box{background:#0d1218;border:1px solid #1c232c;border-radius:13px;padding:22px;margin-bottom:14px}
input[type=text]{width:100%;background:#05080c;color:#c9d1d9;border:1px solid #1c232c;padding:11px;border-radius:8px;font:inherit}
button{background:#1f6feb;color:#fff;border:0;padding:11px 22px;border-radius:8px;cursor:pointer;font:inherit;font-weight:600;margin-top:12px}
button:hover{background:#2b7fff}button:disabled{background:#1c232c;color:#5a6472}
.or{text-align:center;color:#5a6472;margin:16px 0;font-size:12px}
label{font-size:12px;color:#5a6472}
#log{background:#05080c;border:1px solid #1c232c;border-radius:8px;padding:11px;font-family:ui-monospace,monospace;font-size:12px;height:130px;overflow:auto;display:none;color:#6bcb77}
#out{margin-top:14px}
.sp{width:13px;height:13px;border:2px solid #1c232c;border-top-color:#1f6feb;border-radius:50%;
display:inline-block;animation:s .7s linear infinite;vertical-align:-2px;margin-right:7px}
@keyframes s{to{transform:rotate(360deg)}}
</style><div class=w><h1>scanee</h1><div class=sub>upload a zip, or point at a path on this machine</div>
<div class=box><form id=f enctype=multipart/form-data>
<b style="font-size:13px">Upload</b><br><br><input type=file name=code accept=.zip>
<div class=or>— or —</div>
<b style="font-size:13px">Server path</b><br><br><input type=text name=path placeholder="/var/www/app">
<br><label><input type=checkbox name=tools value=1> also run semgrep / bandit / gitleaks / trivy</label>
<br><button id=b>scan</button></form></div>
<div id=log></div><div id=out></div></div>
<script>
var f=document.getElementById('f');
f.onsubmit=async function(e){
  e.preventDefault();
  document.getElementById('b').disabled=true;
  document.getElementById('out').innerHTML='<div class=box><span class=sp></span>scanning…</div>';
  var log=document.getElementById('log'); log.style.display='block'; log.innerHTML='';
  var r=await fetch('/scan',{method:'POST',body:new FormData(f)});
  var j=await r.json();
  if(j.error){document.getElementById('out').innerHTML='<div class=box>'+j.error+'</div>';
    document.getElementById('b').disabled=false;return;}
  var es=new EventSource('/stream/'+j.job);
  es.addEventListener('log',function(e){log.innerHTML+=JSON.parse(e.data)+'<br>';log.scrollTop=1e9;});
  es.addEventListener('done',function(e){log.innerHTML+='<b>done — '+JSON.parse(e.data).count+' findings</b>';});
  es.addEventListener('html',function(e){
    var h=JSON.parse(e.data);
    document.open();document.write(h);document.close();
  });
  es.addEventListener('error',function(e){document.getElementById('out').innerHTML='<div class=box>'+e.data+'</div>';});
};
</script>"""


def run(host="127.0.0.1", port=8000):
    app.run(host=host, port=port, threaded=True, debug=False)


if __name__ == "__main__":
    run()