import json, os, subprocess, glob, threading, requests, re, time, random, hashlib, shlex, shutil
from flask import Flask, render_template, request, jsonify, Response, send_file, session
import io
from jailbreaks_data import JAILBREAKS, CATEGORIES
from challenges import CHALLENGES, run_challenge
from database import (init_db, save_jailbreak, save_scan_result, save_challenge_attempt,
                      save_challenge_solve, get_solved_challenges, get_user_attempts,
                      get_leaderboard, get_ctf_leaderboard, get_category_stats,
                      get_recent_activity, get_overall_stats,
                      check_and_award_achievements, get_user_achievements,
                      save_writeup, get_writeups,
                      save_quiz_score, get_quiz_leaderboard,
                      get_used_jb_categories, create_user, verify_user,
                      save_sandbox_solve, get_sandbox_solves, get_sandbox_leaderboard,
                      save_skilltree_score, get_skilltree_leaderboard,
                      save_aicode_flags, get_aicode_leaderboard,
                      get_soc_metrics)
import atlas_data
import sandbox

app = Flask(__name__)
# Session secret: persisted to disk so logins survive restarts. Override with SECRET_KEY env.
def _load_secret():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.expanduser("~/.local/share/garak/flask_secret")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return open(path).read().strip()
    secret = os.urandom(32).hex()
    open(path, "w").write(secret)
    return secret
app.secret_key = _load_secret()
init_db()


def current_user(data=None):
    """Resolve the acting username: logged-in session wins, else a posted/queried
    username (backward compatible with the pre-auth flow), else 'anonymous'."""
    if session.get("username"):
        return session["username"]
    if data and data.get("username"):
        return str(data["username"])[:20]
    qu = request.args.get("username")
    return str(qu)[:20] if qu else "anonymous"

GARAK_RUNS = os.path.expanduser("~/.local/share/garak/garak_runs")
scans = {
    "vulnerable": {"running": False, "lines": [], "prompts": []},
    "defended":   {"running": False, "lines": [], "prompts": []},
}

AVAILABLE_PROBES = [
    ("promptinject",  "Prompt Injection",     "Hijacks the LLM's task"),
    ("dan",           "DAN Jailbreaks",        "'Do Anything Now' bypasses"),
    ("apikey",        "API Key Leakage",       "Tricks LLM into revealing secrets"),
    ("continuation",  "Harmful Continuation",  "Gets LLM to complete harmful text"),
    ("encoding",      "Encoding Attacks",      "Base64/rot13/leetspeak bypasses"),
    ("ansiescape",    "ANSI Escape Injection", "Terminal control-char injection"),
    ("misleading",    "Misleading Claims",     "Gets LLM to assert false facts"),
    ("knownbadsignatures", "Known Bad Signatures", "Known malicious output patterns"),
]

PUBLIC_URL = None  # set by ngrok if enabled

_news_cache = {"data": None, "ts": 0}
NEWS_FEEDS = [
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews",  "tag": "general"},
    {"name": "Krebs on Security","url": "https://krebsonsecurity.com/feed/",             "tag": "breaches"},
    {"name": "Dark Reading",     "url": "https://www.darkreading.com/rss.xml",           "tag": "research"},
    {"name": "CyberScoop",       "url": "https://cyberscoop.com/feed/",                 "tag": "general"},
    {"name": "Schneier on Sec.", "url": "https://www.schneier.com/blog/atom.xml",        "tag": "research"},
    {"name": "Graham Cluley",    "url": "https://grahamcluley.com/feed/",                "tag": "general"},
]

_HTML_ENT = {
    'nbsp':' ','mdash':'-','ndash':'-','ldquo':'"','rdquo':'"','lsquo':"'",'rsquo':"'",
    'hellip':'...','bull':'•','middot':'·','copy':'©','reg':'®','trade':'™',
    'laquo':'«','raquo':'»','eacute':'é','egrave':'è','agrave':'à','aacute':'á',
}
def _clean_rss(raw):
    text = raw.decode('utf-8', errors='replace').replace('\x00', '')
    def _ent(m):
        n = m.group(1)
        if n in ('amp','lt','gt','quot','apos'): return m.group(0)
        return _HTML_ENT.get(n, '')
    return re.sub(r'&([a-zA-Z][a-zA-Z0-9]*);', _ent, text).encode('utf-8')


# ── Groq ─────────────────────────────────────────────────────────────────────

def query_groq(prompt, api_key, model="llama3-8b-8192"):
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 300},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[Groq error: {e}]"


# ── Reports ───────────────────────────────────────────────────────────────────

def get_reports():
    reports = []
    for path in sorted(glob.glob(f"{GARAK_RUNS}/*.report.jsonl"), reverse=True)[:10]:
        html = path.replace(".report.jsonl", ".report.html")
        results = []
        try:
            with open(path) as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        if obj.get("entry_type") == "eval":
                            passed = obj.get("passed", 0)
                            # garak field names vary by version; total_evaluated is current
                            total = (obj.get("total_evaluated") or obj.get("total_processed")
                                     or obj.get("total") or 0)
                            pf = (passed / total) if total else obj.get("passed_frac", 0)
                            results.append({
                                "probe": obj.get("probe", ""), "detector": obj.get("detector", ""),
                                "passed": passed, "total": total,
                                "passed_frac": round(pf * 100, 1),
                            })
                            save_scan_result(obj.get("probe",""), obj.get("detector",""),
                                             "unknown", passed, total, pf)
                    except Exception:
                        pass
        except Exception:
            pass
        reports.append({"name": os.path.basename(path),
                         "html": os.path.basename(html) if os.path.exists(html) else None,
                         "results": results})
    return reports


# ── Scanner ───────────────────────────────────────────────────────────────────

def run_scan(target_key, fn_name, probe):
    state = scans[target_key]
    state["lines"] = []
    state["prompts"] = []
    try:
        proc = subprocess.Popen(
            ["python3", "-m", "garak", "--target_type", "function.Single",
             "--target_name", f"mock_llm#{fn_name}", "--probes", probe],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd="/home/justin/garak-demo",
        )
        for line in proc.stdout:
            clean = line.rstrip()
            state["lines"].append(clean)
            if any(k in clean.lower() for k in ["prompt","attempt","hijack","probe"]):
                state["prompts"].append(clean)
        proc.wait()
    finally:
        state["running"] = False


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/favicon.ico")
def favicon():
    # 1x1 green pixel ICO
    ico = bytes([
        0,0,1,0,1,0,1,1,0,0,1,0,24,0,40,0,0,0,22,0,0,0,40,0,0,0,1,0,0,0,2,0,0,0,1,0,24,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,255,65,0,0,255,65,0,0,0,0,0
    ])
    return send_file(io.BytesIO(ico), mimetype='image/x-icon')

@app.route("/")
def index():
    # Strip non-serializable fields (lambdas) before passing to template
    safe_challenges = [
        {k: v for k, v in c.items() if k != "validator"}
        for c in CHALLENGES
    ]
    html = render_template("index.html",
                           probes=AVAILABLE_PROBES,
                           jailbreaks=JAILBREAKS,
                           categories=CATEGORIES,
                           challenges=safe_challenges,
                           reports=get_reports(),
                           public_url=PUBLIC_URL or "")
    resp = Response(html)
    # Never let the browser serve a stale copy of the dashboard
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    probe, target = data.get("probe","promptinject"), data.get("target","vulnerable")
    fn_map = {"vulnerable": "vulnerable_llm", "defended": "defended_llm"}
    targets = ["vulnerable","defended"] if target == "both" else [target]
    started = []
    for t in targets:
        if scans[t]["running"]: continue
        scans[t]["running"] = True
        threading.Thread(target=run_scan, args=(t, fn_map[t], probe), daemon=True).start()
        started.append(t)
    return jsonify({"status": "started", "targets": started})


@app.route("/status")
def status():
    return jsonify({t: {"running": scans[t]["running"], "lines": scans[t]["lines"][-60:],
                         "prompts": scans[t]["prompts"][-20:]} for t in scans})


@app.route("/reports")
def reports():
    return jsonify(get_reports())


@app.route("/report/<filename>")
def serve_report(filename):
    path = os.path.join(GARAK_RUNS, filename)
    if not os.path.exists(path) or not filename.endswith(".html"):
        return "Not found", 404
    with open(path) as f:
        return Response(f.read(), mimetype="text/html")


# ── Garak report data (for charts) ─────────────────────────────────────────────

@app.route("/reports/data")
def reports_data():
    """Aggregate real garak eval results across recent runs for visualization."""
    reports = get_reports()
    by_probe = {}
    for rep in reports:
        for r in rep["results"]:
            probe = r["probe"].split(".")[-1] or r["probe"] or "unknown"
            agg = by_probe.setdefault(probe, {"probe": probe, "passed": 0, "total": 0, "runs": 0})
            agg["passed"] += r["passed"]; agg["total"] += r["total"]; agg["runs"] += 1
    probes = []
    for p in by_probe.values():
        p["pass_rate"] = round(p["passed"] / p["total"] * 100, 1) if p["total"] else 0
        probes.append(p)
    probes.sort(key=lambda x: x["pass_rate"])
    return jsonify({"probes": probes, "report_count": len(reports)})


@app.route("/report/export/<filename>")
def report_export(filename):
    """Export a garak report as markdown (?fmt=md) or printable HTML (default)."""
    base = os.path.basename(filename)
    path = os.path.join(GARAK_RUNS, base)
    if not base.endswith(".report.jsonl") or not os.path.exists(path):
        return "Not found", 404
    rows = []
    with open(path) as f:
        for line in f:
            try:
                obj = json.loads(line)
                if obj.get("entry_type") == "eval":
                    rows.append({
                        "probe": obj.get("probe", ""), "detector": obj.get("detector", ""),
                        "passed": obj.get("passed", 0), "total": obj.get("total", 0),
                        "pct": round(obj.get("passed_frac", 0) * 100, 1),
                    })
            except Exception:
                pass
    fmt = request.args.get("fmt", "html")
    title = f"garak scan report — {base}"
    if fmt == "md":
        lines = [f"# {title}", "", f"_Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}_",
                 "", "| Probe | Detector | Passed | Total | Pass % |",
                 "|-------|----------|-------:|------:|-------:|"]
        for r in rows:
            lines.append(f"| {r['probe']} | {r['detector']} | {r['passed']} | {r['total']} | {r['pct']}% |")
        md = "\n".join(lines) + "\n"
        return Response(md, mimetype="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="{base}.md"'})
    # printable HTML (use the browser's Print → Save as PDF)
    trs = "".join(
        f"<tr><td>{r['probe']}</td><td>{r['detector']}</td><td>{r['passed']}</td>"
        f"<td>{r['total']}</td><td class='{ 'good' if r['pct']>=80 else 'bad' if r['pct']<50 else 'mid'}'>{r['pct']}%</td></tr>"
        for r in rows)
    html = f"""<!doctype html><html><head><meta charset=utf-8><title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;margin:40px;color:#111}}
h1{{font-size:20px}}table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid #ccc;padding:6px 10px;text-align:left}}th{{background:#f0f0f0}}
td.good{{color:#0a0;font-weight:bold}}td.bad{{color:#c00;font-weight:bold}}td.mid{{color:#c80}}
.meta{{color:#666;font-size:12px;margin-bottom:16px}}
@media print{{.noprint{{display:none}}}}</style></head>
<body><h1>{title}</h1>
<div class=meta>Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} · {len(rows)} eval rows</div>
<button class=noprint onclick=window.print()>Print / Save as PDF</button>
<table><thead><tr><th>Probe</th><th>Detector</th><th>Passed</th><th>Total</th><th>Pass %</th></tr></thead>
<tbody>{trs}</tbody></table></body></html>"""
    return Response(html, mimetype="text/html")


# ── Auth ───────────────────────────────────────────────────────────────────────

@app.route("/auth/register", methods=["POST"])
def auth_register():
    d = request.json or {}
    ok, err = create_user(d.get("username", ""), d.get("password", ""))
    if not ok:
        return jsonify({"error": err}), 400
    session["username"] = d.get("username", "").strip()
    session.permanent = True
    return jsonify({"username": session["username"]})


@app.route("/auth/login", methods=["POST"])
def auth_login():
    d = request.json or {}
    name = verify_user(d.get("username", ""), d.get("password", ""))
    if not name:
        return jsonify({"error": "Invalid username or password."}), 401
    session["username"] = name
    session.permanent = True
    return jsonify({"username": name})


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.pop("username", None)
    return jsonify({"ok": True})


@app.route("/auth/me")
def auth_me():
    return jsonify({"username": session.get("username")})


# ── MITRE ATLAS coverage ────────────────────────────────────────────────────────

@app.route("/atlas/coverage")
def atlas_coverage():
    user = current_user()
    solved = get_solved_challenges(user) if user != "anonymous" else set()
    cats = get_used_jb_categories(user) if user != "anonymous" else []
    rows = atlas_data.build_coverage(solved, cats)
    return jsonify({"techniques": rows, "summary": atlas_data.coverage_summary(rows),
                    "user": user})


# ── Prompt-injection sandbox ─────────────────────────────────────────────────────

@app.route("/sandbox/levels")
def sandbox_levels():
    user = current_user()
    solved = get_sandbox_solves(user) if user != "anonymous" else set()
    return jsonify({"levels": sandbox.public_levels(), "solved": sorted(solved)})


@app.route("/sandbox/attempt", methods=["POST"])
def sandbox_attempt():
    d = request.json or {}
    user = current_user(d)
    level = int(d.get("level", 1))
    prompt = str(d.get("prompt", ""))[:2000]
    result = sandbox.run(level, prompt)
    if result.get("success") and user != "anonymous":
        # attempts counter is best-effort (re-uses challenge_attempts namespace via level offset)
        save_sandbox_solve(user, level, prompt, int(d.get("attempts", 1)))
    return jsonify({"response": result["response"], "success": result["success"],
                    "flag": result.get("flag") if result["success"] else None})


@app.route("/sandbox/leaderboard")
def sandbox_lb():
    return jsonify(get_sandbox_leaderboard())


# ── Multi-model jailbreak arena ──────────────────────────────────────────────────

ARENA_MODELS = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile", "gemma2-9b-it"]

@app.route("/arena/run", methods=["POST"])
def arena_run():
    from mock_llm import vulnerable_llm, defended_llm
    from database import bypassed
    d = request.json or {}
    prompt = str(d.get("prompt", ""))[:2000]
    api_key = d.get("groq_api_key", "")
    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400
    results = [
        {"model": "mock: vulnerable", "response": vulnerable_llm(prompt)[0]},
        {"model": "mock: defended", "response": defended_llm(prompt)[0]},
    ]
    if api_key:
        for m in ARENA_MODELS:
            resp = query_groq(prompt, api_key, m)
            results.append({"model": m, "response": resp})
    for r in results:
        r["bypassed"] = bool(bypassed(r["response"])) and not r["response"].startswith("[Groq error")
    return jsonify({"results": results, "live": bool(api_key)})


# ── Shodan OSINT ─────────────────────────────────────────────────────────────────

@app.route("/osint/shodan")
def osint_shodan():
    ip = request.args.get("ip", "").strip()
    api_key = request.args.get("api_key", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    if not api_key:
        return jsonify({"error": "Shodan API key required — get one free at account.shodan.io"}), 400
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": api_key}, timeout=12)
        if r.status_code == 404:
            return jsonify({"error": "No information available for that IP."}), 404
        r.raise_for_status()
        data = r.json()
        return jsonify({
            "ip": data.get("ip_str", ip),
            "org": data.get("org", ""), "isp": data.get("isp", ""),
            "country": data.get("country_name", ""), "city": data.get("city", ""),
            "os": data.get("os", ""), "ports": sorted(data.get("ports", [])),
            "hostnames": data.get("hostnames", []),
            "vulns": sorted(data.get("vulns", [])) if data.get("vulns") else [],
            "services": [{"port": s.get("port"), "product": s.get("product", ""),
                          "transport": s.get("transport", ""),
                          "banner": (s.get("data", "") or "")[:300]}
                         for s in data.get("data", [])][:25],
        })
    except requests.HTTPError as e:
        return jsonify({"error": f"Shodan API error: {e.response.status_code}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── SSE live updates ─────────────────────────────────────────────────────────────
# NOTE: Server-Sent Events stream from a single worker's in-memory/file state.
# With the gunicorn `--workers 2` Procfile, run a single worker (or sticky
# sessions) for consistent streaming. Plain `python3 app.py` (dev) is fine.

def _live_snapshot():
    """Cheap snapshot of the activity surfaces clients want pushed."""
    try:
        squad = json.load(open(SQUAD_FEED_FILE)) if os.path.exists(SQUAD_FEED_FILE) else []
    except Exception:
        squad = []
    try:
        dispatch = json.load(open(_DISPATCH_FILE)) if os.path.exists(_DISPATCH_FILE) else []
    except Exception:
        dispatch = []
    squad = sorted(squad, key=lambda x: x.get("ts", 0), reverse=True)[:8]
    # dispatches are appended in chronological order; newest = tail
    dispatch = list(reversed(dispatch))[:8] if isinstance(dispatch, list) else []
    dispatch = [{"operator": e.get("operator", ""), "tag": e.get("tag", ""),
                 "ts": e.get("ts", ""), "id": e.get("id", "")} for e in dispatch]
    return {"squad": squad, "dispatch": dispatch, "ts": int(time.time())}


@app.route("/live/stream")
def live_stream():
    def gen():
        last = None
        # cap the stream lifetime so connections don't pile up
        for _ in range(600):  # ~600 * 3s ≈ 30 min
            snap = _live_snapshot()
            payload = json.dumps(snap)
            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload
            else:
                yield ": keep-alive\n\n"
            time.sleep(3)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/jailbreak", methods=["POST"])
def jailbreak():
    from mock_llm import vulnerable_llm, defended_llm
    data = request.json
    prompt   = data.get("prompt", "")
    name     = data.get("name", "Custom")
    category = data.get("category", "Custom")
    username = data.get("username", "anonymous")
    api_key  = data.get("groq_api_key", "")
    model    = data.get("groq_model", "llama3-8b-8192")
    vuln_resp = vulnerable_llm(prompt)[0]
    def_resp  = defended_llm(prompt)[0]
    groq_resp = query_groq(prompt, api_key, model) if api_key else ""
    save_jailbreak(username, name, category, prompt, vuln_resp, def_resp, groq_resp)
    new_achievements = check_and_award_achievements(username) if username != "anonymous" else []
    return jsonify({"vulnerable": vuln_resp, "defended": def_resp, "groq": groq_resp,
                    "new_achievements": new_achievements})


@app.route("/challenge/attempt", methods=["POST"])
def challenge_attempt():
    data = request.json
    challenge_id = data.get("challenge_id")
    prompt       = data.get("prompt", "")
    username     = data.get("username", "anonymous")

    from challenges import CHALLENGE_MAP
    c = CHALLENGE_MAP.get(challenge_id)
    if not c:
        return jsonify({"error": "Challenge not found"}), 404

    result   = run_challenge(challenge_id, prompt)
    attempts = get_user_attempts(username, challenge_id) + 1
    save_challenge_attempt(username, challenge_id, prompt, result["response"], result["success"])

    if result["success"]:
        save_challenge_solve(username, challenge_id, c["title"], c["points"], attempts)

    new_achievements = check_and_award_achievements(username) if username != "anonymous" else []
    return jsonify({**result, "attempts": attempts, "new_achievements": new_achievements})


@app.route("/challenge/status/<username>")
def challenge_status(username):
    solved = get_solved_challenges(username)
    result = []
    for c in CHALLENGES:
        attempts = get_user_attempts(username, c["id"])
        result.append({
            "id": c["id"], "title": c["title"], "difficulty": c["difficulty"],
            "points": c["points"], "category": c["category"],
            "description": c["description"],
            "solved": c["id"] in solved, "attempts": attempts,
        })
    return jsonify(result)


@app.route("/achievements/<username>")
def achievements(username):
    return jsonify(get_user_achievements(username))


@app.route("/leaderboard")
def leaderboard():
    return jsonify(get_leaderboard())


@app.route("/ctf/leaderboard")
def ctf_leaderboard():
    return jsonify(get_ctf_leaderboard())


@app.route("/dashboard/stats")
def dashboard_stats():
    return jsonify({"overall": get_overall_stats(), "categories": get_category_stats(),
                    "recent": get_recent_activity(8)})


@app.route("/quiz/score", methods=["POST"])
def quiz_score():
    data = request.json
    username = data.get("username","anonymous")
    save_quiz_score(username, data.get("category","Mixed"), data.get("score",0), data.get("total",10))
    return jsonify({"success": True})

@app.route("/quiz/leaderboard")
def quiz_lb():
    return jsonify(get_quiz_leaderboard())

@app.route("/challenge/writeup", methods=["POST"])
def post_writeup():
    data = request.json
    username = data.get("username","").strip()
    challenge_id = data.get("challenge_id")
    writeup = data.get("writeup","").strip()
    if not username or not writeup or not challenge_id:
        return jsonify({"error": "Missing fields"}), 400
    save_writeup(username, challenge_id, writeup)
    return jsonify({"success": True})


@app.route("/challenge/writeups/<int:challenge_id>")
def fetch_writeups(challenge_id):
    return jsonify(get_writeups(challenge_id))


@app.route("/osint/dns")
def osint_dns():
    domain = request.args.get("domain","").strip()
    rtype  = request.args.get("type","A")
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    try:
        r = requests.get(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}",
            headers={"Accept": "application/dns-json"}, timeout=8
        )
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/osint/crt")
def osint_crt():
    domain = request.args.get("domain","").strip()
    if not domain:
        return jsonify({"error": "No domain"}), 400
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=12)
        data = r.json()
        seen, results = set(), []
        for cert in data:
            for name in cert.get("name_value","").lower().split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name and name not in seen:
                    seen.add(name)
                    results.append(name)
        return jsonify({"subdomains": sorted(results)[:40]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/news/feed")
def news_feed():
    global _news_cache
    if _news_cache["data"] and time.time() - _news_cache["ts"] < 300:
        return jsonify(_news_cache["data"])
    import xml.etree.ElementTree as ET
    articles, errors = [], []
    for feed in NEWS_FEEDS:
        try:
            r = requests.get(feed["url"], timeout=8, headers={"User-Agent": "Mozilla/5.0"})
            try:
                root = ET.fromstring(r.content)
            except ET.ParseError:
                root = ET.fromstring(_clean_rss(r.content))
            # Support both RSS (<item>) and Atom (<entry>) feeds
            ns = {"a": "http://www.w3.org/2005/Atom"}
            items = root.findall(".//item") or root.findall(".//a:entry", ns)
            for item in items[:6]:
                title   = (item.findtext("title") or item.findtext("a:title", namespaces=ns) or "").strip()
                link_el = item.find("a:link", ns)
                link    = (item.findtext("link") or (link_el.get("href","") if link_el is not None else "") or "").strip()
                desc    = re.sub(r"<[^>]+>", "", (item.findtext("description") or item.findtext("a:summary", namespaces=ns) or item.findtext("a:content", namespaces=ns) or ""))[:280].strip()
                pubdate = (item.findtext("pubDate") or item.findtext("a:published", namespaces=ns) or "").strip()
                if title and link:
                    articles.append({"title": title, "link": link, "desc": desc,
                                     "date": pubdate, "source": feed["name"], "tag": feed["tag"]})
        except Exception as e:
            errors.append({"source": feed["name"], "error": str(e)})
    result = {"articles": articles, "errors": errors,
              "updated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}
    _news_cache = {"data": result, "ts": time.time()}
    return jsonify(result)



_cve_cache = {"data": None, "ts": 0}

@app.route("/cve/feed")
def cve_feed():
    global _cve_cache
    if _cve_cache["data"] and time.time() - _cve_cache["ts"] < 600:
        return jsonify(_cve_cache["data"])
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "resultsPerPage": 20,
                "startIndex": 0,
                "pubStartDate": (time.strftime("%Y-%m-%dT00:00:00.000", time.gmtime(time.time()-30*86400))),
                "pubEndDate":   time.strftime("%Y-%m-%dT23:59:59.999", time.gmtime()),
                "noRejected":   "",
            },
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=12
        )
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")[:300]
            metrics = cve.get("metrics", {})
            score = None
            severity = "UNKNOWN"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    score = m.get("cvssData", {}).get("baseScore")
                    severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    break
            published = cve.get("published", "")[:10]
            refs = cve.get("references", [])
            ref_url = refs[0]["url"] if refs else ""
            cves.append({
                "id": cve_id, "desc": desc, "score": score,
                "severity": severity, "published": published, "ref": ref_url
            })
        result = {"cves": cves, "updated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "error": None}
    except Exception as e:
        result = {"cves": [], "updated": "", "error": str(e)}
    _cve_cache = {"data": result, "ts": time.time()}
    return jsonify(result)

@app.route("/skilltree/score", methods=["POST"])
def skilltree_score():
    data = request.json or {}
    username = str(data.get("username", "OPERATOR"))[:20]
    xp = min(max(int(data.get("xp", 0)), 0), 99999)
    save_skilltree_score(username, xp)
    return jsonify({"ok": True})


@app.route("/skilltree/leaderboard")
def skilltree_leaderboard():
    return jsonify(get_skilltree_leaderboard())


@app.route("/aicode/flags", methods=["POST"])
def aicode_flags():
    data = request.json or {}
    username = str(data.get("username", "OPERATOR"))[:20]
    count = min(max(int(data.get("count", 0)), 0), 5)
    save_aicode_flags(username, count)
    return jsonify({"ok": True})


@app.route("/aicode/leaderboard")
def aicode_leaderboard():
    return jsonify(get_aicode_leaderboard())


@app.route("/ngrok/start", methods=["POST"])
def ngrok_start():
    global PUBLIC_URL
    try:
        from pyngrok import ngrok as pyngrok
        token = request.json.get("token","")
        if token:
            pyngrok.set_auth_token(token)
        tunnel = pyngrok.connect(5001, bind_tls=True)
        PUBLIC_URL = tunnel.public_url
        return jsonify({"url": PUBLIC_URL})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ngrok/status")
def ngrok_status():
    return jsonify({"url": PUBLIC_URL or ""})


@app.route("/ctf/calendar")
def ctf_calendar():
    try:
        now = int(time.time())
        r = requests.get(
            "https://ctftime.org/api/v1/events/",
            params={"limit": 20, "start": now},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=8
        )
        return jsonify(r.json())
    except Exception as e:
        return jsonify([{"title": f"CTFtime unreachable: {e}", "start": now, "finish": now, "url": "https://ctftime.org", "format": "N/A", "weight": 0}])


# ── OPERATOR FEED ──────────────────────────────────────────────────────────────
SQUAD_FEED_FILE = "/tmp/squad_feed.json"
_FAKE_OPS  = ["VIPER","PHANTOM","DARKSTAR","CIPHER","NOVA","GHOST","REAPER","SPECTER","WRAITH","INFERNO"]
_FAKE_ACTS = [
    "completed skill: Nmap Mastery (Skill Tree)",
    "earned WEB MASTER badge — 6/6 web nodes done",
    "joined CTF: X-MAS CTF 2026",
    "cracked 14 hashes with hashcat — rockyou.txt",
    "solved challenge: SQL Injection (Level 2)",
    "submitted score: 475 XP (leaderboard updated)",
    "earned NET NAVIGATOR badge — 6/6 network nodes",
    "completed skill: BloodHound (Skill Tree)",
    "earned CRYPTO KING badge — 6/6 crypto nodes",
    "ran nuclei scan — found 3 high-severity findings",
    "completed OSINT: Subdomain Recon (Skill Tree)",
    "solved Jailbreak: DAN v12 bypass — 44/44",
    "won head-to-head race vs GHOST — answered in 8s",
    "updated War Room: SQL Injection → CLAIMED",
    "earned BINARY BREAKER badge",
    "completed skill: Burp Suite Pro (Skill Tree)",
    "solved CTF challenge: Cookie Theft XSS",
    "submitted score: 850 XP (new personal best)",
]

def _seed_squad_feed():
    if os.path.exists(SQUAD_FEED_FILE):
        try:
            data = json.load(open(SQUAD_FEED_FILE))
            if len(data) >= 5:
                return
        except:
            pass
    now = time.time()
    seed = [{"name": random.choice(_FAKE_OPS), "action": random.choice(_FAKE_ACTS),
             "ts": int(now - random.randint(120, 7200))} for _ in range(18)]
    seed.sort(key=lambda x: x["ts"])
    json.dump(seed, open(SQUAD_FEED_FILE, "w"))

@app.route("/squad/feed")
def squad_feed():
    _seed_squad_feed()
    try:
        data = json.load(open(SQUAD_FEED_FILE)) if os.path.exists(SQUAD_FEED_FILE) else []
    except:
        data = []
    return jsonify(sorted(data, key=lambda x: x["ts"], reverse=True)[:25])

@app.route("/squad/activity", methods=["POST"])
def squad_activity():
    d = request.json or {}
    name   = str(d.get("name",   "OPERATOR"))[:20]
    action = str(d.get("action", ""))[:100]
    if not action:
        return jsonify({"ok": False})
    try:
        data = json.load(open(SQUAD_FEED_FILE)) if os.path.exists(SQUAD_FEED_FILE) else []
    except:
        data = []
    data.append({"name": name, "action": action, "ts": int(time.time())})
    json.dump(data[-50:], open(SQUAD_FEED_FILE, "w"))
    return jsonify({"ok": True})

# ── WAR ROOM ───────────────────────────────────────────────────────────────────
WARROOM_FILE = "/tmp/warroom.json"
_WARROOM_DEFAULT_TASKS = [
    {"id":0,"cat":"WEB","title":"SQL Injection","assigned":"","status":"OPEN"},
    {"id":1,"cat":"WEB","title":"XSS / CSRF / Auth bypass","assigned":"","status":"OPEN"},
    {"id":2,"cat":"WEB","title":"IDOR / Business Logic","assigned":"","status":"OPEN"},
    {"id":3,"cat":"RECON","title":"Subdomain enumeration","assigned":"","status":"OPEN"},
    {"id":4,"cat":"RECON","title":"Tech stack fingerprint","assigned":"","status":"OPEN"},
    {"id":5,"cat":"RECON","title":"Email / employee OSINT","assigned":"","status":"OPEN"},
    {"id":6,"cat":"CRYPTO","title":"Encoding / ROT / base64","assigned":"","status":"OPEN"},
    {"id":7,"cat":"CRYPTO","title":"Hash crack (MD5/SHA1)","assigned":"","status":"OPEN"},
    {"id":8,"cat":"CRYPTO","title":"Custom cipher / RSA","assigned":"","status":"OPEN"},
    {"id":9,"cat":"PWN","title":"Binary analysis (RE)","assigned":"","status":"OPEN"},
    {"id":10,"cat":"PWN","title":"Buffer overflow","assigned":"","status":"OPEN"},
    {"id":11,"cat":"PWN","title":"ROP / heap exploit","assigned":"","status":"OPEN"},
    {"id":12,"cat":"FORENSICS","title":"Memory dump / Volatility","assigned":"","status":"OPEN"},
    {"id":13,"cat":"FORENSICS","title":"PCAP analysis","assigned":"","status":"OPEN"},
    {"id":14,"cat":"FORENSICS","title":"Steganography","assigned":"","status":"OPEN"},
    {"id":15,"cat":"MISC","title":"Trivia / general","assigned":"","status":"OPEN"},
    {"id":16,"cat":"MISC","title":"Scripting challenge","assigned":"","status":"OPEN"},
    {"id":17,"cat":"MISC","title":"Wildcard / bonus flag","assigned":"","status":"OPEN"},
]

@app.route("/warroom", methods=["GET"])
def warroom_get():
    try:
        data = json.load(open(WARROOM_FILE)) if os.path.exists(WARROOM_FILE) else \
               {"ctf_name": "", "tasks": list(_WARROOM_DEFAULT_TASKS), "notes": ""}
    except:
        data = {"ctf_name": "", "tasks": list(_WARROOM_DEFAULT_TASKS), "notes": ""}
    return jsonify(data)

@app.route("/warroom", methods=["POST"])
def warroom_post():
    d = request.json or {}
    try:
        current = json.load(open(WARROOM_FILE)) if os.path.exists(WARROOM_FILE) else \
                  {"ctf_name": "", "tasks": list(_WARROOM_DEFAULT_TASKS), "notes": ""}
    except:
        current = {"ctf_name": "", "tasks": list(_WARROOM_DEFAULT_TASKS), "notes": ""}
    if "ctf_name" in d: current["ctf_name"] = str(d["ctf_name"])[:80]
    if "notes"    in d: current["notes"]    = str(d["notes"])[:1000]
    if "tasks"    in d: current["tasks"]    = d["tasks"]
    json.dump(current, open(WARROOM_FILE, "w"))
    return jsonify({"ok": True})

# ── HEAD-TO-HEAD RACE ─────────────────────────────────────────────────────────
_RACE_QUESTIONS = [
    {"q":"Which port does SSH run on by default?","opts":["21","22","23","25"],"ans":1},
    {"q":"What does XSS stand for?","opts":["Cross-Site Scripting","Cross-Server Scripting","Cross-Site Session","Cross-System Security"],"ans":0},
    {"q":"Which port is used by HTTPS?","opts":["80","8080","443","8443"],"ans":2},
    {"q":"What tool enumerates Active Directory attack paths?","opts":["Metasploit","BloodHound","Nmap","Burp Suite"],"ans":1},
    {"q":"IDOR stands for?","opts":["Indirect Data Object Reference","Insecure Direct Object Reference","Internal Directory Object Response","Indirect Domain Object Read"],"ans":1},
    {"q":"Which Impacket script dumps NTLM hashes from a DC?","opts":["psexec.py","wmiexec.py","secretsdump.py","GetUserSPNs.py"],"ans":2},
    {"q":"SSRF stands for?","opts":["Server-Side Request Forgery","Secure Server Request Format","Session-State Request Failure","Server-Side Response Filtering"],"ans":0},
    {"q":"Port 3389 is used by which protocol?","opts":["SSH","RDP","VNC","Telnet"],"ans":1},
    {"q":"Which tool is commonly used for web directory fuzzing?","opts":["Nmap","Shodan","ffuf","Metasploit"],"ans":2},
    {"q":"CSRF stands for?","opts":["Cross-Site Request Forgery","Cross-Server Request Forgery","Client-Side Request Failure","Cached Site Request Fraud"],"ans":0},
    {"q":"Kerberoasting steals what to crack offline?","opts":["Service account Kerberos tickets","NTLM hashes from memory","Active Directory database","TLS certificates"],"ans":0},
    {"q":"What does a reverse shell do?","opts":["Opens a port on attacker machine","Target connects back to attacker","Attacker connects to target","Binds a shell to localhost"],"ans":1},
    {"q":"BlueKeep (CVE-2019-0708) is a vulnerability in?","opts":["SMB","RDP","SSH","DNS"],"ans":1},
    {"q":"Which tool cracks password hashes offline at scale?","opts":["John the Ripper","Nmap","Wireshark","Netcat"],"ans":0},
    {"q":"What does SQL stand for?","opts":["Structured Query Language","Simple Query Language","Standard Question Language","Secure Query Language"],"ans":0},
]
_races = {}

@app.route("/race/create", methods=["POST"])
def race_create():
    d    = request.json or {}
    name = str(d.get("name", "OPERATOR"))[:20]
    code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    q    = random.choice(_RACE_QUESTIONS)
    _races[code] = {
        "code": code, "question": q,
        "players": [{"name": name, "answered": False, "correct": False, "ts": None}],
        "status": "waiting", "winner": None, "created": time.time()
    }
    return jsonify({"code": code, "question": {k: v for k, v in q.items() if k != "ans"}})

@app.route("/race/join/<code>", methods=["POST"])
def race_join(code):
    d    = request.json or {}
    name = str(d.get("name", "OPERATOR"))[:20]
    r    = _races.get(code.upper())
    if not r:                     return jsonify({"error": "Room not found"}), 404
    if r["status"] != "waiting":  return jsonify({"error": "Race already started"}), 400
    if len(r["players"]) >= 2:    return jsonify({"error": "Room full"}), 400
    r["players"].append({"name": name, "answered": False, "correct": False, "ts": None})
    r["status"] = "live"
    r["started"] = time.time()
    return jsonify({"ok": True, "question": {k: v for k, v in r["question"].items() if k != "ans"}})

@app.route("/race/status/<code>")
def race_status(code):
    r = _races.get(code.upper())
    if not r: return jsonify({"error": "Not found"}), 404
    safe = {k: v for k, v in r.items() if k != "question"}
    safe["question"] = {k: v for k, v in r["question"].items() if k != "ans"}
    return jsonify(safe)

@app.route("/race/answer/<code>", methods=["POST"])
def race_answer(code):
    d       = request.json or {}
    name    = str(d.get("name", "OPERATOR"))[:20]
    ans_idx = int(d.get("answer", -1))
    r = _races.get(code.upper())
    if not r or r["status"] != "live":
        return jsonify({"error": "No active race"}), 400
    correct = ans_idx == r["question"]["ans"]
    for p in r["players"]:
        if p["name"] == name and not p["answered"]:
            p["answered"] = True; p["correct"] = correct; p["ts"] = time.time()
            break
    if correct and not r["winner"]:
        r["winner"] = name; r["status"] = "done"
    elif all(p["answered"] for p in r["players"]) and not r["winner"]:
        r["status"] = "done"
    return jsonify({"correct": correct, "winner": r.get("winner")})


# ── SOC / IR: metrics + playbook library ────────────────────────────────────────

@app.route("/soc/metrics")
def soc_metrics():
    """Analyst scorecard derived from the current user's CTF/sandbox activity."""
    user = current_user()
    return jsonify({"user": user, "metrics": get_soc_metrics(user)})


SOC_PB_FILE = "/tmp/soc_playbooks.json"
SOC_PB_BUILTIN = [
    {"id": "seed_phishing", "title": "Phishing / Credential Harvesting", "category": "Email",
     "builtin": True, "steps": [
        "Confirm the report (user-reported or detected by mail security)",
        "Pull the email + full headers; extract URLs, attachments, sender + originating IP",
        "Detonate URL/attachment in a sandbox; check VirusTotal / TIP for reputation",
        "Search mail logs: who else received it, who opened/clicked",
        "Contain: quarantine across all mailboxes, block sender + URL at the gateway",
        "If credentials were entered: force password reset, revoke active sessions, review sign-in logs",
        "Document, add IOCs to the TIP, send a heads-up to affected users"]},
    {"id": "seed_ransomware", "title": "Ransomware Outbreak", "category": "Malware",
     "builtin": True, "steps": [
        "Isolate affected hosts immediately (EDR network-contain) — do NOT power off (preserves memory)",
        "Identify the variant and scope of encryption",
        "Preserve evidence: image + hash before remediation",
        "Disable spread paths: lock accounts, disable shares, cut lateral routes",
        "Engage IR lead, management, and Legal; verify backup integrity",
        "Eradicate persistence + malware, then restore from known-good backups",
        "Post-incident review + regulatory/insurer notification if required"]},
    {"id": "seed_account", "title": "Account Compromise / Suspicious Login", "category": "Identity",
     "builtin": True, "steps": [
        "Confirm the anomaly (impossible travel, MFA fatigue, new device)",
        "Review the identity provider sign-in logs for the user",
        "Revoke sessions + tokens; force password reset; re-enrol MFA",
        "Check for mailbox rules, OAuth grants, or new MFA methods added by the attacker",
        "Scope: what did the account access while compromised?",
        "Notify the user + their manager; document timeline"]},
    {"id": "seed_malware", "title": "Malware on an Endpoint", "category": "Endpoint",
     "builtin": True, "steps": [
        "Network-isolate the host via EDR",
        "Collect triage data (running processes, persistence, network connections)",
        "Identify the malware family; pull IOCs",
        "Hunt the IOCs across the fleet for other infected hosts",
        "Eradicate + reimage if integrity is uncertain",
        "Add detections; document root cause (delivery vector)"]},
]


def _soc_pb_load():
    try:
        return json.load(open(SOC_PB_FILE)) if os.path.exists(SOC_PB_FILE) else []
    except Exception:
        return []


def _soc_pb_save(d):
    json.dump(d[-200:], open(SOC_PB_FILE, "w"))


@app.route("/soc/playbooks")
def soc_playbooks():
    return jsonify({"builtin": SOC_PB_BUILTIN, "custom": list(reversed(_soc_pb_load()))})


@app.route("/soc/playbooks/add", methods=["POST"])
def soc_pb_add():
    d = request.json or {}
    title = str(d.get("title", "")).strip()[:80]
    category = str(d.get("category", "Custom")).strip()[:30] or "Custom"
    raw = str(d.get("steps", ""))
    steps = [s.strip() for s in raw.replace("\r", "").split("\n") if s.strip()][:30]
    if not title or not steps:
        return jsonify({"error": "Title and at least one step are required."}), 400
    item = {"id": f"pb_{int(time.time()*1000)}", "title": title, "category": category,
            "builtin": False, "author": current_user()[:20], "steps": steps,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    data = _soc_pb_load(); data.append(item); _soc_pb_save(data)
    return jsonify({"ok": True, "item": item})


@app.route("/soc/playbooks/delete", methods=["POST"])
def soc_pb_delete():
    pid = str((request.json or {}).get("id", ""))
    if not pid.startswith("pb_"):
        return jsonify({"error": "Only custom playbooks can be deleted."}), 400
    data = _soc_pb_load()
    new = [p for p in data if p.get("id") != pid]
    _soc_pb_save(new)
    return jsonify({"ok": True, "removed": len(data) - len(new)})


# ── LIVE TERMINAL ─────────────────────────────────────────────────────────────
_TERM_ALLOWED = {'dig','nslookup','host','whois','ping','curl','traceroute','tracepath',
                 'echo','base64','xxd','python3','openssl','nmap','id','pwd','uname',
                 'date','ip','ss','netstat','lsof','cat','ls','file','strings'}
# Commands we can emulate over HTTP when the native binary is absent.
_TERM_FALLBACK = {'dig', 'nslookup', 'host', 'whois'}
_DNS_TYPES = {'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA'}


def _term_command_status():
    """Which allowed commands are runnable: native binary, HTTP fallback, or neither."""
    native, fallback, missing = [], [], []
    for c in sorted(_TERM_ALLOWED):
        if shutil.which(c):
            native.append(c)
        elif c in _TERM_FALLBACK:
            fallback.append(c)
        else:
            missing.append(c)
    return {"native": native, "fallback": fallback, "missing": missing}


def _extract_dns_query(parts):
    """Pull (name, rtype) from a dig/nslookup/host invocation."""
    name, rtype, i = None, "A", 1
    toks = parts[1:]
    while i <= len(toks):
        p = toks[i - 1] if i - 1 < len(toks) else None
        i += 1
        if not p:
            continue
        if p in ("-t", "-type", "--type") and i - 1 < len(toks):
            rtype = toks[i - 1].upper(); i += 1; continue
        m = re.match(r'-(?:type|t)=(\w+)', p)
        if m:
            rtype = m.group(1).upper(); continue
        if p.startswith(("+", "-")):
            continue
        if p.upper() in _DNS_TYPES:
            rtype = p.upper(); continue
        if name is None:
            name = p
    return name, rtype


def _doh_lookup(name, rtype):
    """dig-style answer via Cloudflare DNS-over-HTTPS (used when dig isn't installed)."""
    r = requests.get("https://cloudflare-dns.com/dns-query",
                     params={"name": name, "type": rtype},
                     headers={"Accept": "application/dns-json"}, timeout=8)
    data = r.json()
    out = [f"; <<>> garak DoH fallback <<>> {rtype} {name}",
           f";; status: {'NOERROR' if data.get('Status') == 0 else 'ERR(' + str(data.get('Status')) + ')'}"]
    answers = data.get("Answer", [])
    if not answers:
        out.append(";; no records found")
    else:
        out.append(";; ANSWER SECTION:")
        for a in answers:
            out.append(f"{a.get('name','')}\t{a.get('TTL','')}\tIN\t{rtype}\t{a.get('data','')}")
    return "\n".join(out) + "\n"


def _rdap_whois(domain):
    """whois-style summary via RDAP over HTTP (used when whois isn't installed)."""
    r = requests.get(f"https://rdap.org/domain/{domain}",
                     headers={"Accept": "application/rdap+json"}, timeout=10,
                     allow_redirects=True)
    if r.status_code == 404:
        return f"No RDAP record for {domain} (may be an unsupported TLD)."
    r.raise_for_status()
    d = r.json()
    lines = [f"Domain Name: {d.get('ldhName', domain)}",
             f"Status: {', '.join(d.get('status', [])) or 'unknown'}"]
    for ev in d.get("events", []):
        lines.append(f"{ev.get('eventAction','event').title()}: {ev.get('eventDate','')}")
    registrar = next((e for e in d.get("entities", [])
                      if "registrar" in (e.get("roles") or [])), None)
    if registrar:
        vcard = registrar.get("vcardArray", [None, []])[1]
        fn = next((v[3] for v in vcard if v and v[0] == "fn"), "")
        if fn:
            lines.append(f"Registrar: {fn}")
    ns = [n.get("ldhName", "") for n in d.get("nameservers", [])]
    for n in ns:
        lines.append(f"Name Server: {n}")
    return "\n".join(lines) + "\n;; RDAP HTTP fallback (whois binary not installed)\n"


@app.route("/terminal/commands")
def terminal_commands():
    return jsonify(_term_command_status())


@app.route("/terminal/run", methods=["POST"])
def terminal_run():
    raw = (request.json or {}).get("cmd", "").strip()
    if not raw:
        return jsonify({"out": "", "err": "No command entered."})
    try:
        parts = shlex.split(raw)
    except ValueError as e:
        return jsonify({"out": "", "err": f"Parse error: {e}"})
    cmd = parts[0].lower().split('/')[-1]
    if cmd not in _TERM_ALLOWED:
        allowed = ', '.join(sorted(_TERM_ALLOWED))
        return jsonify({"out": "", "err": f"'{cmd}' not allowed.\nPermitted: {allowed}"})
    # HTTP fallbacks when the native binary is missing (dig/nslookup/host/whois)
    if cmd in _TERM_FALLBACK and not shutil.which(cmd):
        try:
            if cmd in ("dig", "nslookup", "host"):
                name, rtype = _extract_dns_query(parts)
                if not name:
                    return jsonify({"out": "", "err": f"{cmd}: specify a domain"})
                out = _doh_lookup(name, rtype)
                return jsonify({"out": out, "err": "", "rc": 0, "fallback": True})
            if cmd == "whois":
                target = next((p for p in parts[1:] if not p.startswith("-")), None)
                if not target:
                    return jsonify({"out": "", "err": "whois: specify a domain"})
                return jsonify({"out": _rdap_whois(target), "err": "", "rc": 0, "fallback": True})
        except Exception as e:
            return jsonify({"out": "", "err": f"{cmd} fallback failed: {e}"})
    # Safety constraints per command
    if cmd == 'ping':
        host = next((p for p in parts[1:] if not p.startswith('-')), None)
        if not host: return jsonify({"out":"","err":"ping: specify a host"})
        parts = ['ping', '-c', '3', '-W', '2', host]
    elif cmd == 'nmap':
        blocked = {'-sS','-O','--os-detection','-A','--script=exploit','--script=vuln'}
        if any(any(p.startswith(b) for b in blocked) for p in parts):
            return jsonify({"out":"","err":"nmap: aggressive scan flags not permitted in this terminal."})
        if '--host-timeout' not in ' '.join(parts):
            parts += ['--host-timeout','10s','--max-retries','1']
    elif cmd == 'curl':
        if '--max-time' not in ' '.join(parts):
            parts = ['curl','--max-time','8','--max-filesize','102400'] + parts[1:]
    elif cmd == 'python3':
        if len(parts) < 3 or parts[1] != '-c':
            return jsonify({"out":"","err":"Only 'python3 -c <code>' is allowed."})
    elif cmd in ('id','pwd','uname','date'):
        parts = [cmd]
    elif cmd in ('cat','strings','xxd','file'):
        # Restrict to /tmp and relative paths only
        for p in parts[1:]:
            if p.startswith('/') and not p.startswith('/tmp'):
                return jsonify({"out":"","err":f"Access restricted to /tmp — cannot read {p}"})
    try:
        result = subprocess.run(
            parts, capture_output=True, text=True, timeout=15,
            env={'PATH':'/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin','HOME':'/tmp','TERM':'xterm'}
        )
        return jsonify({"out": result.stdout, "err": result.stderr, "rc": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"out": "", "err": "Command timed out (15s)"})
    except FileNotFoundError:
        st = _term_command_status()
        hint = f"'{cmd}' is not installed on this server."
        if cmd in ("nmap",): hint += " Ask the admin to `apt install nmap`."
        elif cmd in ("traceroute", "tracepath"): hint += " Try `ping` instead."
        elif cmd in ("netstat",): hint += " Try `ss` instead."
        hint += "\nWorking now: " + ", ".join(st["native"] + st["fallback"])
        return jsonify({"out": "", "err": hint})
    except Exception as e:
        return jsonify({"out": "", "err": str(e)})

# ── MINI SQUAD CTF ────────────────────────────────────────────────────────────
MINICTF_FILE = "/tmp/minictf.json"
_MINICTF_DEFAULT = {
    "challenges": [
        {"id":1,"title":"The Base Awakens","cat":"CRYPTO","points":100,
         "desc":"Someone encoded a secret message. Decode it to find the flag.\n\nPayload: Y2Flc2FyX2lzX2Z1bg==\n\nHint: What encoding uses = padding?",
         "flag":"garak{caesar_is_fun}","author":"SYSTEM","solves":0},
        {"id":2,"title":"View Source","cat":"WEB","points":150,
         "desc":"The flag is hidden in plain sight.\n\n<!-- garak{always_check_source} -->\n\nHint: Right-click → View Page Source on any page and look for HTML comments.",
         "flag":"garak{always_check_source}","author":"SYSTEM","solves":0},
        {"id":3,"title":"Hash Clash","cat":"CRYPTO","points":200,
         "desc":"This MD5 hash was leaked in a breach file:\n\n5f4dcc3b5aa765d61d8327deb882cf99\n\nCrack it. Flag format: garak{<plaintext>}",
         "flag":"garak{password}","author":"SYSTEM","solves":0},
        {"id":4,"title":"Who Made Linux?","cat":"OSINT","points":250,
         "desc":"Find the GitHub username of the creator of the Linux kernel.\n\nFlag format: garak{github_username}\n\nHint: github.com/torvalds",
         "flag":"garak{torvalds}","author":"SYSTEM","solves":0},
        {"id":5,"title":"SQL Time","cat":"WEB","points":300,
         "desc":"Classic login bypass. The backend runs:\n\nSELECT * FROM users WHERE user='$u' AND pass='$p'\n\nWhat single-quote payload makes this always true?\nFlag format: garak{your_payload}",
         "flag":"garak{' OR '1'='1}","author":"SYSTEM","solves":0},
        {"id":6,"title":"ROT Thirteen","cat":"CRYPTO","points":100,
         "desc":"Decode this ROT13 message:\n\nynenx{ebg_guvegrra_vf_rnfl}\n\nHint: rot13.com",
         "flag":"garak{rot_thirteen_is_easy}","author":"SYSTEM","solves":0},
        {"id":7,"title":"Port Knowledge","cat":"MISC","points":150,
         "desc":"What port does SSH run on by default?\nWhat port does HTTPS use?\nCombine them: garak{SSH_port}-{HTTPS_port}",
         "flag":"garak{22-443}","author":"SYSTEM","solves":0},
    ],
    "solves": []
}

def _load_minictf():
    try:
        return json.load(open(MINICTF_FILE)) if os.path.exists(MINICTF_FILE) else dict(_MINICTF_DEFAULT)
    except: return dict(_MINICTF_DEFAULT)

def _save_minictf(data):
    json.dump(data, open(MINICTF_FILE,"w"))

@app.route("/minictf/challenges")
def minictf_challenges():
    data = _load_minictf()
    chals = [{k:v for k,v in c.items() if k != 'flag'} for c in data['challenges']]
    return jsonify({"challenges": chals, "solves": data['solves']})

@app.route("/minictf/create", methods=["POST"])
def minictf_create():
    d = request.json or {}
    data = _load_minictf()
    new_id = max([c['id'] for c in data['challenges']], default=0) + 1
    data['challenges'].append({
        "id": new_id,
        "title": str(d.get("title","Untitled"))[:60],
        "cat": str(d.get("cat","MISC"))[:20].upper(),
        "points": max(50, min(int(d.get("points",100)), 1000)),
        "desc": str(d.get("desc",""))[:1000],
        "flag": str(d.get("flag",""))[:100],
        "author": str(d.get("author","UNKNOWN"))[:20].upper(),
        "solves": 0
    })
    _save_minictf(data)
    return jsonify({"ok": True, "id": new_id})

@app.route("/minictf/submit", methods=["POST"])
def minictf_submit():
    d = request.json or {}
    username = str(d.get("username","ANON"))[:20].upper()
    chal_id  = int(d.get("challenge_id", 0))
    flag     = str(d.get("flag","")).strip()
    data = _load_minictf()
    chal = next((c for c in data['challenges'] if c['id'] == chal_id), None)
    if not chal: return jsonify({"correct":False,"msg":"Challenge not found"})
    already = any(s['username']==username and s['chal_id']==chal_id for s in data['solves'])
    if already: return jsonify({"correct":True,"msg":"Already solved!","points":0})
    if flag == chal['flag']:
        data['solves'].append({"username":username,"chal_id":chal_id,"points":chal['points'],"ts":int(time.time())})
        chal['solves'] = chal.get('solves',0) + 1
        _save_minictf(data)
        return jsonify({"correct":True,"msg":f"CORRECT FLAG! +{chal['points']} pts","points":chal['points']})
    return jsonify({"correct":False,"msg":"Wrong flag. Keep trying!"})

@app.route("/minictf/board")
def minictf_board():
    data = _load_minictf()
    scores = {}
    for s in data['solves']:
        scores[s['username']] = scores.get(s['username'],0) + s['points']
    return jsonify(sorted([{"username":u,"points":p} for u,p in scores.items()], key=lambda x:-x['points']))

# ── BREACH INTEL ──────────────────────────────────────────────────────────────
_XON = {"data": None, "ts": 0}

@app.route("/breach/password", methods=["POST"])
def breach_password():
    pw = (request.json or {}).get("password","")
    if not pw: return jsonify({"error":"No password"})
    sha1   = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                         headers={"User-Agent":"garak-edu-tool","Add-Padding":"true"}, timeout=6)
        count = 0
        for line in r.text.splitlines():
            h, c = line.split(":")
            if h == suffix: count = int(c); break
        return jsonify({"found": count > 0, "count": count, "prefix": prefix})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/breach/email", methods=["POST"])
def breach_email():
    data    = request.json or {}
    email   = data.get("email","").strip()
    api_key = data.get("api_key","").strip()
    if not email:   return jsonify({"error":"No email"})
    if not api_key: return jsonify({"error":"API key required — get one free at haveibeenpwned.com/API/Key"})
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}",
            headers={"hibp-api-key": api_key, "User-Agent": "garak-edu-tool"},
            params={"truncateResponse": "false"},
            timeout=8
        )
        if r.status_code == 404:
            return jsonify({"found": False, "breaches": []})
        if r.status_code == 401:
            return jsonify({"error": "Invalid API key"})
        if r.status_code == 429:
            return jsonify({"error": "Rate limited — wait a moment and try again"})
        r.raise_for_status()
        breaches = r.json()
        return jsonify({"found": True, "breaches": breaches})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/breach/global")
def breach_global():
    """Live world breach monitor via XposedOrNot /v1/breaches (cached 10 min)."""
    global _xon_cache
    try:
        _xon_cache
    except NameError:
        pass
    now = time.time()
    if _XON.get("data") and now - _XON.get("ts", 0) < 600:
        return jsonify(_XON["data"])
    try:
        r = requests.get("https://api.xposedornot.com/v1/breaches",
                         headers={"User-Agent": "garak-edu-tool"}, timeout=12)
        ex = r.json().get("exposedBreaches", []) or []
        total = 0; items = []
        for b in ex:
            try: rec = int(b.get("exposedRecords") or 0)
            except Exception: rec = 0
            total += rec
            data = b.get("exposedData", "")
            if isinstance(data, list): data = "; ".join(str(x) for x in data)
            items.append({"name": b.get("breachID", ""),
                          "date": (b.get("breachedDate") or "")[:10],
                          "added": b.get("addedDate") or "",
                          "industry": b.get("industry", ""),
                          "records": rec, "data": data,
                          "desc": (b.get("exposureDescription", "") or "")[:200]})
        items.sort(key=lambda x: x["added"], reverse=True)
        out = {"count": len(items), "total_records": total, "recent": items[:50]}
        _XON["data"] = out; _XON["ts"] = now
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e), "count": 0, "total_records": 0, "recent": []})


@app.route("/breach/email_free", methods=["POST"])
def breach_email_free():
    """Free, no-key email breach lookup via XposedOrNot (so friends can just type an email)."""
    email = (request.json or {}).get("email", "").strip()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Enter a valid email address."})
    out = {"email": email, "found": False, "count": 0, "risk": None, "breaches": []}
    try:
        q = requests.utils.quote(email)
        chk = requests.get("https://api.xposedornot.com/v1/check-email/%s" % q,
                           headers={"User-Agent": "garak-edu-tool"}, timeout=10)
        j = chk.json() if chk.content else {}
        names = []
        if isinstance(j, dict) and j.get("breaches"):
            first = j["breaches"][0] if j["breaches"] else []
            names = first if isinstance(first, list) else j["breaches"]
        if not names:
            return jsonify(out)  # clean
        out["found"] = True
        out["count"] = len(names)
        # rich detail via analytics
        try:
            a = requests.get("https://api.xposedornot.com/v1/breach-analytics",
                             params={"email": email}, headers={"User-Agent": "garak-edu-tool"},
                             timeout=10).json()
            risk = (a.get("BreachMetrics", {}) or {}).get("risk")
            if isinstance(risk, list) and risk:
                out["risk"] = {"label": risk[0].get("risk_label"), "score": risk[0].get("risk_score")}
            det = (a.get("ExposedBreaches", {}) or {}).get("breaches_details", []) or []
            byname = {d.get("breach"): d for d in det}
            for nm in names:
                d = byname.get(nm, {})
                out["breaches"].append({
                    "name": nm,
                    "date": d.get("xposed_date", ""),
                    "records": d.get("xposed_records", ""),
                    "data": d.get("xposed_data", ""),
                    "industry": d.get("industry", ""),
                    "details": (d.get("details", "") or "")[:240],
                })
        except Exception:
            out["breaches"] = [{"name": nm, "date": "", "records": "", "data": "", "industry": "", "details": ""} for nm in names]
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)})


# ══════════════════════════════════════════════════════
# SIGINT STATION
# ══════════════════════════════════════════════════════
import ssl, socket
_SIGINT_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

@app.route("/sigint/lookup", methods=["POST"])
def sigint_lookup():
    domain = (request.json or {}).get("domain","").strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
    if not domain or not _SIGINT_RE.match(domain):
        return jsonify({"error": "Invalid domain"})
    result = {"domain": domain}
    # IP resolution
    try: result["ips"] = list(set(str(x[4][0]) for x in socket.getaddrinfo(domain, None)))
    except: result["ips"] = []
    # Reverse DNS
    try: result["rdns"] = socket.gethostbyaddr(result["ips"][0])[0] if result["ips"] else ""
    except: result["rdns"] = ""
    # WHOIS (truncated)
    try:
        w = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        lines = [l for l in w.stdout.splitlines() if l.strip() and not l.startswith("%") and ":" in l][:30]
        result["whois"] = "\n".join(lines)
    except: result["whois"] = "unavailable"
    # DNS records
    dns = {}
    for rtype in ["A","MX","NS","TXT","CNAME"]:
        try:
            d = subprocess.run(["dig","+short",rtype,domain], capture_output=True, text=True, timeout=5)
            vals = [l.strip() for l in d.stdout.splitlines() if l.strip()]
            if vals: dns[rtype] = vals
        except: pass
    result["dns"] = dns
    # SSL certificate
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=5), server_hostname=domain) as s:
            cert = s.getpeercert()
            result["ssl"] = {
                "subject": dict(x[0] for x in cert.get("subject",[])),
                "issuer":  dict(x[0] for x in cert.get("issuer",[])),
                "notBefore": cert.get("notBefore",""),
                "notAfter":  cert.get("notAfter",""),
                "sans": [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"][:10],
            }
    except: result["ssl"] = None
    # HTTP headers
    try:
        hr = requests.head(f"https://{domain}", timeout=5, allow_redirects=True,
                           headers={"User-Agent":"Mozilla/5.0"})
        interesting = ["server","x-powered-by","x-frame-options","content-security-policy",
                       "strict-transport-security","x-content-type-options","via","cf-ray","x-generator"]
        result["headers"] = {k:v for k,v in hr.headers.items() if k.lower() in interesting}
        result["status_code"] = hr.status_code
    except: result["headers"] = {}; result["status_code"] = None
    # Subdomains via crt.sh
    try:
        cr = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=8,
                          headers={"User-Agent":"garak-edu-tool"})
        subs = list({e["name_value"].strip().lower() for e in cr.json()
                     if "*" not in e.get("name_value","") and e.get("name_value","").endswith(domain)})
        result["subdomains"] = sorted(subs)[:20]
    except: result["subdomains"] = []
    # IP Geolocation
    try:
        ip = result["ips"][0] if result["ips"] else ""
        if ip:
            geo = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,lat,lon",
                               timeout=5).json()
            result["geo"] = geo
    except: result["geo"] = {}
    return jsonify(result)


# ══════════════════════════════════════════════════════
# DEAD DROP
# ══════════════════════════════════════════════════════
import base64, secrets as _secrets

_DEADDROP_FILE = "/tmp/deaddrops.json"

def _dd_load():
    try:
        with open(_DEADDROP_FILE) as f: return json.load(f)
    except: return {}

def _dd_save(data):
    with open(_DEADDROP_FILE,"w") as f: json.dump(data, f)

def _dd_xor(text_bytes, key_bytes):
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i,b in enumerate(text_bytes))

@app.route("/deaddrop/create", methods=["POST"])
def deaddrop_create():
    msg  = (request.json or {}).get("message","").strip()
    burn = (request.json or {}).get("burn_after_read", True)
    ttl  = int((request.json or {}).get("ttl_hours", 24))
    if not msg: return jsonify({"error":"No message"})
    if len(msg) > 4000: return jsonify({"error":"Message too long (4000 char max)"})
    code  = _secrets.token_urlsafe(10)
    key   = hashlib.sha256(code.encode()).digest()
    cipher= base64.urlsafe_b64encode(_dd_xor(msg.encode("utf-8"), key)).decode()
    drops = _dd_load()
    drops[code] = {"cipher": cipher, "burn": burn, "created": time.time(), "ttl": ttl*3600, "reads": 0}
    _dd_save(drops)
    return jsonify({"code": code, "ttl_hours": ttl})

@app.route("/deaddrop/retrieve", methods=["POST"])
def deaddrop_retrieve():
    code = (request.json or {}).get("code","").strip()
    if not code: return jsonify({"error":"No code"})
    drops = _dd_load()
    drop  = drops.get(code)
    if not drop: return jsonify({"error":"Dead drop not found or already burned"})
    if time.time() - drop["created"] > drop["ttl"]:
        drops.pop(code); _dd_save(drops)
        return jsonify({"error":"Dead drop expired"})
    key  = hashlib.sha256(code.encode()).digest()
    try: msg = _dd_xor(base64.urlsafe_b64decode(drop["cipher"]), key).decode("utf-8")
    except: return jsonify({"error":"Decryption failed"})
    drop["reads"] += 1
    if drop["burn"]: drops.pop(code)
    _dd_save(drops)
    return jsonify({"message": msg, "burned": drop["burn"], "reads": drop["reads"]})


# ══════════════════════════════════════════════════════
# OP PLANNER
# ══════════════════════════════════════════════════════
_OPS_FILE = "/tmp/ops.json"

def _ops_load():
    try:
        with open(_OPS_FILE) as f: return json.load(f)
    except: return []

def _ops_save(data):
    with open(_OPS_FILE,"w") as f: json.dump(data, f)

@app.route("/ops/list", methods=["GET"])
def ops_list():
    return jsonify(_ops_load())

@app.route("/ops/create", methods=["POST"])
def ops_create():
    d = request.json or {}
    op = {
        "id": f"op_{int(time.time()*1000)}",
        "codename": d.get("codename","UNNAMED OP").upper(),
        "target":   d.get("target",""),
        "scope":    d.get("scope",""),
        "status":   "ACTIVE",
        "created":  time.strftime("%Y-%m-%dT%H:%M:%S"),
        "tasks":    []
    }
    ops = _ops_load(); ops.append(op); _ops_save(ops)
    return jsonify({"ok":True,"op":op})

@app.route("/ops/task/add", methods=["POST"])
def ops_task_add():
    d = request.json or {}
    ops = _ops_load()
    op  = next((o for o in ops if o["id"]==d.get("op_id")), None)
    if not op: return jsonify({"error":"Op not found"})
    task = {"id":f"task_{int(time.time()*1000)}","lane":d.get("lane","RECON"),
            "title":d.get("title",""),"notes":d.get("notes",""),"assignee":d.get("assignee",""),"done":False}
    op["tasks"].append(task); _ops_save(ops)
    return jsonify({"ok":True,"task":task})

@app.route("/ops/task/update", methods=["POST"])
def ops_task_update():
    d = request.json or {}
    ops = _ops_load()
    for op in ops:
        if op["id"] == d.get("op_id"):
            for task in op["tasks"]:
                if task["id"] == d.get("task_id"):
                    if "done"  in d: task["done"]  = d["done"]
                    if "lane"  in d: task["lane"]  = d["lane"]
                    if "notes" in d: task["notes"] = d["notes"]
                    break
    _ops_save(ops)
    return jsonify({"ok":True})

@app.route("/ops/delete", methods=["POST"])
def ops_delete():
    op_id = (request.json or {}).get("op_id","")
    ops   = [o for o in _ops_load() if o["id"] != op_id]
    _ops_save(ops)
    return jsonify({"ok":True})


# ══════════════════════════════════════════════════════
# GHOST PROTOCOL — anonymous squad voting
# ══════════════════════════════════════════════════════
_GHOST_FILE = "/tmp/ghost_proposals.json"

def _ghost_load():
    try:
        with open(_GHOST_FILE) as f: return json.load(f)
    except: return []

def _ghost_save(d):
    with open(_GHOST_FILE,"w") as f: json.dump(d, f)

@app.route("/ghost/proposals", methods=["GET"])
def ghost_proposals():
    props = _ghost_load()
    # Strip voter identities from response
    safe = []
    for p in props:
        safe.append({k:v for k,v in p.items() if k != "voter_ids"})
    return jsonify(safe)

@app.route("/ghost/propose", methods=["POST"])
def ghost_propose():
    d = request.json or {}
    prop = {
        "id":       f"gh_{int(time.time()*1000)}",
        "title":    d.get("title","").strip()[:120],
        "detail":   d.get("detail","").strip()[:500],
        "type":     d.get("type","CTF"),
        "proposer": d.get("proposer","UNKNOWN").upper()[:20],
        "created":  time.strftime("%Y-%m-%dT%H:%M:%S"),
        "yes":0, "no":0, "abstain":0,
        "voter_ids":[], "status":"OPEN"
    }
    if not prop["title"]: return jsonify({"error":"Title required"})
    props = _ghost_load(); props.append(prop); _ghost_save(props)
    return jsonify({"ok":True,"id":prop["id"]})

@app.route("/ghost/vote", methods=["POST"])
def ghost_vote():
    d      = request.json or {}
    prop_id= d.get("id","")
    vote   = d.get("vote","")           # yes / no / abstain
    voter  = d.get("voter","UNKNOWN").upper()
    if vote not in ("yes","no","abstain"): return jsonify({"error":"Invalid vote"})
    props  = _ghost_load()
    prop   = next((p for p in props if p["id"]==prop_id), None)
    if not prop: return jsonify({"error":"Not found"})
    if voter in prop.get("voter_ids",[]): return jsonify({"error":"Already voted"})
    prop[vote] += 1
    prop.setdefault("voter_ids",[]).append(voter)
    total = prop["yes"]+prop["no"]+prop["abstain"]
    if prop["yes"] > total/2: prop["status"] = "ACCEPTED"
    elif prop["no"] > total/2: prop["status"] = "REJECTED"
    _ghost_save(props)
    return jsonify({"ok":True,"status":prop["status"],"yes":prop["yes"],"no":prop["no"],"total":total})


# ══════════════════════════════════════════════════════
# DISPATCH BOARD — encrypted squad dispatches
# ══════════════════════════════════════════════════════
_DISPATCH_FILE = "/tmp/dispatches.json"

def _dispatch_load():
    try:
        with open(_DISPATCH_FILE) as f: return json.load(f)
    except: return []

def _dispatch_save(d):
    with open(_DISPATCH_FILE,"w") as f: json.dump(d, f)

@app.route("/dispatch/feed", methods=["GET"])
def dispatch_feed():
    return jsonify(list(reversed(_dispatch_load()))[:50])

@app.route("/dispatch/post", methods=["POST"])
def dispatch_post():
    d = request.json or {}
    msg  = d.get("message","").strip()[:2000]
    op   = d.get("operator","UNKNOWN").upper()[:20]
    tag  = d.get("tag","FIELD REPORT")[:30]
    if not msg: return jsonify({"error":"Empty message"})
    key  = hashlib.sha256(f"{op}{time.time()}".encode()).digest()
    cipher = base64.urlsafe_b64encode(
        bytes(b ^ key[i%len(key)] for i,b in enumerate(msg.encode("utf-8")))
    ).decode()
    entry = {
        "id":       f"dsp_{int(time.time()*1000)}",
        "operator": op,
        "tag":      tag,
        "cipher":   cipher,
        "key_hint": base64.urlsafe_b64encode(key[:4]).decode(),
        "ts":       time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plaintext": msg,    # stored for display; real impl would be client-side only
    }
    dispatches = _dispatch_load(); dispatches.append(entry); _dispatch_save(dispatches)
    return jsonify({"ok":True,"id":entry["id"]})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", debug=False, port=port)
