#!/usr/bin/env python3
"""compare_recall.py -- COMPARATIVE recall benchmark: score AEGIS vs widely-regarded OSS scanners on the SAME
target and the SAME known-bug truth-set (a recall_benchmarks manifest), so "AEGIS got X/6" becomes an
apples-to-apples "AEGIS X/6 vs ZAP/nuclei/sqlmap/nikto/wapiti Y/6".

Each OSS tool runs against the manifest target (in Kali), its output is flattened to searchable finding
BLOBS, and every expected bug is RECALLED iff some blob matches its class (via a class->keyword map) AND
(its surface OR any match token) -- the SAME forgiving rule recall_suite uses. AEGIS's own recall is read
from a prior recall_suite JSON (--aegis-json). Memory-safe: tools run ONE AT A TIME (ZAP heaviest, optional).

Fair-use notes baked into the report: tools differ in scope (sqlmap=injection only, nikto=server/headers,
nuclei=templates, wapiti/ZAP=general DAST). The telling signal is the authz/logic classes (idor/BAC) that
DAST tools are weak on -- where AEGIS should differentiate -- not sqli/xss where the specialists are strong.

Usage: python operator/compare_recall.py --manifest recall_benchmarks/juice-shop.json [--aegis-json f.json]
       [--tools nuclei,sqlmap,nikto,wapiti,zap] [--json] [--out FILE]
"""
from __future__ import annotations
import argparse, json, os, re, shlex, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WSL = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")

# our class -> the vocabulary OSS tools actually use (lowercased substring match)
CLASS_KW = {
    "injection": ["sql injection", "sqli", "injectable", "sql-injection", "error-based", "boolean-based", "union query"],
    "xss": ["xss", "cross site scripting", "cross-site scripting", "reflected xss", "dom"],
    "authz": ["access control", "authorization", "authoriz", "broken access", "forbidden bypass", "idor", "bola"],
    "idor": ["idor", "insecure direct object", "bola", "object level", "basket"],
    "security_headers": ["header", "x-frame-options", "content-security", "hsts", "strict-transport",
                         "x-content-type", "clickjack", "cookie", "directory listing", "ftp", "backup", "exposure"],
    "auth_session": ["jwt", "json web token", "session", "authentication", "token", "weak secret", "whoami"],
    # ExploitGym trust-chain / scenario classes (so match_expected + the tool bake-off cover them too)
    "ssrf": ["ssrf", "server-side request forgery", "server side request", "metadata", "169.254",
             "internal request", "url fetch", "outbound request"],
    "mass_assignment": ["mass assignment", "mass-assignment", "over-post", "overpost", "unexpected field",
                        "extra field", "unrestricted field", "role", "privilege field"],
    "privesc": ["privilege escalation", "privesc", "vertical privilege", "role escalation", "broken access", "admin"],
    "misconfig": ["misconfiguration", "misconfig", "exposed", "default cred", "debug mode", "verbose error",
                  "directory listing", "backup", "open config", "admin", ".env", ".git", "config file",
                  "discovered path"],
    "supply_chain": ["outdated", "known vulnerab", "cve-", "vulnerable dependency", "component with known",
                     "known-cve", "dependency"],
    "rce": ["remote code execution", "rce", "command injection", "os command", "code execution", "os-command"],
    "traversal": ["path traversal", "directory traversal", "lfi", "local file inclusion", "../", "arbitrary file read"],
}


def _kali(cmd, timeout):
    env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    argv = (["wsl", "-d", WSL, "-u", "root", "--"] if os.name == "nt" else []) + ["bash", "-lc", cmd]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=env)
        return (p.stdout or "") + "\n" + (p.stderr or "")
    except Exception as e:
        return f"[run error: {e}]"


# ---- per-tool adapters: run the tool, return (blobs[list[str]], note) ----
def adapt_nuclei(t):
    # A fresh Kali often has NO templates -> the old `-duc` (disable-update-check) left the DB empty and
    # nuclei "ran" but scanned nothing ("0 templates"). Ensure the template DB exists first (bounded), then
    # scan WITHOUT -duc so it self-updates if needed.
    _kali("nuclei -update-templates -silent 2>/dev/null; true", 240)
    out = _kali(f"nuclei -u {t} -jsonl -silent -nc -timeout 8 -rl 40 2>/dev/null | head -c 200000", 300)
    blobs = []
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                d = json.loads(ln)
                info = d.get("info", {}) if isinstance(d.get("info"), dict) else {}
                blobs.append(" ".join(str(x) for x in [d.get("template-id"), info.get("name"),
                             " ".join(info.get("tags") or []) if isinstance(info.get("tags"), list) else info.get("tags"),
                             info.get("severity"), d.get("matched-at")]))
            except Exception:
                pass
    n = len(blobs)
    return blobs, ("%d matches" % n if n else "0 matches (if templates missing, run: nuclei -update-templates)")


def adapt_sqlmap(t):
    # target juice-shop's known login SQLi (auth-bypass in the email field). Feed sqlmap a RAW REQUEST FILE
    # with a '*' injection marker on email, NOT -u/--data with inline JSON: the nested quotes were mangled
    # across host->WSL->bash and put sqlmap into "multiple targets mode" (it never tested the param). The
    # request file avoids all shell-quoting and pins the injection point precisely. boolean-based is the
    # technique that catches an auth-bypass differential (' OR 1=1-- returns a token, ' AND 1=2 does not).
    # -r request-file mode fell back to STDIN in this non-TTY WSL context (tested: never parsed the file).
    # Use -u + --data with a '*' marker on the email JSON value instead. KEY: --ignore-code=401 so sqlmap
    # tests PAST the 401-on-bad-creds baseline (the boolean payload flips 401 -> 200+token, the differential
    # it keys on); --dbms=sqlite (juice-shop's DB) speeds detection. Confirmed: finds the login SQLi.
    base = t.rstrip("/")
    cmd = ("sqlmap -u '" + base + "/rest/user/login' "
           "--data='{\"email\":\"x*\",\"password\":\"y\"}' "
           "--headers='Content-Type: application/json' "
           "--dbms=sqlite --ignore-code=401 --batch --technique=B --level 2 --risk 2 "
           "--flush-session --disable-coloring 2>&1 | tail -c 6000")
    out = _kali(cmd, 360)
    vuln = bool(re.search(r"is vulnerable|injectable|parameter '[^']+' is|sqlmap identified", out, re.I))
    # surface the tail on a non-hit so a fast/empty exit (didn't actually run) is diagnosable, not silently 0/6
    tail = " ".join((out or "").split())[-180:]
    return (["sql injection sqli /rest/user/login (sqlmap confirmed)"] if vuln else []), \
           ("vulnerable" if vuln else f"no injection [diag: {tail}]")


def adapt_nikto(t):
    out = _kali(f"nikto -h {t} -maxtime 240 -ask no 2>/dev/null | head -c 120000", 300)
    blobs = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("+")]
    return blobs, ("%d notes" % len(blobs))


def adapt_wapiti(t):
    out = _kali(f"wapiti -u {t} -f json -o /tmp/wapiti.json --flush-session -m 'xss,sql,exec,file,redirect' "
                f"--max-scan-time 240 2>/dev/null; cat /tmp/wapiti.json 2>/dev/null | head -c 200000", 360)
    blobs = []
    m = re.search(r"\{.*\}", out, re.S)
    if m:
        try:
            d = json.loads(m.group(0)); vulns = d.get("vulnerabilities", {})
            for cat, items in (vulns.items() if isinstance(vulns, dict) else []):
                for it in (items or []):
                    blobs.append(f"{cat} {it.get('path','')} {it.get('info','')}")
        except Exception:
            pass
    return blobs, ("%d vulns" % len(blobs))


def adapt_zap(t):
    img = _kali("docker images --format '{{.Repository}}' | grep -i zap | head -1", 30).strip()
    if "zap" not in img.lower():
        return [], "SKIP (image not pulled: docker pull zaproxy/zap-stable)"
    # BUG this fixes: the old adapter wrote the report inside a `--rm` container, then a SECOND `--rm`
    # container tried to `cat` it -- but the first container (and its /tmp/zap.json) was already destroyed,
    # so it always read nothing = "0 alerts" in ~1s. Fix: MOUNT a host workdir into ONE container so the
    # JSON persists on the host, write the report there (-J is relative to /zap/wrk), then read the HOST file.
    # zap-baseline.py EXITS NON-ZERO when it reports WARN/FAIL alerts (that's a finding, not an error); `-I`
    # keeps it from failing the process on warnings. `-m 3` = 3-minute spider.
    work = "/tmp/zapwork_%d" % int(time.time())
    cmd = (f"mkdir -p {work}; chmod 777 {work}; "
           f"docker run --rm --network host -v {work}:/zap/wrk:rw {img} "
           f"zap-baseline.py -t {t} -J zap.json -m 3 -I 2>&1 | tail -c 4000; "
           f"echo '----ZAPJSON----'; cat {work}/zap.json 2>/dev/null | head -c 300000")
    out = _kali(cmd, 900)
    payload = out.split("----ZAPJSON----", 1)[-1]
    blobs = []
    m = re.search(r"\{.*\}", payload, re.S)
    if m:
        try:
            d = json.loads(m.group(0))
            for site in d.get("site", []):
                for a in site.get("alerts", []):
                    blobs.append(f"{a.get('alert','')} {a.get('name','')} {a.get('riskdesc','')}")
        except Exception:
            pass
    if blobs:
        return blobs, "%d alerts" % len(blobs)
    # no alerts parsed: surface a diag tail so a container/launch failure is visible, not a silent 0/6
    diag = " ".join((out.split("----ZAPJSON----", 1)[0] or "").split())[-180:]
    return [], f"0 alerts [diag: {diag}]"


ADAPTERS = {"nuclei": adapt_nuclei, "sqlmap": adapt_sqlmap, "nikto": adapt_nikto, "wapiti": adapt_wapiti, "zap": adapt_zap}


def adapt_semgrep(src):
    """SAST adapter (grey-box): run Semgrep against the target's OWN source dir `src` (a path in Kali),
    return (blobs, note). Non-destructive/static -- reads code, executes nothing. Complements the DAST
    tools: it can see the sink (e.g. an unguarded urlopen or a blind dict-merge) that black-box scanners miss."""
    import shlex as _sh
    out = _kali(f"semgrep --config auto --json --quiet --timeout 60 --max-target-bytes 2000000 "
                f"{_sh.quote(src)} 2>/dev/null | head -c 300000", 300)
    blobs = []
    m = re.search(r"\{.*\}", out, re.S)
    if m:
        try:
            d = json.loads(m.group(0))
            for r in (d.get("results") or []):
                ex = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
                meta = ex.get("metadata", {}) if isinstance(ex.get("metadata"), dict) else {}
                cwe = meta.get("cwe")
                blobs.append(" ".join(str(x) for x in [r.get("check_id"), ex.get("message"), r.get("path"),
                             " ".join(cwe) if isinstance(cwe, list) else cwe, " ".join(meta.get("owasp") or []) if isinstance(meta.get("owasp"), list) else meta.get("owasp")]))
        except Exception:
            pass
    return blobs, ("%d findings" % len(blobs) if blobs else "0 (needs: pip install semgrep)")


# source-based (SAST) adapters take a SOURCE DIR path, not a URL target -- kept separate from the DAST ADAPTERS
SOURCE_ADAPTERS = {"semgrep": adapt_semgrep}


# ---- fuller-parity Kali arsenal (individual find/verify tools -- the same scanners HexStrike wraps, run
#      one-at-a-time and non-destructively; per-tool attribution the autonomous orchestration would obscure) ----
def adapt_nmap(t):
    """Recon: service/version + SAFE default NSE scripts (non-intrusive; excludes the intrusive/dos categories)."""
    from urllib.parse import urlparse
    host = urlparse(t if "//" in t else "//" + t).hostname or t
    out = _kali(f"nmap -sV -Pn --script=default -T4 --host-timeout 180s {shlex.quote(host)} 2>/dev/null | head -c 100000", 300)
    blobs = []
    for ln in out.splitlines():
        s = ln.strip()
        if re.match(r"^\d+/(tcp|udp)\s+open", s):          # e.g. "80/tcp open http nginx 1.25"
            blobs.append(s)
        elif s.startswith("|"):                            # NSE script output lines
            blobs.append(s.lstrip("| ").strip())
    return blobs, ("%d ports/notes" % len(blobs) if blobs else "0 (nothing open / nmap not installed)")


def adapt_ffuf(t):
    """Content discovery (non-destructive GETs): brute a common wordlist -> exposed paths/files (misconfig)."""
    base = t.rstrip("/")
    cmd = ("WL=/usr/share/seclists/Discovery/Web-Content/common.txt; [ -f \"$WL\" ] || WL=/usr/share/wordlists/dirb/common.txt; "
           f"ffuf -u {shlex.quote(base)}/FUZZ -w \"$WL\" -mc 200,204,301,302,307,401,403 -t 40 -maxtime 180 "
           f"-of csv -o /tmp/ffuf_bo.csv -s 2>/dev/null; cat /tmp/ffuf_bo.csv 2>/dev/null | head -c 100000")
    out = _kali(cmd, 240)
    blobs = []
    for ln in out.splitlines():
        s = ln.strip()
        if s and "," in s and not s.lower().startswith(("fuzzword", "url,", "input.")):   # csv rows, skip header
            blobs.append("discovered path " + s)
    return blobs, ("%d paths" % len(blobs) if blobs else "0 (nothing / ffuf or wordlist missing)")


def adapt_dalfox(t):
    """Reflected/DOM XSS detection (sends probe payloads; non-destructive, no persistence)."""
    out = _kali(f"dalfox url {shlex.quote(t)} --skip-bav --timeout 8 --worker 20 --silence 2>/dev/null | head -c 100000", 240)
    blobs = [s.strip() for s in out.splitlines()
             if s.strip() and ("[POC]" in s or "[V]" in s or "[VULN]" in s.upper() or "xss" in s.lower())]
    return blobs, ("%d xss signals" % len(blobs) if blobs else "0 (none / dalfox not installed)")


ADAPTERS.update({"nmap": adapt_nmap, "ffuf": adapt_ffuf, "dalfox": adapt_dalfox})


# ---- BlackArch/Arch discovery arsenal (routed through distro_backend: run natively where the tool lives --
#      Kali if present, else the BlackArch container -- so we don't source-build/OOM Kali). Find/verify only:
#      attack-surface enumeration (crawl / historical URLs / params / tech). Non-destructive GETs. ----
def _distro_cmd(tool, cmd, timeout=240):
    """Run a raw command for `tool` in the backend that has it (Kali direct, else BlackArch), via
    distro_backend.route(); falls back to Kali if the router isn't importable. Returns combined output."""
    try:
        import distro_backend as _DB
        if _DB.route(tool) == "kali":
            return _kali(cmd, timeout)
        rc, out, err = _DB.run_in_blackarch(cmd, ensure_tools=[tool], timeout=timeout)
        return (out or "") + "\n" + (err or "")
    except Exception:
        return _kali(cmd, timeout)


def _host_of(t):
    from urllib.parse import urlparse
    return urlparse(t if "//" in t else "//" + t).hostname or t


def _urls(out):
    return [ln.strip() for ln in (out or "").splitlines() if ln.strip().startswith("http")]


def adapt_katana(t):
    """Crawler -> discovered endpoints/attack surface (recon)."""
    out = _distro_cmd("katana", f"katana -u {shlex.quote(t)} -silent -jc -d 2 -timeout 8 2>/dev/null | head -c 200000")
    u = _urls(out)
    return [f"discovered endpoint {x}" for x in u[:800]], ("%d urls" % len(u) if u else "0 (katana none / not installed)")


def adapt_gau(t):
    """Historical URLs from public archives (recon; passive)."""
    out = _distro_cmd("gau", f"gau {shlex.quote(_host_of(t))} --threads 5 2>/dev/null | head -c 200000")
    u = _urls(out)
    return [f"historical url {x}" for x in u[:800]], ("%d urls" % len(u) if u else "0 (gau none / not installed)")


def adapt_waybackurls(t):
    """Wayback Machine URLs (recon; passive)."""
    out = _distro_cmd("waybackurls", f"waybackurls {shlex.quote(_host_of(t))} 2>/dev/null | head -c 200000")
    u = _urls(out)
    return [f"wayback url {x}" for x in u[:800]], ("%d urls" % len(u) if u else "0 (waybackurls none / not installed)")


def adapt_hakrawler(t):
    """Crawler (reads a seed URL on stdin) -> discovered endpoints (recon)."""
    out = _distro_cmd("hakrawler", f"echo {shlex.quote(t)} | hakrawler -d 2 -u 2>/dev/null | head -c 200000")
    u = _urls(out)
    return [f"crawled endpoint {x}" for x in u[:800]], ("%d urls" % len(u) if u else "0 (hakrawler none / not installed)")


def adapt_x8(t):
    """Hidden HTTP parameter discovery (recon; expands the tested surface for other classes)."""
    wl = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    out = _distro_cmd("x8", f"WL={wl}; [ -f \"$WL\" ] || WL=/usr/share/wordlists/dirb/common.txt; "
                            f"x8 -u {shlex.quote(t)} -w \"$WL\" 2>/dev/null | head -c 80000")
    blobs = [ln.strip() for ln in out.splitlines()
             if ln.strip() and ("param" in ln.lower() or "found" in ln.lower() or ln.strip().startswith("http"))]
    return [f"hidden parameter {b}" for b in blobs[:300]], ("%d param signals" % len(blobs) if blobs else "0 (x8 none / not installed)")


def adapt_gowitness(t):
    """Screenshot + tech/title/status capture (recon; server fingerprint)."""
    out = _distro_cmd("gowitness", f"gowitness single {shlex.quote(t)} --screenshot-path /tmp/gw 2>&1 | head -c 60000")
    blobs = [ln.strip() for ln in out.splitlines()
             if ln.strip() and any(k in ln.lower() for k in ("title", "server", "status", "tech", "http"))]
    return [f"tech/fingerprint {b}" for b in blobs[:120]], ("%d notes" % len(blobs) if blobs else "0 (gowitness none / not installed)")


ADAPTERS.update({"katana": adapt_katana, "gau": adapt_gau, "waybackurls": adapt_waybackurls,
                 "hakrawler": adapt_hakrawler, "x8": adapt_x8, "gowitness": adapt_gowitness})


def match_expected(expected, blobs):
    """recall_suite's forgiving rule: recalled iff a blob contains the class keyword AND (surface OR a match token)."""
    text = [b.lower() for b in blobs]
    per = []
    for e in expected:
        kws = CLASS_KW.get(e.get("class", ""), [e.get("class", "")])
        toks = [str(x).lower() for x in ([e.get("surface")] + (e.get("match") or [])) if x]
        hit = any(any(k in b for k in kws) and (not toks or any(tok in b for tok in toks)) for b in text)
        # fallback: class keyword alone (some tools don't echo the surface) -> weaker match, still counts
        hit = hit or any(any(k in b for k in kws) for b in text)
        per.append({"id": e.get("id"), "class": e.get("class"), "recalled": hit})
    return per


def aegis_row(aegis_json, expected):
    try:
        raw = open(aegis_json, encoding="utf-8", errors="replace").read()   # tolerate log preamble before the JSON
        # Parse the WHOLE file first; only strip a log preamble/postamble on failure. The old
        # array-first greedy regex matched an INNER array (e.g. per_expected) instead of the
        # top-level object, so d[0] became a per_expected entry with no per_expected key -> pe={}
        # -> silent 0/6 with a truthy "recall_suite" note (not an exception, not all-None).
        try:
            d = json.loads(raw)
        except Exception:
            # log preamble before the JSON -> scan for the first position that actually PARSES
            # (a preamble tag like "[recall]" has brackets, so don't just grab the first "{"/"[").
            dec = json.JSONDecoder(); d = None
            for k, ch in enumerate(raw):
                if ch in "{[":
                    try:
                        d, _ = dec.raw_decode(raw[k:]); break
                    except Exception:
                        continue
            if d is None:
                raise ValueError("no JSON value found in aegis-json")
        d = d[0] if isinstance(d, list) else d
        pe = {p.get("id"): p.get("recalled") for p in (d.get("per_expected") or [])}
        per = [{"id": e.get("id"), "class": e.get("class"), "recalled": bool(pe.get(e.get("id")))} for e in expected]
        return per, "recall_suite"
    except Exception as e:
        return [{"id": e.get("id"), "class": e.get("class"), "recalled": None} for e in expected], f"n/a ({str(e)[:40]})"


def _one_tool(tool, target, expected):
    t0 = time.time()
    blobs, note = ADAPTERS[tool](target)
    per = match_expected(expected, blobs)
    return tool, {"per": per, "note": f"{note} ({time.time()-t0:.0f}s)"}


def run(manifest_path, tools, aegis_json=None, parallel=False):
    man = json.load(open(manifest_path, encoding="utf-8"))
    target = man.get("target"); expected = man.get("expected") or []
    rows = {}
    if aegis_json:
        per, note = aegis_row(aegis_json, expected)
        rows["AEGIS"] = {"per": per, "note": note}
    tools = [t for t in tools if t in ADAPTERS]
    if parallel:
        print(f"[compare] running {len(tools)} tools IN PARALLEL vs {target} ...", flush=True)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(len(tools), 4)) as ex:
            for tool, r in ex.map(lambda t: _one_tool(t, target, expected), tools):
                rows[tool] = r
                print(f"[compare]   {tool}: {sum(1 for p in r['per'] if p['recalled'])}/{len(expected)}  ({r['note']})", flush=True)
    else:
        for tool in tools:
            print(f"[compare] running {tool} vs {target} ...", flush=True)
            _, r = _one_tool(tool, target, expected)
            rows[tool] = r
            print(f"[compare]   {tool}: {sum(1 for p in r['per'] if p['recalled'])}/{len(expected)}  ({r['note']})", flush=True)
    return target, expected, rows


def render(target, expected, rows):
    # ASCII-ONLY output: the markdown FILE is consumed by other tools/viewers/git across cp1252 and utf-8
    # boundaries, so non-ASCII glyphs (checkmark / em-dash / middle-dot) mojibake somewhere downstream even
    # when this process writes utf-8. Use plain ASCII markers so the report is byte-portable everywhere.
    ids = [e.get("id") for e in expected]
    out = [f"# COMPARATIVE RECALL -- {target}", "",
           f"truth-set ({len(expected)}): " + ", ".join(f"{e['id']}({e['class']})" for e in expected), "",
           "| tool | recall | " + " | ".join(ids) + " | note |",
           "|---|---|" + "|".join(["---"] * len(ids)) + "|---|"]
    for tool, r in rows.items():
        per = {p["id"]: p["recalled"] for p in r["per"]}
        n = sum(1 for p in r["per"] if p["recalled"])
        cells = " | ".join("YES" if per.get(i) else ("n/a" if per.get(i) is None else "no") for i in ids)
        # A row whose cells are ALL None means "not run / not parsed" -- do NOT render it as a real
        # 0/N score (that mislabels an unparsed AEGIS --aegis-json as an actual zero, the exact bug
        # that made a valid 2/6 AEGIS run show as 0/6). Show recall as n/a instead.
        recall = "n/a" if all(p["recalled"] is None for p in r["per"]) else f"{n}/{len(expected)}"
        out.append(f"| **{tool}** | {recall} | " + cells + f" | {r['note']} |")
    out += ["", "_YES=recalled, no=missed, n/a=not run. Fair-use: sqlmap=injection-only, nikto=server/headers, "
            "nuclei=templates, wapiti/ZAP=general DAST. The differentiating classes are idor/authz (DAST-weak)._"]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="comparative recall: AEGIS vs OSS scanners on one truth-set")
    ap.add_argument("--manifest", default=os.path.join(HERE, "recall_benchmarks", "juice-shop.json"))
    ap.add_argument("--tools", default="nuclei,sqlmap,nikto,wapiti")
    ap.add_argument("--aegis-json", default=None, help="a recall_suite JSON to read AEGIS's recall from")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--parallel", action="store_true", help="run the OSS tools concurrently")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    tools = [t.strip() for t in a.tools.split(",") if t.strip()]
    target, expected, rows = run(a.manifest, tools, a.aegis_json, parallel=a.parallel)
    if a.json:
        print(json.dumps({"target": target, "rows": rows}, indent=2)); return
    md = render(target, expected, rows)
    out = a.out or os.path.join(HERE, "..", "COMPARE_RECALL_juice-shop.md")
    open(out, "w", encoding="utf-8").write(md)
    try:                                   # a Windows cp1252 console can't encode the check-mark glyph
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        print("\n" + md)
    except UnicodeEncodeError:
        print("\n" + md.encode("ascii", "replace").decode("ascii"))
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
