#!/usr/bin/env python3
"""meta_oracle.py -- TRUSTWORTHY verification of a coder-written exploit probe.

The gap it closes: (1) test_suggestions replays ONE parsed request, so a probe's replay-loop/concurrency
never actually runs -> no accumulation, no breach; (2) even with an authoritative SQL oracle (G34), a coder
can write a PERMISSIVE SELECT that returns rows regardless -> a false 'win'.

The meta-oracle makes a win VERIFIABLE and exploit-CAUSED:
  1. extract the coder's ORACLE SQL (the invariant check) + the full CODE.
  2. BASELINE: run the SQL now -- it MUST return EMPTY. If it returns rows, the oracle is loose/permissive
     (or the invariant is already broken) -> NOT a trustworthy win: verdict 'invalid_oracle'.
  3. EXECUTE the coder's FULL code (its loop/concurrency), AUTHENTICATED, non-destructive-guarded.
  4. AFTER: run the SQL again -- it MUST now return ROWS.
  META-WIN iff baseline EMPTY and after ROWS: the exploit CAUSED the invariant to break. Anything else is
  no_breach / invalid_oracle / code_error -- never a win.

Doctrine: contained mirror only; the code is guarded (create/read for proof, no erase/DROP/DELETE); the
auth session is injected so the probe reaches authenticated surface without logging in itself.
"""
import os, re, sys, json, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_SEL = re.compile(r"(SELECT\b.+?;)", re.I | re.S)


def extract_sql(probe):
    m = _SEL.search(probe or "")
    return m.group(1).strip() if m else None


def extract_code(probe):
    m = re.search(r"CODE\s*[-:]?\s*(.+?)(?:\n\s*ORACLE|\Z)", probe or "", re.I | re.S)
    c = (m.group(1) if m else "").strip()
    c = re.sub(r"```[a-zA-Z]*", "", c).strip("`\n ")
    return c


def _db(sql):
    import test_suggestions as TS
    return TS.db(sql)


def _rows(res):
    return bool((res or "").strip()) and not str(res).startswith("[db error") and (res or "").strip() not in ("0", "f", "false", "[]")


# auth-injecting runner: logs in, routes every requests.* call through the authenticated session and
# rewrites the host to the contained mirror, then execs the probe code. Non-destructive guard applied first.
_RUNNER = r'''
import os, sys, re, json, requests
try: requests.packages.urllib3.disable_warnings()
except Exception: pass
BASE=os.environ["AEGIS_TARGET"]
_s=requests.Session(); _s.verify=False
acc=json.loads(os.environ.get("AEGIS_ROLE_MAP","{}")).get(os.environ.get("PROBE_ROLE","owner"),"Owner User")
try: _s.post(BASE+"/api/auth/login", json={"name":acc,"pin":os.environ.get("AEGIS_TEST_PIN","123456")}, timeout=15)
except Exception as e: print("login-fail",e)
_orig=_s.request
def _route(method,url,**kw):
    kw.setdefault("verify",False); kw.setdefault("timeout",20)
    if isinstance(url,str) and url.startswith("http"):
        path=re.sub(r"^https?://[^/]+","",url); url=BASE+path if path.startswith("/") else url
    elif isinstance(url,str) and url.startswith("/"):
        url=BASE+url
    return _orig(method,url,**kw)
for _m in ("get","post","put","patch","delete","head","options"):
    setattr(requests,_m,(lambda mm:(lambda url,**k:_route(mm.upper(),url,**k)))(_m))
requests.request=lambda method,url,**k:_route(method,url,**k)
requests.Session=lambda *a,**k:_s
code=open(sys.argv[1],encoding="utf-8").read()
try:
    exec(compile(code,"<probe>","exec"),{"requests":requests,"__name__":"__main__","BASE":BASE,"session":_s})
except SystemExit: pass
except Exception as e:
    print("PROBE-EXC:",type(e).__name__,str(e)[:200])
'''


def run_probe_code(code, role="owner", timeout=90):
    """Exec the coder's FULL code, authenticated + host-forced + non-destructive-guarded. Returns (ok, out)."""
    import test_suggestions as TS
    ok, why = TS.guard(code)                       # reject destructive (erase/DROP/DELETE/TRUNCATE) code
    if not ok:
        return False, f"[guard blocked] {why}"
    with tempfile.TemporaryDirectory(prefix="meta-") as d:
        cf = os.path.join(d, "probe.py"); open(cf, "w", encoding="utf-8").write(code)
        rf = os.path.join(d, "runner.py"); open(rf, "w", encoding="utf-8").write(_RUNNER)
        env = dict(os.environ, PYTHONUTF8="1", PROBE_ROLE=role)
        try:
            p = subprocess.run([sys.executable, rf, cf], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout, env=env)
            return True, (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return False, f"[exec error] {e}"


def verify(probe, role="owner"):
    """Meta-verify a probe. Returns dict: verdict in
    {META_WIN, no_breach, invalid_oracle(baseline non-empty), no_sql, no_code, code_error}."""
    sql = extract_sql(probe)
    code = extract_code(probe)
    if not sql:
        return {"verdict": "no_sql"}
    if not code or "requests" not in code:
        return {"verdict": "no_code"}
    base = _db(sql)
    if str(base).startswith("[db error"):
        return {"verdict": "invalid_oracle", "reason": "oracle SQL is broken (db error)", "baseline": base[:100]}
    if _rows(base):
        return {"verdict": "invalid_oracle", "reason": "baseline non-empty (loose oracle or already-broken)",
                "baseline": base[:80]}
    ok, out = run_probe_code(code, role=role)
    if not ok:
        return {"verdict": "code_error", "detail": out[:200]}
    after = _db(sql)
    if str(after).startswith("[db error"):
        return {"verdict": "invalid_oracle", "reason": "oracle SQL broke after exec", "after": after[:100]}
    if _rows(after):
        # trustworthy: same SQL was EMPTY on baseline and returns ROWS only after the exploit ran
        return {"verdict": "META_WIN", "baseline_empty": True, "after": after[:120], "exec_tail": out[-160:]}
    return {"verdict": "no_breach", "after_empty": True, "exec_tail": out[-160:]}


if __name__ == "__main__":
    import test_suggestions as TS  # noqa
    txt = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(verify(txt, role=os.environ.get("PROBE_ROLE", "owner")), indent=1))
