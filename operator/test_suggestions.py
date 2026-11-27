#!/usr/bin/env python3
"""
test_suggestions.py -- execute + verify the board's CODE-FLAVOURED attack suggestions.

The board's exploit-code specialists (qwen2.5-coder via its baked role, and DS when it uses the
same shape) emit suggestions as blocks of:
    TARGET  - HTTP method + endpoint + field
    CODE    - a runnable curl / SQL snippet
    ORACLE  - the check that proves pass/fail (an HTTP status/body assert, or a SELECT)

This harness parses those blocks, runs each against the CONTAINED twin, checks the oracle, and
records verified/rejected through the shared findings layer -- attributed to the source model, so
DS's and qwen's suggestions are tested through one pipeline and compared.

SAFETY: contained twin only (https://localhost:8443); a non-destructive guard blocks
DELETE / DROP / TRUNCATE / erase / rm etc.; DRY-RUN by default -- pass --execute to actually fire.

Usage:
    python test_suggestions.py --file suggestions.md --source qwen            # dry-run
    python test_suggestions.py --board eg_board --source qwen --execute       # run qwen's board posts
    python test_suggestions.py --file ds_suggestions.md --source ds --execute --role owner
"""
import os, re, sys, glob, json, argparse, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # vendored verified_findings / coverage_matrix
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    requests = None

BASE = os.environ.get("AEGIS_TARGET", "https://localhost:8443")
DB_CONTAINER = os.environ.get("AEGIS_DB_CONTAINER", "target-mirror-db-1")
DB_USER = os.environ.get("AEGIS_DB_USER", "appdb")
DB_NAME = os.environ.get("AEGIS_DB_NAME", "appdb")
DB_PASS = os.environ.get("AEGIS_DB_PASS", "mirror-db-pass")
WSL_DISTRO = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")

# G48: route accumulation/replay-loop probes (loop or concurrency in CODE + a SQL invariant oracle) through
# the meta-oracle so the WHOLE loop actually runs (single-request replay never triggers accumulation).
_META_ON = os.environ.get("AEGIS_META_ORACLE", "1") != "0"
_LOOP_RE = re.compile(r"\b(for|while)\b|threading|asyncio|concurrent\.futures|ThreadPool|multiprocessing", re.I)

ACCOUNTS = {"owner": "owner-user", "dispatcher": "dispatcher-user", "finance": "finance-user",
            "warehouse": "warehouse-user", "technician": "technician-user"}
# Point at the REAL mirror accounts without hardcoding client values (skill doctrine: env, not code).
# AEGIS_ROLE_MAP (JSON role->login-name) overlays the generic defaults; AEGIS_TEST_PIN sets the shared PIN.
# e.g. AEGIS_ROLE_MAP={"owner":"Alex Morgan","finance":"Fiona Clarke","dispatcher":"Marcus Reilly",
#      "warehouse":"Wes Okonkwo","technician":"Jordan Blake"}  AEGIS_TEST_PIN=123456
try:
    _rm = json.loads(os.environ.get("AEGIS_ROLE_MAP", "") or "{}")
    ACCOUNTS.update({k.lower(): v for k, v in _rm.items() if v})
except Exception:
    pass

# ---- non-destructive guard (doctrine: plant/write OK, NEVER erase/delete) ----
# covers shell equivalents of data-loss, not just the SQL/`rm -rf` basics (Pass 7b #15): bare rm -r/-f,
# dd of=, shred, chmod -R 000, redirect-clobber to system paths, mv .. /dev/null.
DESTRUCTIVE = re.compile(
    r"\bDELETE\s+FROM\b|\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\b|--\s*drop|"
    r"\brm\s+-\s*[rf]|\bmkfs|\bshred\b|\bdd\s+of=|\bchmod\s+-R\s+0{3}\b|\bshutdown\b|"
    r"\bdel\s+/|\bformat\s+[a-z]:|\bmv\s+\S+\s+/dev/null|>\s*/(dev|etc|var|usr|bin|boot|root)\b|:\s*>\s*/",
    re.I)
def guard(code: str):
    if DESTRUCTIVE.search(code or ""):
        return False, "destructive pattern (erase/drop/truncate) -- blocked by non-destructive doctrine"
    if re.search(r"-X\s*DELETE\b", code or "", re.I):
        return False, "HTTP DELETE -- blocked by non-destructive doctrine"
    return True, ""

# ---- parse TARGET/CODE/ORACLE blocks out of free-form model output ----
def parse(text: str):
    # split on numbered items or on repeated TARGET labels
    chunks = re.split(r"(?m)^\s*(?:\d+[\).]|-)\s+(?=TARGET)", text)
    out = []
    for ch in chunks:
        if "TARGET" not in ch.upper():
            continue
        def grab(label, nxt):
            m = re.search(rf"{label}\s*[-:]?\s*(.*?)(?=\n\s*(?:{nxt})\b|\Z)", ch, re.I | re.S)
            return (m.group(1).strip() if m else "")
        target = grab("TARGET", "CODE|ORACLE")
        code = grab("CODE", "ORACLE")
        oracle = grab("ORACLE", "TARGET")
        if target or code:
            out.append({"target": target, "code": code, "oracle": oracle})
    return out

# ---- python-probe body extraction: the bench writes PYTHON (requests.<m>(url, json=payload)), not curl,
# so the curl parser missed the METHOD and BODY and replayed a bodyless GET. These resolve the real method
# and the json/data payload (inline dict OR a `payload = {...}` variable) so the exploit is actually sent.
def _balanced_dict(code: str, from_idx: int):
    i = code.find("{", from_idx)
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(code)):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                return code[i:j + 1]
    return None


def _py_body(code: str):
    """Return a JSON string for the requests json=/data= argument, or None. Handles an inline dict and a
    variable (payload = {...}; json=payload). Python literals -> JSON via ast.literal_eval."""
    m = re.search(r"\b(?:json|data)\s*=\s*([A-Za-z_]\w*|\{)", code)
    if not m:
        return None
    tok = m.group(1)
    if tok == "{":
        d = _balanced_dict(code, m.start(1))
    else:
        vm = re.search(rf"\b{re.escape(tok)}\s*=\s*\{{", code)
        d = _balanced_dict(code, vm.start()) if vm else None
    if not d:
        return None
    import ast
    try:
        return json.dumps(ast.literal_eval(d))
    except Exception:
        return d


# ---- a tiny curl-line -> HTTP request replayer (forces host to the contained twin) ----
def parse_curl(code: str):
    # normalise a possibly multi-line, fenced, backslash-continued curl into one line
    raw = re.sub(r"```[a-zA-Z]*", "", code or "")
    raw = raw.replace("\\\r\n", " ").replace("\\\n", " ")
    line = " ".join(raw.split())
    if "curl" not in line.lower() and "http" not in line.lower():
        return None
    m_url = re.search(r"https?://[^\s'\"]+", line)
    if not m_url:
        return None
    path = re.sub(r"https?://[^/]+", "", m_url.group(0)) or "/"
    method = "GET"
    mm = re.search(r"-X\s*([A-Z]+)", line)
    if mm: method = mm.group(1).upper()
    data = None
    md = re.search(r"-d\s*'([^']*)'|-d\s*\"([^\"]*)\"|--data(?:-raw)?\s*'([^']*)'", line)
    if md:
        data = next(g for g in md.groups() if g is not None)
        if method == "GET": method = "POST"
    headers = {}
    for hm in re.finditer(r"-H\s*'([^']*)'|-H\s*\"([^\"]*)\"", line):
        h = hm.group(1) or hm.group(2)
        if ":" in h:
            k, v = h.split(":", 1)
            # the harness supplies its own authenticated session -- ignore model-placeholder auth headers
            if k.strip().lower() in ("cookie", "authorization"):
                continue
            headers[k.strip()] = v.strip()
    # PYTHON probe: the bench writes requests.<method>(url, json=payload), which the curl-style extraction
    # above misses (no -X -> GET, no -d -> no body). Override with the real python method + JSON body so the
    # exploit's actual mutation is replayed (via the harness's authenticated session).
    pym = re.search(r"requests\.(get|post|put|patch|delete|head)\s*\(", code or "", re.I)
    if pym:
        method = pym.group(1).upper()
        pb = _py_body(code)
        if pb is not None:
            data = pb
    return {"method": method, "path": path, "data": data, "headers": headers}

def db(sql: str) -> str:
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"; env["MSYS2_ARG_CONV_EXCL"] = "*"
    try:
        return subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "docker", "exec",
                               "-e", f"PGPASSWORD={DB_PASS}", DB_CONTAINER, "psql", "-U", DB_USER,
                               "-d", DB_NAME, "-t", "-A", "-c", sql],
                              capture_output=True, text=True, env=env, timeout=30).stdout.strip()
    except Exception as e:
        return f"[db error: {e}]"

def login(role: str):
    s = requests.Session(); s.verify = False
    try:
        r = s.post(BASE + "/api/auth/login", json={"name": ACCOUNTS.get(role, ACCOUNTS["owner"]), "pin": os.environ.get("AEGIS_TEST_PIN", "000000")}, timeout=15)
        ok = r.status_code == 200
    except Exception:
        ok = False
    return s, ok

# ---- G57: Prisma raw-SQL + filter-injection DIFFERENTIAL oracles ----------------------------------
# check_oracle proves status/body/SELECT-invariant. The Prisma blind-spot classes need a DIFFERENTIAL
# probe (several requests + row-set comparison), the same shape as the loop's vectors.sql_raw /
# vectors.filter_injection -- so a board suggestion flagged raw-sql / filter-injection is confirmed here
# too, reusing the SAME verified_findings oracles. DB-confirmation (a SELECT in the ORACLE) is what lifts
# the verdict to 'verified'; without it the differential is reported INCONCLUSIVE (over-claim guard, per
# the >=2-confirmation-for-HIGH doctrine). These also emit surface:/class: coverage tags so breadth_audit
# counts the (route x class) cell EXERCISED instead of forever SEEDED_NOT_EXERCISED.
_PRISMA_RX = {
    "sql_raw": re.compile(r"raw[\s_-]?sql|sql[\s_-]?raw|\$?queryraw|\$?executeraw|boolean[\s-]?based", re.I),
    "filter_injection": re.compile(r"filter[\s_-]?inject|where[\s_-]?inject|orderby[\s_-]?inject|"
                                   r"operator[\s_-]?inject|prisma\s+filter|scope[\s_-]?widen", re.I),
}


def prisma_class(sug):
    """Return 'sql_raw' | 'filter_injection' if the suggestion declares that class, else None."""
    blob = " ".join((sug.get("oracle") or "", sug.get("target") or "", sug.get("code") or ""))
    for cls, rx in _PRISMA_RX.items():
        if rx.search(blob):
            return cls
    return None


def _resp_ids(resp):
    """Best-effort id-set from a JSON list/collection response (id|uuid|_id)."""
    if resp is None:
        return []
    try:
        j = resp.json()
    except Exception:
        return []
    items = j if isinstance(j, list) else (j.get("data") or j.get("items") or j.get("results") or j.get("rows") or [])
    ids = []
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict):
                for k in ("id", "uuid", "_id", "Id", "ID"):
                    if k in it:
                        ids.append(str(it[k])); break
    return ids


def _get(sess, url):
    try:
        return sess.get(url, timeout=20)
    except Exception:
        return None


def _diff_params(sug):
    """Resolve (base_path, injected_query, param, value) from a suggestion's TARGET/CODE.
    base_path = the endpoint sans query; injected_query = the '?...'' the board wrote (the injected filter),
    param/value = the first query pair (for the sql_raw boolean-differential)."""
    req = parse_curl(sug.get("code") or "")
    raw_path = (req["path"] if req else "") or ""
    if not raw_path:
        m = re.search(r"(/[^\s'\"]+)", sug.get("target") or "")
        raw_path = m.group(1) if m else "/"
    base_path = raw_path.split("?")[0] or "/"
    query = raw_path[len(base_path):]                       # includes leading '?', maybe ''
    pm = re.search(r"[?&]([A-Za-z_]\w*)=([^&\s]+)", query)
    param = pm.group(1) if pm else "q"
    value = pm.group(2) if pm else "1"
    return base_path, query, param, value


def prisma_diff_oracle(cls, sug, sess):
    """Differential probe + the matching verified_findings oracle.
    Returns (verdict in {'pass','fail','inconclusive'}, notes, surface)."""
    from verified_findings import SqlRawOracle, FilterInjectionOracle
    from urllib.parse import quote as _q
    base_path, query, param, value = _diff_params(sug)
    notes = []
    # optional DB confirmation: a SELECT in the ORACLE (the co-pilot supplies it) returns the ids/rows the
    # flaw must expose -> proves the injection reached the DB / the extra rows are real cross-scope objects.
    sel = re.search(r"(SELECT\b.+?;)", sug.get("oracle") or "", re.I | re.S)
    db_rows = None
    if sel:
        raw = db(sel.group(1))
        if not raw.startswith("[db error"):
            db_rows = [x for x in re.split(r"[\s,]+", raw.strip()) if x]
        notes.append(f"db->{(raw or '')[:50]}")

    if cls == "sql_raw":
        def probe(cond):
            return _resp_ids(_get(sess, BASE.rstrip("/") + base_path + f"?{param}=" + _q(value + cond)))
        t, f, c = probe(" AND 1=1-- "), probe(" AND 1=2-- "), probe("")
        verdict, _ = SqlRawOracle(t, f, c, db_confirmed=bool(db_rows), surface=base_path).check()
        notes.append(f"true={len(t)} false={len(f)} control={len(c)}")
    else:  # filter_injection
        base_ids = _resp_ids(_get(sess, BASE.rstrip("/") + base_path))
        inj = query or "?take=1000&skip=0"
        inj_ids = _resp_ids(_get(sess, BASE.rstrip("/") + base_path + inj))
        cross = db_rows if db_rows is not None else []      # cross-owner ids must be DB-confirmed to VERIFY
        verdict, _ = FilterInjectionOracle(base_ids, inj_ids, cross, surface=base_path).check()
        notes.append(f"baseline={len(base_ids)} injected={len(inj_ids)} cross={len(cross)}")

    v = "pass" if verdict == "verified" else ("fail" if verdict == "rejected" else "inconclusive")
    notes.append(f"oracle={verdict}")
    if verdict != "verified" and not sel:
        notes.append("no ORACLE SELECT -> DB-unconfirmed (add a SELECT to lift to verified)")
    return v, "; ".join(notes), base_path


# ---- oracle evaluation ----
def check_oracle(oracle: str, resp, sess):
    """Evaluate a prose oracle. Handles relational conditions ('below 400', '>= 500', '2xx',
    'server error'), an exact status, body-contains, and a DB SELECT check."""
    o = oracle or ""
    low = o.lower()
    notes = []
    verdict = "manual"
    if resp is not None:
        st = resp.status_code
        notes.append(f"http={st} bytes={len(resp.content)}")
        # SPA-200 GUARD (bake-off caught a false PASS): an unmatched route returns the SPA shell -- 200
        # text/html with a root div/doctype -- which is NOT a real handler success. A status-based PASS
        # (2xx / below-400) must NOT fire on it, else a probe that never reached /api gets a false 'verified'.
        ctype = (resp.headers.get("content-type") or "").lower()
        _bl = (resp.text or "")[:800].lower()
        from verified_findings import is_spa_shell   # H13: one canonical SPA-shell predicate
        is_spa = is_spa_shell(st, ctype, _bl)
        if is_spa:
            notes.append("SPA-shell(not a real handler)")
        m_rel = re.search(r"(?:below|under|less than|<=?)\s*(\d{3})", low)
        m_ge  = re.search(r"(?:>=|at least|greater than(?: or equal)?|more than|over)\s*(\d{3})", low)
        m_2xx = re.search(r"\b2xx\b|success|accepted|created|saved|persist|stored|below\s*400", low)
        m_5xx = re.search(r"\b5xx\b|server error|internal error|crash|\b500\b", low)
        m_exact = re.search(r"(?:http\s*|status\s*(?:code)?\s*(?:==|=|is|:)?\s*)(\d{3})", low)
        if m_rel:
            verdict = "pass" if (st < int(m_rel.group(1)) and not is_spa) else "fail"; notes.append(f"expect <{m_rel.group(1)}")
        elif m_ge:
            verdict = "pass" if st >= int(m_ge.group(1)) else "fail"; notes.append(f"expect >={m_ge.group(1)}")
        elif m_2xx:
            # 2xx/accept is the common PASS condition; check it BEFORE 5xx so an oracle that mentions
            # both ("pass if 2xx; a 500 means blocked") binds to the success clause, not the failure one.
            # An SPA-shell 200 is NOT a handler success -> not a pass (bake-off false-PASS fix).
            verdict = "pass" if (200 <= st < 300 and not is_spa) else "fail"; notes.append("expect 2xx")
        elif m_5xx:
            verdict = "pass" if st >= 500 else "fail"; notes.append("expect 5xx")
        elif m_exact:
            exp = int(m_exact.group(1)); verdict = "pass" if st == exp else "fail"; notes.append(f"expect {exp}")
        elif not re.search(r"\bSELECT\b", o, re.I):
            # BARE status code with no http/status prefix (e.g. "200 OK", "returns 201") -- take the
            # first standalone 1xx-5xx token as the expected status. Loosened so coder-written probe
            # ORACLEs verify instead of falling to 'manual'. SKIP for a DB SELECT oracle: its numbers
            # (ids/amounts) are DATA, not a status, and a bogus 'fail' here would block the DB SELECT
            # branch below (which only overrides a still-'manual' verdict).
            m_bare = re.search(r"\b([1-5]\d\d)\b", low)
            if m_bare:
                exp = int(m_bare.group(1)); verdict = "pass" if st == exp else "fail"; notes.append(f"expect ~{exp}")
        # body-contains, quoted (incl BACKTICKS) OR bare (contains 'x' | contains "x" | contains `x` | contains x)
        bm = (re.search(r"contains?\s+[`'\"]([^`'\"]+)[`'\"]", o, re.I)
              or re.search(r"contains?\s+([^\s'\"`;,]+)", o, re.I))
        if bm:
            # strip wrapping backticks/quotes; a DOTTED JSON path (authentication.token) never appears
            # literally in JSON ("authentication":{"token"), so check that EACH segment is present instead.
            marker = bm.group(1).strip().strip("`'\"")
            body_t = resp.text or ""
            segs = [s for s in re.split(r"[.\[\]]+", marker) if s]
            hit = (all(s in body_t for s in segs) if len(segs) > 1 else (marker in body_t))
            if verdict == "manual":
                verdict = "pass" if hit else "fail"
            elif verdict == "pass" and not hit:
                # a REQUIRED body signal was specified but ABSENT -> the proof fails even on a 2xx,
                # so a bare-200 / SPA-shell response can't satisfy a "200 AND body contains X" oracle.
                verdict = "fail"
            notes.append(f"body~'{marker}':{hit}")
    db_confirmed = False   # A2: did an authoritative DB SELECT witness decide this? (independent 2nd oracle)
    sel = re.search(r"(SELECT\b.+?;)", o, re.I | re.S)
    if sel:
        res = db(sel.group(1))
        notes.append(f"db -> {res[:70]}")
        # G34: a SELECT is the INVARIANT check and is AUTHORITATIVE -- it returns rows ONLY when the flaw
        # holds. It DECIDES the verdict, overriding a co-mentioned status: creating a record (2xx) is not a
        # finding; the invariant BREACH is. Rows -> pass; empty -> fail (invariant held); db error -> inconclusive.
        if res.startswith("[db error"):
            verdict = "inconclusive"
        else:
            rows = bool(res.strip()) and res.strip() not in ("0", "f", "false", "[]")
            verdict = "pass" if rows else "fail"
            db_confirmed = rows
    return verdict, "; ".join(notes), db_confirmed

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="a suggestions file (md/txt)")
    ap.add_argument("--board", help="board dir to glob for suggestion posts")
    ap.add_argument("--source", default="unknown", help="attribution: qwen | ds | ...")
    ap.add_argument("--role", default="owner", choices=list(ACCOUNTS))
    ap.add_argument("--execute", action="store_true", help="actually fire (default: dry-run)")
    ap.add_argument("--campaign", help="G57: also write findings to campaigns/<c>/findings.jsonl so "
                    "breadth_audit --campaign <c> counts the exercised (route x class) cells")
    a = ap.parse_args()

    texts = []
    if a.file:
        texts.append(open(a.file, encoding="utf-8").read())
    if a.board:
        pat = "*" + a.source + "*" if a.source != "unknown" else "*"
        for f in glob.glob(os.path.join(a.board, pat + ".md")):
            texts.append(open(f, encoding="utf-8").read())
    if not texts:
        sys.exit("nothing to test -- pass --file or --board")

    suggestions = []
    for t in texts:
        suggestions += parse(t)
    print(f"parsed {len(suggestions)} suggestion(s) from source='{a.source}'  mode={'EXECUTE' if a.execute else 'DRY-RUN'}\n")

    store = cov = None
    if a.execute:
        from verified_findings import FindingStore, Finding, Evidence, run_marker
        from coverage_matrix import CoverageTracker
        from dataclasses import asdict
        if a.campaign:
            _cdir = os.path.join(HERE, "campaigns", a.campaign); os.makedirs(_cdir, exist_ok=True)
            store = FindingStore(os.path.join(_cdir, "findings.jsonl"))       # breadth_audit reads this path
            cov = CoverageTracker(os.path.join(_cdir, "coverage.jsonl"))
        else:
            store = FindingStore(os.path.join(HERE, "suggestion_test_findings.jsonl"))
            cov = CoverageTracker(os.path.join(HERE, "suggestion_test_coverage.jsonl"))
        mk = run_marker(f"suggtest-{a.source}")
        sess, authed = login(a.role)
        if not authed:
            sys.exit(f"[abort] login as role '{a.role}' failed (is the mirror up? do ACCOUNTS/PIN match?) -- "
                     "refusing to run the battery unauthenticated; results would be misleadingly 'refuted'.")

    passed = failed = blocked = manual = 0
    for i, sug in enumerate(suggestions, 1):
        ok, why = guard(sug["code"])
        print(f"[{i}] TARGET: {sug['target'][:90]}")
        if not ok:
            blocked += 1; print(f"    BLOCKED: {why}\n"); continue
        req = parse_curl(sug["code"])
        if not a.execute:
            print(f"    would run: {req['method'] if req else '(unparsed)'} {req['path'] if req else sug['code'][:60]}")
            print(f"    oracle: {sug['oracle'][:90]}\n"); continue
        # G48 REPLAY-LOOP DEPTH: a probe whose CODE has a loop/concurrency + a SQL invariant oracle is an
        # ACCUMULATION exploit -- replaying ONE parsed request never triggers it. Route the FULL code through
        # the meta-oracle (executes the whole loop authenticated + non-destructive; baseline-empty -> exec ->
        # rows-after = trustworthy exploit-caused). Falls back to single-request replay for everything else.
        verdict = notes = None
        db_witness = False                             # A2: an independent DB/meta/differential witness fired
        pcls = prisma_class(sug); psurface = None      # G57: Prisma raw-SQL / filter-injection class + surface
        if _META_ON and _LOOP_RE.search(sug["code"] or "") and re.search(r"\bselect\b", sug["oracle"] or "", re.I):
            try:
                import meta_oracle as _MO
                probe_text = f"TARGET {sug['target']}\nCODE\n{sug['code']}\nORACLE\n{sug['oracle']}"
                v = _MO.verify(probe_text, role=(a.role if a.role in ("owner","dispatcher","finance","warehouse","technician") else "owner"))
                vd = v.get("verdict")
                verdict = "pass" if vd == "META_WIN" else ("fail" if vd in ("no_breach", "invalid_oracle") else "manual")
                db_witness = (vd == "META_WIN")   # A2: meta-oracle win is a DB-state (baseline->exec->rows) witness
                notes = f"meta-oracle:{vd} {v.get('reason') or v.get('after') or v.get('detail') or ''}"[:200]
                print(f"    [replay-loop->meta-oracle] {verdict.upper()} -- {notes}")
            except Exception as e:
                verdict = None; print(f"    [replay-loop->meta-oracle] unavailable ({str(e)[:60]}) -> single-request replay")
        # G57: Prisma raw-SQL / filter-injection need a DIFFERENTIAL probe (not a single replay) -> route to
        # the matching verified_findings oracle. inconclusive is a real verdict (falls to the manual bucket).
        if verdict is None and pcls in ("sql_raw", "filter_injection"):
            try:
                verdict, notes, psurface = prisma_diff_oracle(pcls, sug, sess)
                db_witness = (verdict == "pass")   # A2: SqlRaw/FilterInjection oracle verifies ONLY when DB-confirmed
                print(f"    [prisma-diff:{pcls}] {verdict.upper()} -- {notes}")
            except Exception as e:
                verdict = None; print(f"    [prisma-diff:{pcls}] unavailable ({str(e)[:70]}) -> single-request replay")
        if verdict is None:
            resp = None
            if req:
                try:
                    url = BASE + req["path"] if req["path"].startswith("/") else BASE + "/" + req["path"]
                    kw = {"timeout": 20, "headers": req["headers"] or None}
                    if req["data"]:
                        try: kw["json"] = json.loads(req["data"])
                        except Exception: kw["data"] = req["data"]
                    resp = sess.request(req["method"], url, **kw)
                except Exception as e:
                    print(f"    run error: {type(e).__name__}: {e}\n"); manual += 1; continue
            verdict, notes, db_witness = check_oracle(sug["oracle"], resp, sess)
        print(f"    {verdict.upper()} -- {notes}")
        from dataclasses import asdict
        from verified_findings import Finding, Evidence
        # G57: carry surface:/class: tags so breadth_audit.exercised_map counts the (route x class) cell.
        if pcls and not psurface:
            psurface, *_ = _diff_params(sug)
        _ctags = [f"source:{a.source}", "technique:suggestion-test"]
        if pcls:
            _ctags += [f"class:{pcls}", f"technique:{pcls}"]
            if psurface:
                _ctags.append(f"surface:{psurface}")
        f = Finding(claim_type=f"suggestion.{a.source}",
                    summary=f"[{a.source}] {sug['target'][:120]} | oracle: {sug['oracle'][:120]}",
                    severity=("high" if pcls else "unknown"), run_id=mk,
                    provenance={"provider": a.source, "via": "test_suggestions", "class": pcls or ""},
                    coverage_tags=_ctags,
                    evidence=[asdict(Evidence(kind="http", detail=notes))])
        fid = store.record_candidate(f)
        if verdict == "pass":
            store._transition(fid, "verified", f"oracle:{a.source}", {"notes": notes}); passed += 1
            if db_witness:   # A2: the DB/meta/differential witness is an INDEPENDENT 2nd oracle -> feeds A1's
                             # >=2-for-HIGH gate so a DB-confirmed data-class finding can legitimately be HIGH.
                store._transition(fid, "verified", "db-witness@1", {"notes": "A2: DB-confirmed 2nd oracle"})
        elif verdict == "fail":
            store._transition(fid, "rejected", f"oracle:{a.source}", {"notes": notes}); failed += 1
        else:
            manual += 1
        cov.record(surface=(psurface or sug["target"][:60]), role=a.role, technique=(pcls or "suggestion-test"),
                   result="finding" if verdict == "pass" else ("clean" if verdict == "fail" else "inconclusive"),
                   note=f"{a.source}:{verdict}")
        print()

    print(f"== summary ({a.source}): pass={passed} fail={failed} blocked={blocked} manual/inconclusive={manual} ==")
    if a.execute:
        print(f"chain_ok={store.verify_chain()}  findings->{os.path.join(HERE,'suggestion_test_findings.jsonl')}")

if __name__ == "__main__":
    main()
