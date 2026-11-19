#!/usr/bin/env python3
"""breadth_audit.py -- APP-FUNCTION-DEMAND breadth audit (G53). Board-confirmed (7/8).

The gap it closes: we measured coverage against classes-probed (coverage.py) + surfaces-hit (coverage_gate.py)
+ ATT&CK (attack_coverage.py), but NOT against a DEMAND model of what the app's FUNCTIONS require. A function
whose risk class we have NO oracle for is an invisible blind spot -- never proposed, never counted missing.

This builds the demand-vs-supply matrix:
  DEMAND  = the app's functions. Source of truth (no swagger; SPA): the Express ROUTE SOURCE (authoritative --
            every declared method+path, incl. routes the SPA never calls), enriched by the crawler (which are
            LIVE + per-role) and the Prisma SCHEMA (entity/field/ownership ground truth).
  RULES   = board's attribute->required-class map (POST+body->mass-assign; :id->idor/authz; money entity->
            invariant/idempotency; url param->open-redirect/ssrf; $queryRaw->sql-raw; nested write->nested-write;
            where/orderBy/select param->filter-injection/field-leak; auth route->session/rate/csrf; ...).
  SUPPLY  = our oracle+leg inventory (HAVE_ORACLE) and which have a planner seed generator (HAVE_SEED).
  AUDIT   = per (function x required-class) cell: NOT_APPLICABLE / MISSING_ORACLE / HAVE_ORACLE_NO_SEED /
            SEEDED_NOT_EXERCISED / EXERCISED. breadth score = EXERCISED / APPLICABLE (honest denominator).
  GAPS    -> the self-improvement loop: MISSING_ORACLE -> build a <class> oracle (log_improve, goal_axis=
            discovery); HAVE_ORACLE_NO_SEED -> wire a seed. Ranked by attacker-reachable risk in-context.

Route source is read from the running mirror API container (TS/JS), offline-safe: unreachable -> demand falls
back to crawler+schema (flagged incomplete). Read-only. Writes RUN_BREADTH_<campaign>.md (+ --json / gaps).

Usage: python operator/breadth_audit.py [--campaign C] [--base URL] [--json] [--out FILE]
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

API_CTR = os.environ.get("AEGIS_MIRROR_API_CONTAINER", "aegis-mirror-api-1")  # align w/ stateful_templates/vectors; the stale -v3- default hit a dead container -> silent 0 routes
SRC = os.environ.get("AEGIS_MIRROR_SRC", "/app/backend/src")
SCHEMA = os.environ.get("AEGIS_MIRROR_SCHEMA", "/app/backend/prisma/schema.prisma")
WSL = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")

# ---- SUPPLY: what we can actually test (oracle+leg) and what has a planner seed generator ----
HAVE_ORACLE = {"authz", "idor", "mass_assign", "ssrf", "xss", "csrf", "open_redirect", "security_headers",
               "session_fixation", "rate_limit", "file_upload", "invariant", "idempotency", "secrets",
               "differential", "resource_persistence", "auth_state",
               # G54: the Prisma/Express blind-spot oracles now EXIST (shared/verified_findings.py)
               "nested_write", "field_leak", "filter_injection", "sql_raw"}
HAVE_SEED = {"authz", "idor", "rate_limit", "security_headers", "session_fixation", "open_redirect",
             "mass_assign", "csrf", "ssrf", "xss", "file_upload", "invariant", "idempotency",
             # G55: the breadth-closing oracles now have planner seed generators (planner.breadth_seeds) + legs
             "nested_write", "field_leak", "filter_injection", "sql_raw"}
MISSING_ORACLE = set()   # all four blind-spot oracles now exist (G54) AND are auto-seeded (G55)
# technique/vuln-class keyword -> our class key (to read what a campaign EXERCISED from coverage tags)
TECH2CLASS = {"authz": "authz", "access": "authz", "idor": "idor", "bola": "idor", "mass": "mass_assign",
              "ssrf": "ssrf", "xss": "xss", "csrf": "csrf", "redirect": "open_redirect", "header": "security_headers",
              "session": "session_fixation", "rate": "rate_limit", "upload": "file_upload", "invariant": "invariant",
              "idempot": "idempotency", "secret": "secrets", "differential": "differential",
              "resource": "resource_persistence", "surface-coverage": "authz",
              # G57: the Prisma/Express blind-spot classes -- without these, findings the loop legs
              # (iterative_hunt_live) and test_suggestions emit as class:/technique: sql-raw / filter-injection /
              # field-leak / nested-write never mapped to a cell, so those cells were stuck SEEDED_NOT_EXERCISED
              # forever. Both hyphen (loop-leg tag) and underscore (breadth class name) forms are matched.
              "sql_raw": "sql_raw", "sql-raw": "sql_raw", "sqlraw": "sql_raw",
              "filter_injection": "filter_injection", "filter-injection": "filter_injection",
              "field_leak": "field_leak", "field-leak": "field_leak",
              "nested_write": "nested_write", "nested-write": "nested_write"}


import base64 as _b64


def _grep(pattern, path, flag):
    """grep the mirror API container's source. The pattern is base64'd into a container-side pattern file and
    read via `grep -f` so ERE grouping parens survive the wsl.exe interop boundary (bare '(' in an argv breaks
    it). Returns [] offline/unreachable (never raises)."""
    env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    b = _b64.b64encode(pattern.encode()).decode()
    remote = f"echo {b} | base64 -d > /tmp/aegis_pat && grep {flag} -f /tmp/aegis_pat {path} 2>/dev/null"
    argv = (["wsl", "-d", WSL, "-u", "root", "--"] if os.name == "nt" else []) + \
           ["docker", "exec", API_CTR, "sh", "-c", remote]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env)
        return [l for l in (p.stdout or "").splitlines() if l.strip()]
    except Exception:
        return []


def _wsl_grep(pattern, path):
    return _grep(pattern, path, "-rhoE")


def _wsl_grep_n(pattern, path):
    return _grep(pattern, path, "-rnE")


def parse_routes():
    """Grep the Express route source into normalized function records. Authoritative DEMAND list."""
    # 1) mounts: app.use("/api/x", xRouter)  -> {routerVar: prefix}
    mounts = {}
    for l in _wsl_grep(r'app\.use\("/api[^"]*", *[A-Za-z0-9_]+', SRC):
        m = re.search(r'app\.use\("(/api[^"]*)", *([A-Za-z0-9_]+)', l)
        if m:
            mounts.setdefault(m.group(2), m.group(1))
    # 2) router decls: const xRouter = Router()  -> file where defined (routerVar -> its file basename)
    #    3) route lines: xRouter.get("/sub", ... )  (grep -n gives file:line:content)
    route_lines = _wsl_grep_n(r'[A-Za-z0-9_]+\.(get|post|put|patch|delete)\("', SRC)
    # 4) router-level auth: xRouter.use(requireAuth)
    router_authed = set(re.findall(r'([A-Za-z0-9_]+)\.use\(require', "\n".join(_wsl_grep(r'[A-Za-z0-9_]+\.use\(require[A-Za-z]+', SRC))))
    # per-file sink flags
    sink_files = {
        "sql_raw": set(_wsl_grep_n(r'\$(queryRaw|executeRaw)', SRC) and [x.split(":")[0] for x in _wsl_grep_n(r'\$(queryRaw|executeRaw)', SRC)]),
        "nested_write": set(x.split(":")[0] for x in _wsl_grep_n(r'(connect|create|connectOrCreate): *\{', SRC)),
        "field_select": set(x.split(":")[0] for x in _wsl_grep_n(r'(select|include): *\{', SRC)),
        "req_query": set(x.split(":")[0] for x in _wsl_grep_n(r'req\.query', SRC)),
        "multipart": set(x.split(":")[0] for x in _wsl_grep_n(r'(multer|multipart|req\.file)', SRC)),
    }
    routes = []
    for l in route_lines:
        # file:line:  xRouter.get("/sub", requirePermission(...), ...)
        parts = l.split(":", 2)
        if len(parts) < 3:
            continue
        fpath, _ln, content = parts
        m = re.search(r'([A-Za-z0-9_]+)\.(get|post|put|patch|delete)\("([^"]*)"(.*)', content)
        if not m:
            continue
        rvar, method, sub, rest = m.group(1), m.group(2).upper(), m.group(3), m.group(4)
        prefix = mounts.get(rvar, "")
        if not prefix:
            continue                       # not an /api-mounted router -> skip (helpers, sockets)
        full = (prefix.rstrip("/") + "/" + sub.lstrip("/")).rstrip("/") or prefix
        tmpl = re.sub(r":([A-Za-z0-9_]+)", r"{\1}", full)
        authed = (rvar in router_authed) or ("requireAuth" in rest) or ("requirePermission" in rest)
        fbase = fpath.split("/")[-1]
        routes.append({
            "method": method, "path": tmpl, "router": rvar, "file": fbase, "authed": authed,
            "has_body": method in ("POST", "PUT", "PATCH"),
            "has_id": bool(re.search(r"\{[A-Za-z0-9_]+\}", tmpl)),
            "sql_raw": fbase in {p.split("/")[-1] for p in sink_files["sql_raw"]},
            "nested_write": fbase in {p.split("/")[-1] for p in sink_files["nested_write"]},
            "field_select": fbase in {p.split("/")[-1] for p in sink_files["field_select"]},
            "req_query": fbase in {p.split("/")[-1] for p in sink_files["req_query"]},
            "multipart": fbase in {p.split("/")[-1] for p in sink_files["multipart"]},
        })
    # dedup by (method, path)
    seen, out = set(), []
    for r in routes:
        k = (r["method"], r["path"])
        if k not in seen:
            seen.add(k); out.append(r)
    return out, bool(route_lines)


MONEY_ENT = ("invoice", "credit-note", "creditnote", "payment", "estimate", "expense", "supplier-bill", "purchase-order")
OWNER_HINT = ("customer", "job", "user", "technician", "vehicle", "appliance", "part")
REDIRECT_PARAMS = ("url", "redirect", "callback", "returnto", "return", "next", "target", "uri", "link", "webhook", "endpoint")
AUTH_ROUTE = ("/login", "/auth", "/register", "/reset", "/2fa", "/session", "/logout", "/token")


def required_classes(r):
    """Board's attribute -> required-class map. Returns {class: reason}. Applicability-gated by evidence."""
    req = {}
    p = r["path"].lower()
    if r["authed"]:
        req["authz"] = "authed route -> broken-access-control"
    if r["has_id"]:
        req["idor"] = "path id -> object-level authz / IDOR"
    if r["has_body"]:
        req["mass_assign"] = "write body -> mass-assignment / over-post"
    if any(e in p for e in MONEY_ENT):
        req["invariant"] = "money/ledger entity -> domain invariant"
        if r["has_body"]:
            req["idempotency"] = "money write -> replay/idempotency"
    if r["req_query"] and any(q in p for q in REDIRECT_PARAMS):
        req["open_redirect"] = "redirect-ish query param"; req["ssrf"] = "url-ish query param -> SSRF"
    if any(a in p for a in AUTH_ROUTE):
        req["session_fixation"] = "auth route -> session"; req["rate_limit"] = "auth route -> anti-automation"
        if r["has_body"]:
            req["csrf"] = "state-changing auth route -> CSRF"
    if r["multipart"]:
        req["file_upload"] = "multipart/file -> unrestricted upload"
    # Prisma/Express blind spots (MISSING_ORACLE classes)
    if r["sql_raw"]:
        req["sql_raw"] = "$queryRaw/$executeRaw in handler -> raw SQL injection"
    if r["nested_write"] and r["has_body"]:
        req["nested_write"] = "prisma nested connect/create -> nested-write over-post"
    _sensitive = any(e in p for e in MONEY_ENT) or any(o in p for o in OWNER_HINT)
    if r["field_select"] and r["req_query"] and _sensitive:
        req["filter_injection"] = "untrusted where/orderBy/select on a sensitive entity -> filter injection"
    if r["field_select"] and _sensitive and (r["has_id"] or not r["has_body"]):
        req["field_leak"] = "select/include on a sensitive read -> field-level authz leak"
    return req


def exercised_map(campaign):
    """{surface_template: set(class)} the campaign actually probed, from findings coverage_tags."""
    out = defaultdict(set)
    if not campaign:
        return out
    fj = os.path.join(HERE, "campaigns", campaign, "findings.jsonl")
    if not os.path.exists(fj):
        return out
    for ln in open(fj, encoding="utf-8"):
        try:
            d = json.loads(ln)
        except Exception:
            continue
        f = d.get("finding") if isinstance(d.get("finding"), dict) else d
        tags = f.get("coverage_tags") or []
        surf = None; classes = set()
        for t in tags:
            t = str(t)
            if t.startswith("surface:"):
                s = t[len("surface:"):].split("?")[0]
                surf = re.sub(r"/(c[a-z0-9]{20,}|[0-9a-f-]{8,}|\d+)(?=/|$)", "/{id}", s) if s.startswith("/") else None
            elif t.startswith("technique:") or t.startswith("class:"):
                v = t.split(":", 1)[1].lower()
                for kw, cls in TECH2CLASS.items():
                    if kw in v:
                        classes.add(cls)
        if surf:
            out[surf] |= classes
    return out


def audit(campaign=None, base=None):
    routes, src_ok = parse_routes()
    exd = exercised_map(campaign)
    cells = []
    per_state = Counter()
    for r in routes:
        req = required_classes(r)
        for cls, reason in req.items():
            if cls in MISSING_ORACLE or cls not in HAVE_ORACLE:
                state = "MISSING_ORACLE"
            elif cls not in HAVE_SEED:
                state = "HAVE_ORACLE_NO_SEED"
            elif cls in exd.get(r["path"], set()):
                state = "EXERCISED"
            else:
                state = "SEEDED_NOT_EXERCISED"
            per_state[state] += 1
            cells.append({"fn": f"{r['method']} {r['path']}", "class": cls, "state": state,
                          "reason": reason, "entity_money": any(e in r["path"].lower() for e in MONEY_ENT),
                          "authed": r["authed"]})
    applicable = len(cells)
    exercised = per_state["EXERCISED"]
    breadth = round(exercised / applicable, 3) if applicable else 0.0
    return {"campaign": campaign, "src_available": src_ok, "routes": len(routes),
            "applicable_cells": applicable, "breadth_score": breadth, "states": dict(per_state),
            "cells": cells}


def _rank(cells, state):
    # attacker-reachable risk: money/auth first, then authed, then rest
    got = [c for c in cells if c["state"] == state]
    return sorted(got, key=lambda c: (0 if c["entity_money"] else (1 if c["authed"] else 2), c["fn"]))


def render(a):
    out = [f"# BREADTH AUDIT — {a['campaign'] or '(no campaign: demand-vs-supply only)'}", "",
           f"- route source: **{'available' if a['src_available'] else 'UNAVAILABLE (demand incomplete)'}**"
           f"  ·  functions(routes): **{a['routes']}**",
           f"- applicable (function × required-class) cells: **{a['applicable_cells']}**",
           f"- breadth score (EXERCISED / applicable): **{a['breadth_score']:.0%}**",
           f"- states: {a['states']}", ""]
    miss = _rank(a["cells"], "MISSING_ORACLE")
    if miss:
        by_class = Counter(c["class"] for c in miss)
        out += ["## MISSING_ORACLE — no check exists for these (build them; goal_axis=discovery)", "",
                f"by class: {dict(by_class)}", ""]
        for c in miss[:40]:
            out.append(f"- **{c['class']}** on `{c['fn']}` — {c['reason']}"
                       + ("  ⟵ MONEY" if c["entity_money"] else ""))
        out.append("")
    nos = _rank(a["cells"], "HAVE_ORACLE_NO_SEED")
    if nos:
        out += ["## HAVE_ORACLE_NO_SEED — oracle exists but nothing seeds it here (wire a seed)", ""]
        for c in nos[:25]:
            out.append(f"- **{c['class']}** on `{c['fn']}` — {c['reason']}")
        out.append("")
    sne = _rank(a["cells"], "SEEDED_NOT_EXERCISED")
    if sne:
        out += [f"## SEEDED_NOT_EXERCISED ({len(sne)}) — coverage/budget gap (surface gate territory)", ""]
        for c in sne[:20]:
            out.append(f"- {c['class']} on `{c['fn']}`")
        out.append("")
    return "\n".join(out)


def gaps_for_improve(a):
    """The self-improvement handoff: MISSING_ORACLE (build) + HAVE_ORACLE_NO_SEED (wire), deduped by class."""
    build = sorted({c["class"] for c in a["cells"] if c["state"] == "MISSING_ORACLE"})
    wire = sorted({c["class"] for c in a["cells"] if c["state"] == "HAVE_ORACLE_NO_SEED"})
    examples = defaultdict(list)
    for c in a["cells"]:
        if c["state"] in ("MISSING_ORACLE", "HAVE_ORACLE_NO_SEED") and len(examples[c["class"]]) < 3:
            examples[c["class"]].append(c["fn"])
    return {"build_oracle": build, "wire_seed": wire, "examples": dict(examples)}


def main():
    ap = argparse.ArgumentParser(description="app-function-demand breadth audit (demand vs supply)")
    ap.add_argument("--campaign", default=None, help="campaign to score EXERCISED against (else demand-vs-supply only)")
    ap.add_argument("--base", default=os.environ.get("AEGIS_TARGET", "https://localhost:8443"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--gaps", action="store_true", help="print the self-improvement gap handoff (build/wire)")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    res = audit(a.campaign, a.base)
    # B5: FAIL LOUD on a broken/empty demand map. A stale AEGIS_MIRROR_API_CONTAINER (or an unreadable
    # source) once silently returned 0 routes and a whole assessment ran blind against an empty matrix that
    # read as "clean". Never emit an empty 0%/clean result as if it were real -- abort with a diagnostic
    # naming the exact env to fix, unless explicitly overridden (e.g. an intentional empty-demand test).
    if (not res.get("src_available")) or res.get("routes", 0) == 0:
        msg = (f"[breadth_audit] FATAL: route source UNAVAILABLE / 0 functions "
               f"(src_available={res.get('src_available')}, routes={res.get('routes')}). The demand map is "
               f"EMPTY -> this is NOT a clean result, it's a BLIND run. Check AEGIS_MIRROR_API_CONTAINER "
               f"(currently {API_CTR!r}) points at a LIVE api container, and AEGIS_MIRROR_SRC ({SRC!r}) / "
               f"AEGIS_MIRROR_SCHEMA ({SCHEMA!r}) resolve to the app source. Set AEGIS_BREADTH_ALLOW_EMPTY=1 "
               f"to override.")
        if os.environ.get("AEGIS_BREADTH_ALLOW_EMPTY") != "1":
            print(msg, file=sys.stderr); sys.exit(3)
        print("[breadth_audit] WARNING (override): " + msg, file=sys.stderr)
    if a.json:
        print(json.dumps(res, indent=2)); return
    md = render(res)
    out = a.out or os.path.join(HERE, "..", f"RUN_BREADTH_{a.campaign or 'demand'}.md")
    open(out, "w", encoding="utf-8").write(md)
    print(f"breadth audit written: {out}")
    print(md[:1800])
    if a.gaps:
        print("\nGAPS ->", json.dumps(gaps_for_improve(res)))


if __name__ == "__main__":
    main()
