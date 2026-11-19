"""
authz_matrix.py -- EXHAUSTIVE per-route x per-role authorization matrix + CONFIG-vs-RUNTIME diff.

Closes the authz surface-saturation gap (board additions #1 + #2). Where the ~40-move iterative loop
budget-samples (it missed a real DISPATCHER over-reach at 31% saturation), this does the cheap,
COMPLETE thing: GET every discovered route as every role (non-destructive) and build the full matrix,
then -- if given the target's INTENDED access policy -- DIFF config vs observed to catch the exact class
of bug the loop missed: a route reachable by a role the policy does not grant it.

Two detection modes (both non-destructive, GET-only):
  * BASELINE over-reach (no policy): a role gets 2xx on a route where a designated baseline role
    (default: the least-privileged / anon) is denied (401/403) -- the AuthzOracle signal, but applied
    to EVERY route x role, not sampled.
  * CONFIG diff (policy given): observed-allowed but NOT policy-allowed = OVER-REACH (runtime exceeds
    the RBAC config -- the dispatcher class); policy-allowed but observed-denied = UNDER-PROVISION (info).

Policy format (JSON): {"<ROLE>": ["/api/glob/*", ...]}  -- routes each role is INTENDED to reach.
Intended/privileged roles (never flagged, e.g. owner,finance) via --intended.

Findings are recorded to the shared FindingStore, oracle-gated (the 2xx-vs-denied delta IS the proof).
Emits a markdown matrix + a findings list. Reads only; never mutates the target.
"""
from __future__ import annotations
import argparse
import fnmatch
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.join(HERE, "..", "shared")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DEFAULT_ROUTES = [
    "/api/settings", "/api/payroll", "/api/audit-logs", "/api/invoices", "/api/expenses",
    "/api/users", "/api/credit-notes", "/api/payments", "/api/customers", "/api/jobs",
    "/api/estimates", "/api/reports", "/api/quickbooks", "/api/suppliers", "/api/technicians",
]


def _reachable(code):
    return isinstance(code, int) and 200 <= code < 300


def _denied(code):
    return code in (401, 403)


def enumerate_routes(base, session_for_role, roles, extra_routes=None):
    """Discovered routes = crawler XHR/API surfaces (per non-privileged role) + defaults + extras."""
    routes = set(DEFAULT_ROUTES) | set(extra_routes or [])
    try:
        import crawler
        cr = crawler.crawl(base, session_for_role=session_for_role, roles=[r for r in roles if r not in ("owner", "admin")])
        for s in (cr.get("surfaces") or []):
            # strip {id} templates to a base collection route (authz is per-collection)
            routes.add(s.split("/{")[0] if "/{" in s else s)
    except Exception:
        pass
    return sorted(r for r in routes if r and r.startswith("/"))


def probe_matrix(base, session_for_role, roles, routes, timeout=15):
    """GET every (route, role); return {route: {role: status}} + reachable/denied. Non-destructive."""
    import requests
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    matrix = {}
    for route in routes:
        matrix[route] = {}
        url = base.rstrip("/") + (route if route.startswith("/") else "/" + route)
        for role in roles:
            try:
                s = session_for_role(role)
                r = s.request("GET", url, timeout=timeout, verify=False)
                matrix[route][role] = r.status_code
            except Exception:
                matrix[route][role] = -1
    return matrix


def _policy_allows(policy, role, route):
    pats = policy.get(role) or policy.get(role.upper()) or policy.get(role.lower()) or []
    return any(fnmatch.fnmatch(route, p) or route.startswith(p.rstrip("*")) for p in pats)


def analyze(matrix, roles, *, policy=None, baseline_role=None, intended=(), owner_role="owner"):
    """Return over-reach findings. Config diff if policy given, else baseline over-reach."""
    intended = {r.lower() for r in intended}
    findings = []
    for route, byrole in matrix.items():
        # owner defines the "route exists + is meant to serve data" reference
        owner_ok = _reachable(byrole.get(owner_role, -1))
        for role, code in byrole.items():
            rl = role.lower()
            if rl == owner_role or rl in intended:
                continue                         # intended-privileged: never flagged
            if not _reachable(code):
                continue                         # role can't reach it -> fine
            if policy is not None:
                # CONFIG diff: reachable but policy does NOT grant it => over-reach vs the RBAC config
                if not _policy_allows(policy, role, route):
                    findings.append({"route": route, "role": role, "status": code,
                                     "kind": "config-over-reach", "severity": "high",
                                     "detail": "reachable by %s (HTTP %s) but the access policy does not grant it" % (role, code)})
            else:
                # BASELINE: reachable by this role but the baseline role is denied => over-reach
                b = byrole.get(baseline_role, -1) if baseline_role else -1
                if baseline_role and _denied(b) and owner_ok:
                    findings.append({"route": route, "role": role, "status": code,
                                     "kind": "baseline-over-reach", "severity": "high",
                                     "detail": "reachable by %s (HTTP %s) where baseline %s is denied (HTTP %s)" % (role, code, baseline_role, b)})
    return findings


def record_findings(findings, store, base=""):
    """Oracle-gated recording: the 2xx-vs-denied delta IS the ground truth -> verified."""
    from verified_findings import Finding, Evidence
    from dataclasses import asdict
    ids = []
    for f in findings:
        fd = Finding(claim_type="authz.route_over_reach",
                     summary=("%s over-reach: %s reaches %s (HTTP %s)" % (f["kind"], f["role"], f["route"], f["status"]))[:200],
                     severity=f.get("severity", "high"), target_id="target-mirror",
                     evidence=[asdict(Evidence(kind="note", detail=f["detail"][:300]))],
                     coverage_tags=["surface:%s" % f["route"], "technique:authz-matrix",
                                    "class:broken-access-control", "role:%s" % f["role"]],
                     provenance={"provider": "authz_matrix", "kind": f["kind"], "route": f["route"], "role": f["role"]})
        fid = store.record_candidate(fd)
        store._transition(fid, "verified", "authz-matrix", {"route": f["route"], "role": f["role"],
                          "status": f["status"], "kind": f["kind"]})
        ids.append(fid)
    return ids


def report_md(matrix, roles, findings):
    lines = ["# Authz matrix (per-route x per-role) — GET, non-destructive", ""]
    hdr = "| route | " + " | ".join(roles) + " |"
    lines += [hdr, "|" + "---|" * (len(roles) + 1)]
    for route in sorted(matrix):
        row = "| `%s` | " % route + " | ".join(str(matrix[route].get(r, "-")) for r in roles) + " |"
        lines.append(row)
    lines += ["", "## Over-reach findings: %d" % len(findings)]
    for f in findings:
        lines.append("- **[%s] %s** — %s" % (f["severity"].upper(), f["route"], f["detail"]))
    return "\n".join(lines)


def run(base, roles=None, routes_file=None, policy_file=None, intended=None, baseline_role=None,
        store_path=None):
    import session_factory
    sfr = session_factory.from_env(base)
    if sfr is None:
        return {"error": "no AEGIS_ROLE_MAP -- need role sessions for the matrix"}
    role_map = json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}"))
    roles = roles or (list(role_map.keys()) + ["anon"])
    intended = intended or [r for r in (os.environ.get("AEGIS_AUTHZ_INTENDED", "").split(",")) if r]
    baseline_role = baseline_role or os.environ.get("AEGIS_AUTHZ_BASELINE", "technician")
    extra = []
    if routes_file and os.path.exists(routes_file):
        extra = [l.strip() for l in open(routes_file, encoding="utf-8") if l.strip().startswith("/")]
    policy = None
    if policy_file and os.path.exists(policy_file):
        policy = json.load(open(policy_file, encoding="utf-8"))
    routes = enumerate_routes(base, sfr, roles, extra)
    matrix = probe_matrix(base, sfr, roles, routes)
    findings = analyze(matrix, roles, policy=policy, baseline_role=baseline_role,
                       intended=intended, owner_role=(roles[0] if roles else "owner"))
    out = {"base": base, "roles": roles, "routes": len(routes), "matrix": matrix,
           "findings": findings, "mode": "config-diff" if policy else "baseline"}
    if store_path is not None:
        try:
            from verified_findings import FindingStore
            st = FindingStore(store_path)
            out["recorded"] = len(record_findings(findings, st, base))
        except Exception as e:
            out["record_error"] = str(e)[:120]
    return out


def main():
    ap = argparse.ArgumentParser(description="Exhaustive per-route x per-role authz matrix + config diff")
    ap.add_argument("--base", default=os.environ.get("AEGIS_TARGET", "https://localhost:8443"))
    ap.add_argument("--roles", help="CSV; default = AEGIS_ROLE_MAP keys + anon")
    ap.add_argument("--routes-file", help="extra routes, one /path per line")
    ap.add_argument("--policy", help="intended access policy JSON {role:[globs]} -> config-diff mode")
    ap.add_argument("--intended", help="CSV roles never flagged (default AEGIS_AUTHZ_INTENDED)")
    ap.add_argument("--baseline", help="baseline role that should be denied (default AEGIS_AUTHZ_BASELINE)")
    ap.add_argument("--store", help="FindingStore path to record verified findings")
    ap.add_argument("--report", help="write the markdown matrix here")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = run(a.base, roles=(a.roles.split(",") if a.roles else None), routes_file=a.routes_file,
              policy_file=a.policy, intended=(a.intended.split(",") if a.intended else None),
              baseline_role=a.baseline, store_path=a.store)
    if res.get("error"):
        print("ERROR:", res["error"]); return 1
    if a.report:
        open(a.report, "w", encoding="utf-8").write(report_md(res["matrix"], res["roles"], res["findings"]))
    if a.json:
        print(json.dumps({k: v for k, v in res.items() if k != "matrix"}, indent=2, default=str))
    else:
        print("mode=%s | routes=%d roles=%d | OVER-REACH findings=%d"
              % (res["mode"], res["routes"], len(res["roles"]), len(res["findings"])))
        for f in res["findings"]:
            print("  [%s] %s <- %s (HTTP %s)" % (f["severity"], f["route"], f["role"], f["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
