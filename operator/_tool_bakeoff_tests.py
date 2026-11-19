#!/usr/bin/env python3
"""Offline tests for the tool bake-off core (scenario->class, recall, matrix, markdown) + the new
compare_recall classes/semgrep adapter. No live tools/network. Run: python operator/_tool_bakeoff_tests.py"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare_recall as CR   # noqa: E402
import tool_bakeoff as TB     # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")


def scen(sid, vuln, path):
    ev = types.SimpleNamespace(hops=[{"check": {"path": path}}])
    return types.SimpleNamespace(id=sid, intended_vuln=vuln,
                                 evidence=ev, target=types.SimpleNamespace(build="targets/x"))


# --- new compare_recall wiring ---
ok("semgrep registered as a SAST source-adapter", "semgrep" in CR.SOURCE_ADAPTERS)
ok("ExploitGym classes added to CLASS_KW", all(c in CR.CLASS_KW for c in ("ssrf", "mass_assignment", "misconfig", "supply_chain")))
ok("semgrep NOT in the DAST ADAPTERS (different signature)", "semgrep" not in CR.ADAPTERS)

# --- class_of mapping (most-specific-first) ---
ok("ssrf intent -> ssrf", TB.class_of("SSRF -> cloud-metadata credential theft -> lateral (trust-chain)") == "ssrf")
ok("mass-assignment intent -> mass_assignment (before privesc/authz)",
   TB.class_of("mass-assignment privilege escalation -> admin-only broken access control") == "mass_assignment")
ok("sqli intent -> injection", TB.class_of("SQL injection auth bypass") == "injection")
ok("unknown intent -> ''", TB.class_of("some novel thing") == "")

# --- scenario_expected ---
e = TB.scenario_expected(scen("s_ssrf", "SSRF to metadata", "/api/fetch"))
ok("scenario_expected class+surface", e["class"] == "ssrf" and e["surface"] == "/api/fetch" and e["id"] == "s_ssrf")

# --- recalled: blob matching the class + surface -> True; mismatch -> False ---
ok("recalled: ssrf blob hits ssrf expected",
   TB.recalled({"id": "x", "class": "ssrf", "surface": "/api/fetch", "match": []},
               ["server-side request forgery at /api/fetch"]) is True)
ok("recalled: unrelated blob misses", TB.recalled({"id": "x", "class": "ssrf", "surface": "/api/fetch", "match": []},
               ["x-frame-options header missing on /"]) is False)

# --- build_matrix + operator-unique coverage ---
S_SSRF = scen("s_ssrf", "SSRF to metadata", "/api/fetch")
S_MASS = scen("s_mass", "mass-assignment privilege escalation", "/api/users/me")
expecteds = [TB.scenario_expected(S_SSRF), TB.scenario_expected(S_MASS)]
blobs = {
    "s_ssrf": {"nuclei": ["ssrf detected server-side request forgery /api/fetch"], "zap": ["cookie without HttpOnly"]},
    "s_mass": {"nuclei": ["missing security header"], "zap": ["verbose error"]},   # neither finds mass-assignment
}
op_hits = {"s_ssrf": True, "s_mass": True}
m = TB.build_matrix(expecteds, blobs, op_hits)
ok("matrix tools discovered", set(m["tools"]) == {"nuclei", "zap"})
ok("nuclei recalls ssrf", m["rows"]["nuclei"]["s_ssrf"] is True)
ok("nuclei misses mass-assignment", m["rows"]["nuclei"]["s_mass"] is False)
ok("operator recalls both", m["rows"]["AEGIS-operator"]["s_ssrf"] and m["rows"]["AEGIS-operator"]["s_mass"])
ok("recall counts", m["recall"]["AEGIS-operator"] == (2, 2) and m["recall"]["nuclei"] == (1, 2))
ok("operator-unique = mass-assignment (missed by every tool)", m["operator_unique"] == ["s_mass"])

# --- markdown renders the table + the differentiator line ---
md = TB.to_markdown(m)
ok("markdown has a table header", "tool/operator" in md and "recall" in md)
ok("markdown flags operator-unique coverage", "Operator-unique coverage" in md and "s_mass" in md)

n = 18
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
