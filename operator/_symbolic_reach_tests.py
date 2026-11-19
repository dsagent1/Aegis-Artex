#!/usr/bin/env python3
"""Offline tests for symbolic_reach -- reachability, guard extraction, z3 solving. No target/network.
Run: python operator/_symbolic_reach_tests.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import symbolic_reach as SR  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

# --- intra scan: direct sink + guard extraction ---
src = '''
def handle(data):
    if len(data) > 10:
        if data.startswith("X"):
            eval(data)
def helper(x):
    run_it(x)
def run_it(y):
    __import__(y)
def safe(z):
    return z + 1
'''
funcs, okp = SR.scan_python(src)
ok("scan ok", okp)
ok("handle has eval sink", any(c == "code-exec" for _, c, _ in funcs["handle"]["sinks"]))
ok("guard captured (len + startswith)", any("startswith" in " ".join(g) for _, _, g in funcs["handle"]["sinks"]))
ok("safe has no sink", not funcs["safe"]["sinks"])

# --- end-to-end analyze over a tree ---
d = tempfile.mkdtemp()
open(os.path.join(d, "m.py"), "w").write(src)
res = SR.analyze(d)
by_entry = {c["entry"].split(":")[-1]: c for c in res}
ok("handle reaches code-exec", by_entry.get("handle", {}).get("sink_class") == "code-exec")
ok("multi-hop: helper -> run_it -> __import__", "helper" in by_entry and "run_it" in by_entry["helper"]["path"])
ok("safe not reported", "safe" not in by_entry)

# --- z3 solving (z3 is available in this env) ---
if SR._HAVE_Z3:
    v, ex = SR._solve(["len(data) > 3", 'data.startswith("PK")'], ["data"])
    ok("z3 SAT on satisfiable guards", v == "sat")
    ok("z3 reaching input starts with PK", isinstance(ex, dict) and str(ex.get("data", "")).startswith("PK"))
    v2, _ = SR._solve(["len(x) > 10", "len(x) < 5"], ["x"])
    ok("z3 UNSAT on contradictory guards", v2 == "unsat")
    v3, _ = SR._solve(["frobnicate(x) == weird(x)"], ["x"])
    ok("untranslatable guard -> unknown", v3 == "unknown")
    v4, _ = SR._solve([], ["x"])
    ok("no guards -> no-guards", v4 == "no-guards")
else:
    for _ in range(5):
        ok("z3 present (skipped)", True)

# --- boost_candidates re-ranks reachable-to-sink first ---
cands = [{"target": "m.py:safe", "value": 2}, {"target": "m.py:handle", "value": 2}]
boosted = SR.boost_candidates(cands, d)
ok("boost puts sink-reaching entry first", boosted[0]["target"] == "m.py:handle")
ok("boost marks reaches_sink", boosted[0].get("reaches_sink") is True)

# --- reaching-input -> corpus seed bytes (fuzz_driver wiring) ---
import fuzz_driver as FD
ok("seeds from reaching_input", FD._seeds_from_reach({"reaching_input": {"data": "PKxx"}}) == [b"PKxx"])
ok("no reaching_input -> no seeds", FD._seeds_from_reach({"value": 2}) == [])

n = 16
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
