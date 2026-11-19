#!/usr/bin/env python3
"""Offline tests for param_optimizer.py (per-target probe-knob tuning). No network.
Run: python operator/_param_optimizer_tests.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.pop("AEGIS_PARAM_OPT", None)
import param_optimizer as PO  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

d = tempfile.mkdtemp()
pf = os.path.join(d, "po.json")

# --- knob space + variants ---
opt = PO.ParamOptimizer(path=pf)
ok("knobs_for injection", "encoding" in opt.knobs_for("injection"))
ok("unknown class -> no knobs -> no variants", opt.variants({"vuln_class": "novel_thing"}) == [])
v = opt.variants({"vuln_class": "injection"}, limit=5)
ok("variants returns param dicts", v and all(isinstance(p, dict) and "encoding" in p for p in v))
ok("base variant uses declared-first values on cold start", v[0]["encoding"] == "none" and v[0]["content_type"] == "json")
ok("variants are distinct (base + single-knob perturbations)", len({tuple(sorted(p.items())) for p in v}) == len(v))

# --- learning: observing a strong signal on encoding=unicode ranks it first next time ---
opt.observe("injection", {"encoding": "unicode", "content_type": "json"}, signal=0.7)
opt.observe("injection", {"encoding": "unicode", "content_type": "json"}, signal=0.7)
v2 = opt.variants({"vuln_class": "injection"})
ok("learned knob value now leads the base variant", v2[0]["encoding"] == "unicode")

# --- observe ignores non-positive signal ---
before = dict(opt.scores["injection"]["encoding"])   # snapshot
opt.observe("injection", {"encoding": "url"}, signal=0.0)
ok("zero signal does not move scores", opt.scores["injection"]["encoding"] == before)

# --- persistence roundtrip ---
opt.save()
opt2 = PO.ParamOptimizer(path=pf)
ok("reload preserves learned scores", opt2.variants({"vuln_class": "injection"})[0]["encoding"] == "unicode")

# --- response_signal: deltas vs baseline ---
base = {"status": 200, "length": 1000, "elapsed": 0.1, "body": "ok"}
ok("status change -> signal", PO.response_signal(base, {"status": 500, "length": 1000, "elapsed": 0.1}) >= 0.4)
ok("size delta -> signal", PO.response_signal(base, {"status": 200, "length": 5000, "elapsed": 0.1}) >= 0.3)
ok("timing delta -> signal", PO.response_signal(base, {"status": 200, "length": 1000, "elapsed": 1.2}) >= 0.3)
ok("stack trace in body -> signal", PO.response_signal(base, {"status": 200, "length": 1000, "body": "Traceback (most recent call last)"}) >= 0.3)
ok("identical response -> ~0 signal", PO.response_signal(base, dict(base)) == 0.0)

# --- opt-in module helpers: inert unless AEGIS_PARAM_OPT set ---
ok("inert: active() False + variants_for [] ", PO.active() is False and PO.variants_for({"vuln_class": "injection"}) == [])
os.environ["AEGIS_PARAM_OPT"] = pf
ok("active: variants_for returns tuned variants", PO.variants_for({"vuln_class": "injection"})[0]["encoding"] == "unicode")
os.environ.pop("AEGIS_PARAM_OPT", None)

n = 15
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
