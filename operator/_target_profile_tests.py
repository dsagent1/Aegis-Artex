#!/usr/bin/env python3
"""Offline tests for target_profile.py (persistent saturation/coverage memory) + its opt-in bandit bias.
No network. Run: python operator/_target_profile_tests.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
for k in ("AEGIS_TARGET_PROFILE", "AEGIS_PRIORITY", "AEGIS_PRIORITY_SPLIT"):
    os.environ.pop(k, None)
os.environ["AEGIS_SEED"] = "3"

import target_profile as TP  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

d = tempfile.mkdtemp()
pf = os.path.join(d, "tp.json")


def ctx():
    at = []
    at += [{"move": {"vuln_class": "idempotency", "surface": "/pay"}, "verdict": "rejected", "gain": 0, "delta": {"i": i}} for i in range(10)]
    at += [{"move": {"vuln_class": "ssrf", "surface": "/fetch"}, "verdict": ("verified" if i < 2 else "rejected"), "gain": 1, "delta": {"j": i}} for i in range(10)]
    at += [{"move": {"vuln_class": "authz", "surface": "/adm"}, "verdict": "rejected", "gain": 0, "delta": {"k": i}} for i in range(3)]
    return {"attempts": at, "confirmed": []}


# --- observe + idempotency ---
tp = TP.TargetProfile(path=pf)
n1 = tp.observe_context(ctx())
ok("observe folds all distinct attempts", n1 == 23)
ok("observe is idempotent (same context -> 0 new)", tp.observe_context(ctx()) == 0)
ok("class tallies", tp.classes["idempotency"]["tried"] == 10 and tp.classes["ssrf"]["confirms"] == 2)

# --- saturation ---
ok("idempotency saturated (10 tried, 0 payoff)", tp.saturated("idempotency") is True)
ok("ssrf NOT saturated (payoff rate 0.2)", tp.saturated("ssrf") is False)
ok("authz NOT saturated (below SAT_MIN tries)", tp.saturated("authz") is False)

# --- bias + hint ---
ok("bias down-weights only the saturated class", tp.bias() == {"idempotency": -TP.SAT_PENALTY})
ok("under_probed surfaces = the barely-tried one", "/adm" in tp.under_probed())
h = tp.hint()
ok("hint names the saturated class + under-probed surface", "idempotency" in h and "/adm" in h and "saturated" in h)

# --- persistence roundtrip ---
tp.save()
tp2 = TP.TargetProfile(path=pf)
ok("reload preserves tallies", tp2.classes["idempotency"]["tried"] == 10 and tp2.saturated("idempotency"))

# --- module helpers: inert when unset ---
os.environ.pop("AEGIS_TARGET_PROFILE", None)
ok("inert: active() False", TP.active() is False)
ok("inert: active_bias {} / active_hint '' / observe_and_save 0",
   TP.active_bias() == {} and TP.active_hint() == "" and TP.observe_and_save(ctx()) == 0)

# --- module helpers: active when set ---
os.environ["AEGIS_TARGET_PROFILE"] = pf
ok("active: bias reflects saturation", TP.active_bias() == {"idempotency": -TP.SAT_PENALTY})
ok("active: hint non-empty", "idempotency" in TP.active_hint())

# --- bandit wiring: saturation bias down-ranks a high-mean-but-saturated arm ---
import t0_bandit as TB  # noqa: E402
def bandit():
    b = TB.Bandit(path=None)
    for a in b.arms:
        b.arms[a] = {"n": 5, "reward_sum": 0.5}      # mean 0.10 baseline
    b.arms["idempotency"] = {"n": 5, "reward_sum": 4.5}   # mean 0.90 -> would normally lead
    b.arms["ssrf"] = {"n": 5, "reward_sum": 3.0}          # mean 0.60
    return b

os.environ.pop("AEGIS_TARGET_PROFILE", None)
ok("inert bandit: saturated-but-high arm still leads (no profile)", bandit().select(4)[0] == "idempotency")
os.environ["AEGIS_TARGET_PROFILE"] = pf
top = bandit().select(4)
ok("active bandit: saturated idempotency (0.90 - 0.6 = 0.30) DROPS below ssrf (0.60)", top[0] == "ssrf")
ok("active bandit: saturated arm pushed out of the lead", top[0] != "idempotency")
os.environ.pop("AEGIS_TARGET_PROFILE", None)

n = 17
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
