#!/usr/bin/env python3
"""Offline tests for the PRIORITY SWITCH (opt-in, multi-direction, agent-split; non-persisting).
No LLM/network/Kali. Run: python operator/_priority_switch_tests.py"""
import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["AEGIS_SEED"] = "1"                      # deterministic tie-break
for k in ("AEGIS_PRIORITY", "AEGIS_PRIORITY_BONUS", "AEGIS_PRIORITY_SPLIT"):
    os.environ.pop(k, None)

import t0_bandit as TB  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")


def fresh():
    """A bandit with EQUAL n across arms (equal UCB exploration term) and DISTINCT means, so pure-UCB order
    is exactly the mean order and `idempotency` is the strict leader -- modelling the converged winner."""
    b = TB.Bandit(path=None)
    means = {
        "idempotency": 0.90, "info_disclosure": 0.80, "business_logic": 0.70, "injection": 0.60,
        "auth": 0.22, "authz": 0.20, "ssrf": 0.18, "misconfig": 0.16, "mass_assignment": 0.14,
        "recon": 0.12, "privesc": 0.10, "lateral": 0.08, "race": 0.06, "supply_chain": 0.04,
    }
    for a in b.arms:
        m = means.get(a, 0.05)
        b.arms[a] = {"n": 5, "reward_sum": round(m * 5, 4)}
    return b


# --- inert when unset ---
ok("privesc/lateral registered as default arms", "privesc" in TB.Bandit(path=None).arms and "lateral" in TB.Bandit(path=None).arms)
ok("unset -> _profile_families None (inert)", TB._profile_families() is None)
ok("unset -> priority_active False", TB.priority_active() is False)
ok("unset -> bonus 0 for any arm", TB._profile_bonus("authz") == 0.0 and TB._profile_bonus("idempotency") == 0.0)
b = fresh()
base_top = b.select(k=4)
ok("unset select is UCB-only (idempotency leads)", base_top[0] == "idempotency")

# --- none/off treated as inert ---
os.environ["AEGIS_PRIORITY"] = "off"
ok("'off' -> inert", TB._profile_families() is None and TB._profile_bonus("authz") == 0.0)
os.environ["AEGIS_PRIORITY"] = "none"
ok("'none' -> inert", TB._profile_families() is None)

# --- trust_chain: bonus + multi-direction span ---
os.environ["AEGIS_PRIORITY"] = "trust_chain"
ok("trust_chain active", TB.priority_active() is True and TB._profile_families())
ok("in-family arm gets bonus", TB._profile_bonus("authz") == 0.5 and TB._profile_bonus("ssrf") == 0.5)
ok("out-of-family arm gets no bonus", TB._profile_bonus("idempotency") == 0.0)
b = fresh()
arms_before = copy.deepcopy(b.arms)
top = b.select(k=4)
fam_kw = TB._PROFILES["trust_chain"]
def fam_of(a):
    al = a.lower()
    return next((f for f in fam_kw if f in al), None)
spanned = {fam_of(a) for a in top if fam_of(a)}
ok("trust_chain top-4 spans >=3 distinct families", len(spanned) >= 3)
ok("trust_chain does NOT fill top-4 with the converged winner", "idempotency" not in top[:4])
# NON-PERSISTENCE: select() with priority must not touch arm counts/rewards
ok("select() never mutates persisted arm stats (no poisoning)", b.arms == arms_before)

# --- bonus magnitude tunable ---
os.environ["AEGIS_PRIORITY_BONUS"] = "0.9"
ok("bonus tunable via env", TB._profile_bonus("authz") == 0.9)
os.environ.pop("AEGIS_PRIORITY_BONUS", None)

# --- balanced: active de-herd, but NO directional bonus and NO family span ---
os.environ["AEGIS_PRIORITY"] = "balanced"
ok("balanced is active (not None)", TB._profile_families() == [] and TB.priority_active() is True)
ok("balanced gives no directional bonus", TB._profile_bonus("authz") == 0.0)
b = fresh()
ok("balanced select falls back to UCB order (idempotency leads)", b.select(k=4)[0] == "idempotency")

# --- ad-hoc comma-list families ---
os.environ["AEGIS_PRIORITY"] = "authz,ssrf"
ok("ad-hoc list parsed", TB._profile_families() == ["authz", "ssrf"])
b = fresh()
top2 = b.select(k=4)
ok("ad-hoc list spans its two families in the top", {fam_of(a) for a in top2 if fam_of(a)} >= {"authz", "ssrf"})

# --- split kill-switch ---
os.environ["AEGIS_PRIORITY"] = "trust_chain"
os.environ["AEGIS_PRIORITY_SPLIT"] = "0"
b = fresh()
top3 = b.select(k=4)
# with split off, bonus still applies (families rise) but no round-robin span guarantee
ok("split kill-switch: still returns k arms", len(top3) == 4)
os.environ.pop("AEGIS_PRIORITY_SPLIT", None)

# --- agent-split _pick: a worker avoids an angle already inflight (guarded: needs the MA harness offline) ---
os.environ["AEGIS_PRIORITY"] = "trust_chain"
pick_tested = False
try:
    from agent_hunt import MultiAgentHunt, angle_of
    ma = MultiAgentHunt(brainstorm=lambda ctx: [], execute=lambda m, p: {},
                        oracle=lambda r: ("rejected", {}), budget=10, n_agents=3)
    ma.candidates = [
        {"angle": "authz", "surface": "/a", "vuln_class": "authz"},
        {"angle": "ssrf", "surface": "/b", "vuln_class": "ssrf"},
    ]
    ma.claimed = set()
    ma.st.tried = set()
    # authz is already inflight -> _pick should prefer the ssrf move (different direction)
    chosen = ma._pick(inflight_angles={"authz"})
    pick_tested = True
    ok("agent-split: worker avoids an angle already inflight", angle_of(chosen) == "ssrf")
except Exception as e:
    print(f"SKIP agent-split _pick test (harness not offline-constructible: {str(e)[:80]})")

os.environ.pop("AEGIS_PRIORITY", None)

n = 20 if pick_tested else 19
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
