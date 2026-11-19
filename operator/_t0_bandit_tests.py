"""_t0_bandit_tests.py -- behavioral tests for the T0 UCB1 selector core (t0_bandit.Bandit).

Covers the mechanics the add-on suites (_priority_switch_tests, _target_profile_tests) assume but do
NOT themselves pin down: UCB1 scoring, the reward model, dynamic arm registration (the privesc/lateral/
field-leak path), the load/merge contract that lets NEW default arms appear in an OLD saved state, the
save/load roundtrip, exclude, snapshot, and learn_from_context dedup/idempotency. Offline, no LLM.

Run: python _t0_bandit_tests.py   (exit 0 = all pass)
"""
import json, math, os, tempfile, sys

# ensure sibling-module imports (target_profile, imported lazily inside select()) resolve
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import t0_bandit as B

_P = _F = 0
def ok(cond, label):
    global _P, _F
    if cond:
        _P += 1; print("PASS " + label)
    else:
        _F += 1; print("FAIL " + label)

def _fresh(**kw):
    # no AEGIS_PRIORITY -> priority switch inert; fixed seed for reproducible tie-breaks
    os.environ.pop("AEGIS_PRIORITY", None)
    return B.Bandit(seed=1, **kw)

# ---- UCB1 scoring ---------------------------------------------------------------------------------
b = _fresh()
ok(b.score("authz") == B._UNTRIED and B._UNTRIED > 1e6, "unplayed arm scores the finite try-once sentinel (not inf)")
b.update("authz", "rejected", info_gain=0)          # one pull, reward 0
s = b.score("authz")
exp = (0.0 / 1) + b.c * math.sqrt(math.log(max(1, b._total())) / 1)
ok(abs(s - exp) < 1e-9, "UCB1 score = mean + c*sqrt(ln(total)/n)")
ok(b.score("ssrf") == B._UNTRIED, "a still-unplayed arm stays at the sentinel while another has been pulled")

# ---- reward model ---------------------------------------------------------------------------------
b = _fresh()
b.update("injection", "verified")                    # impact(injection)=1.3 -> 1.0*1.3*1.3
ok(abs(b.arms["injection"]["reward_sum"] - (1.3 * 1.3)) < 1e-9, "verified reward = impact(cls)*impact(surface=cls)")
b.update("recon", "rejected", info_gain=1)           # info-gaining clean
ok(abs(b.arms["recon"]["reward_sum"] - 0.15) < 1e-9, "info-gaining clean -> 0.15")
b.update("recon", "rejected", info_gain=0)           # pure noise
ok(b.arms["recon"]["reward_sum"] == 0.15 and b.arms["recon"]["n"] == 2, "noise adds 0 reward but still counts n")
b.update("money", "verified")                        # money keyword -> 1.6
ok(abs(b.arms["money"]["reward_sum"] - (1.6 * 1.6)) < 1e-9, "high-impact surface scales reward up")
b.update("", "verified")                             # empty class is a no-op
ok("" not in b.arms, "empty class update is a no-op")

# ---- surface_class scales impact independently ----------------------------------------------------
b = _fresh()
b.update("recon", "verified", surface_class="money")  # impact(recon)=1.0, impact(money)=1.6
ok(abs(b.arms["recon"]["reward_sum"] - (1.0 * 1.6)) < 1e-9, "surface_class scales impact separately from cls")

# ---- dynamic registration (the privesc/lateral/field-leak path) -----------------------------------
b = _fresh()
ok("privesc" in b.arms and "lateral" in b.arms, "privesc & lateral ship as default arms")
ok("field-leak" not in b.arms, "field-leak is NOT a default arm (introduced dynamically)")
b.register("field-leak")
ok(b.arms["field-leak"] == {"n": 0, "reward_sum": 0.0}, "register() adds a new arm at zero")
n_before = len(b.arms)
b.register("field-leak")                             # idempotent
b.update("field-leak", "verified")                   # update() auto-registers too
ok(len(b.arms) == n_before, "register() is idempotent; update() does not duplicate an arm")
b.update("brand-new-synth-class", "verified")
ok("brand-new-synth-class" in b.arms, "update() auto-registers an unseen class")

# ---- load/merge: a NEW default arm must appear even in an OLD saved state --------------------------
fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
try:
    # simulate a saved state from before privesc/lateral/field-leak existed
    json.dump({"arms": {"authz": {"n": 5, "reward_sum": 2.0}, "field-leak": {"n": 3, "reward_sum": 0.45}},
               "saved": "2026-09-01T00:00:00Z"}, open(path, "w"))
    b = _fresh(path=path)
    ok(b.arms["authz"] == {"n": 5, "reward_sum": 2.0}, "load overlays saved values onto an existing arm")
    ok(b.arms["field-leak"] == {"n": 3, "reward_sum": 0.45}, "load adds a saved arm absent from defaults")
    ok(b.arms["privesc"] == {"n": 0, "reward_sum": 0.0}, "a default arm missing from the OLD save still appears at zero")
    # ---- save/load roundtrip is lossless ----------------------------------------------------------
    b.update("privesc", "verified"); b.save()
    d = json.load(open(path, encoding="utf-8"))
    ok("saved" in d and d["arms"]["privesc"]["n"] == 1, "save writes arms + a 'saved' UTC stamp")
    b2 = _fresh(path=path)
    ok(b2.arms["privesc"]["n"] == 1 and b2.arms["authz"]["n"] == 5, "reload preserves every arm's counts")
    # ---- corrupt file never raises ----------------------------------------------------------------
    open(path, "w").write("{not json")
    b3 = _fresh(path=path)
    ok("authz" in b3.arms, "a corrupt state file is tolerated (falls back to defaults, no raise)")
finally:
    os.remove(path)

# ---- select(): ordering, exclude, no mutation, k bounds -------------------------------------------
b = _fresh()
for _ in range(3):                                   # make idempotency the clear UCB leader
    b.update("idempotency", "verified")
for a in ("authz", "ssrf", "recon", "injection", "privesc", "lateral", "business_logic",
          "auth", "race", "mass_assignment", "info_disclosure", "supply_chain", "misconfig"):
    b.update(a, "rejected", info_gain=0)             # pulled once, zero reward -> finite, low score
top = b.select(k=3)
ok(top[0] == "idempotency", "select() puts the high-reward arm first once all arms are explored")
snap_n = {a: b.arms[a]["n"] for a in b.arms}
_ = b.select(k=3, exclude=["idempotency"])
ok(_ and "idempotency" not in _, "exclude drops a saturated/closed class")
ok({a: b.arms[a]["n"] for a in b.arms} == snap_n, "select() never mutates persisted arm stats (no poisoning)")
ok(len(b.select(k=999)) == len(b.arms), "k larger than the arm set returns all arms")
ok(len(b.select(k=0)) == 1, "k=0 is clamped to at least one arm")

# ---- snapshot ------------------------------------------------------------------------------------
snap = b.snapshot()
# idempotency impact=1.5 -> each verified pull rewards 1.5*1.5=2.25, so mean over 3 pulls is 2.25
ok(snap["idempotency"]["mean"] == 2.25 and snap["idempotency"]["n"] == 3, "snapshot reports impact-scaled mean & n")
b4 = _fresh()
ok(b4.snapshot()["authz"]["ucb"] is None, "snapshot shows None ucb for a never-played arm")

# ---- learn_from_context: dedup by signature, idempotent -------------------------------------------
b = _fresh()
ctx = {"confirmed": [{"move": {"vuln_class": "authz", "surface": "money"}}],
       "attempts": [{"move": {"vuln_class": "ssrf", "surface": "/x"}, "verdict": "rejected", "gain": 1},
                    {"move": {"vuln_class": "ssrf", "surface": "/x"}, "verdict": "rejected", "gain": 1}]}
learned = B.learn_from_context(b, ctx)
ok(learned == 2, "learn folds 1 confirm + 1 unique attempt, dedups the duplicate attempt")
ok(b.arms["authz"]["n"] == 1 and b.arms["ssrf"]["n"] == 1, "confirm->authz, attempt->ssrf each recorded once")
ok(B.learn_from_context(b, ctx) == 0, "re-folding the same context learns 0 (idempotent)")
eps = {"attempts": [{"move": {"vuln_class": "race", "surface": "/r", "_eps": True}, "verdict": "rejected", "gain": 0}]}
B.learn_from_context(b, eps)
ok(b.arms["race"]["n"] == 0, "epsilon-diversify picks (_eps) are logged but never update the posterior")

# ---- behavioral: bandit shifts toward the rewarding class, exploration keeps laggards alive --------
b = _fresh()
for _ in range(20):
    sel = b.select(k=1)[0]
    b.update(sel, "verified" if sel == "ssrf" else "rejected",
             info_gain=0 if sel != "ssrf" else 1)
ok(b.arms["ssrf"]["n"] >= 2, "a consistently-rewarding arm accrues pulls")
ok(all(b.arms[a]["n"] >= 1 for a in B._DEFAULT_ARMS), "UCB exploration tries every default arm at least once")

print(f"\n{_P}/{_P + _F} PASS" + (f"  ({_F} FAIL)" if _F else ""))
sys.exit(1 if _F else 0)
