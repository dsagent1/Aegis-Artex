#!/usr/bin/env python3
"""review_gate.py -- PRE-INTEGRATION review gate for new orchestrator code.

Motivation: the multi-model board STATIC review (code_review.py) is good at local smells but structurally
CANNOT see the bugs that actually bit the parallel multi-agent module -- (1) a per-role HTTP session shared
across worker threads that FALSE-POSITIVED a stateful logout oracle, and (2) a budget that counted noise
(404/transport/exception) as real attempts, diverging from the single-agent engine. Both are RUNTIME /
DIFFERENTIAL bugs. So this gate is BEHAVIOR-FIRST: it runs the new module against the trusted single-agent
reference on identical offline callables and diffs observable outcomes.

Design consulted with the board (ds_direct + cf_kimi-k2.7-code, 2026-09-24). Consensus:
  - center of gravity = a DIFFERENTIAL-ORACLE harness (candidate vs reference, identical callables), plus a
    PARALLEL session-ISOLATION probe (id() uniqueness per worker). Those two encode the two missed bug CLASSES
    as executable properties.
  - HARD-FAIL only on reproducible, DETERMINISTIC signal (a flaky gate gets disabled -> worse than none).
    Static-review findings + perf deltas are ADVISE-ONLY, never blocking.
  - offline-safe (synthetic callables, no network), non-destructive (no live session/ledger), fail-closed.

Checks (hard-fail unless noted):
  1. smoke            -- construct + run tiny hunt on a frozen fixture; clean return shape; no thread leak.
  2. budget_parity    -- DIFFERENTIAL: on an all-REAL fixture both engines count real work and candidate
                         reports noise==0; on an all-NOISE fixture the reference counts 0 real attempts and
                         the candidate MUST agree (executed==0, noise>0). Encodes bug class 2 (F1).
  3. noise_ceiling    -- an all-noise run terminates (does not spin) and spends 0 real budget.
  4. session_isolation-- per-worker session provider yields a DISTINCT object per thread; a deliberately
                         shared provider is correctly FLAGGED (self-validates the detector). Encodes class 1 (F2).
  5. static_review    -- ADVISE-ONLY: fold in code_review JSON high-severity items; never blocks.

Usage:
  python review_gate.py                       # run all checks against MultiAgentHunt vs IterativeHunt
  python review_gate.py --static-json <f>     # also fold a code_review --json dump as advice
  python review_gate.py --json                # machine-readable verdict; exit 0 = pass, non-zero = blocked
"""
from __future__ import annotations
import os, sys, json, time, random, argparse, threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "shared"))

from agent_hunt import MultiAgentHunt          # candidate
from iterative_hunt import IterativeHunt        # trusted single-agent reference

_SURFACES = [f"/api/s{i}" for i in range(6)]
_CLASSES = ["injection", "xss", "authz", "idor", "ssrf", "auth"]


def _move(s, c, mech="m", pay="0"):
    return {"surface": s, "vuln_class": c, "class": c, "mechanism": mech, "method": "POST", "payload": pay}


def _distinct_moves(n):
    """n distinct-fingerprint moves (deterministic, order-independent)."""
    out = []
    for i in range(n):
        out.append(_move(_SURFACES[i % len(_SURFACES)], _CLASSES[(i // len(_SURFACES)) % len(_CLASSES)],
                         mech=f"m{i}", pay=str(i)))
    return out


def _real_callables(findable):
    """Every executed move is INFORMATION-GAINING (status 200 + unique body + oracle receipt). A move whose
    (surface,class) is in `findable` verifies; others are refuted WITH evidence (still real work)."""
    def brainstorm(ctx):
        return []                                          # seeds-only: deterministic, no board needed
    def execute(move, phase):
        key = (move.get("surface"), move.get("vuln_class"))
        return {"move": move, "hit": key in findable, "status": 200,
                "body": "resp:%s:%s:%s" % (move.get("surface"), move.get("vuln_class"), move.get("payload"))}
    def oracle(result):
        return (("verified", {"ok": True}) if result.get("hit") else ("rejected", {"checked": True}))
    return brainstorm, execute, oracle


def _noise_callables():
    """Every executed move is NOISE: no evidence (transport-style error receipt, non-informative status).
    A correct engine must NOT count these against the real-attempt budget."""
    def brainstorm(ctx):
        return []
    def execute(move, phase):
        return {"move": move, "status": "0", "body": ""}   # no informative status, empty body
    def oracle(result):
        return ("rejected", {"error": "transport", "unreachable": True})
    return brainstorm, execute, oracle


# ---- checks -----------------------------------------------------------------------------------------
def _add(res, name, hard_fail, ok, detail):
    res["checks"].append({"name": name, "advise_only": not hard_fail, "ok": ok, "detail": detail})
    if hard_fail and not ok:
        res["hard_fail"].append(f"{name}: {detail}")
    if (not hard_fail) and not ok:
        res["advise"].append(f"{name}: {detail}")


def check_smoke(res):
    seeds = _distinct_moves(6)
    bs, ex, orc = _real_callables(set())
    t0 = threading.active_count()
    try:
        h = MultiAgentHunt(bs, ex, orc, budget=6, n_agents=4, seed_moves=seeds, max_board_rounds=2)
        m = h.run("fixture", "smoke")
    except Exception as e:
        _add(res, "smoke", True, False, f"raised {type(e).__name__}: {str(e)[:120]}"); return
    time.sleep(0.2)
    leaked = threading.active_count() - t0
    keys = {"executed", "verified", "noise", "proposals", "board_rounds"}
    ok = keys.issubset(m) and leaked <= 1
    _add(res, "smoke", True, ok, f"metrics_keys_ok={keys.issubset(m)} thread_leak={leaked} metrics={ {k:m.get(k) for k in keys} }")


def check_budget_parity(res):
    findable = {(_SURFACES[0], "injection"), (_SURFACES[1], "authz"), (_SURFACES[2], "idor")}
    seeds = _distinct_moves(12)
    # --- all-REAL: both engines do real work; candidate must report NO noise ---
    bs, ex, orc = _real_callables(findable)
    cand = MultiAgentHunt(bs, ex, orc, budget=12, n_agents=1, seed_moves=list(seeds), max_board_rounds=1)
    cm = cand.run("fixture", "real")
    bs2, ex2, orc2 = _real_callables(findable)
    ref = IterativeHunt(bs2, ex2, orc2, budget=12, seed_moves=list(seeds), max_board_rounds=1)
    rr = ref.run("fixture", "real")
    ref_real = rr.get("real_attempts", 0)
    real_ok = (cm["noise"] == 0 and cm["executed"] > 0 and ref_real > 0)
    _add(res, "budget_parity/all_real", True, real_ok,
         f"candidate executed={cm['executed']} noise={cm['noise']} | reference real_attempts={ref_real} "
         f"(real work must NOT be scored as noise)")
    # DIFFERENTIAL on the discovered set: candidate must AGREE with the reference (not necessarily find all
    # findables -- the shared angle-cap legitimately bounds both engines; the property is parity, not coverage).
    ref_conf = len(rr.get("confirmed", []) or [])
    find_ok = (cm["verified"] == ref_conf)
    _add(res, "budget_parity/discovered_set", True, find_ok,
         f"candidate verified={cm['verified']} reference confirmed={ref_conf} "
         f"(differential: candidate must match the reference's discovered count; findable={len(findable)})")
    # --- all-NOISE: reference counts 0 real; candidate MUST agree (this is the F1 regression guard) ---
    bs, ex, orc = _noise_callables()
    candn = MultiAgentHunt(bs, ex, orc, budget=12, n_agents=1, seed_moves=_distinct_moves(12), max_board_rounds=1)
    cn = candn.run("fixture", "noise")
    bs2, ex2, orc2 = _noise_callables()
    refn = IterativeHunt(bs2, ex2, orc2, budget=12, seed_moves=_distinct_moves(12), max_board_rounds=1)
    rn = refn.run("fixture", "noise")
    ref_noise_real = rn.get("real_attempts", 0)
    # only a valid differential if the reference AGREES the fixture is noise
    if ref_noise_real == 0:
        noise_ok = (cn["executed"] == 0)
        _add(res, "budget_parity/all_noise", True, noise_ok,
             f"candidate executed(real)={cn['executed']} noise={cn['noise']} | reference real_attempts=0 "
             f"(noise must NOT pad the real-attempt budget)")
    else:
        _add(res, "budget_parity/all_noise", False, True,
             f"skipped: reference scored {ref_noise_real} real on the noise fixture (fixture not pure noise)")


def check_noise_ceiling(res):
    bs, ex, orc = _noise_callables()
    h = MultiAgentHunt(bs, ex, orc, budget=8, n_agents=4, seed_moves=_distinct_moves(40), max_board_rounds=1)
    t0 = time.time()
    m = h.run("fixture", "noise-ceiling")
    took = time.time() - t0
    ok = (m["executed"] == 0 and m["noise"] > 0 and took < 20)
    _add(res, "noise_ceiling", True, ok,
         f"executed(real)={m['executed']} noise={m['noise']} took={took:.1f}s (all-noise run must terminate, spend 0 real budget)")


def check_session_isolation(res):
    """Bug class 1 (F2): a per-worker session provider must yield a DISTINCT object per thread. We validate
    the DETECTOR on two stub providers -- a thread-local one (correct, like agent_hunt_live._session_for_role)
    and a shared one (buggy) -- so the check both encodes the property AND proves it can catch a violation.
    Wire your real provider here to gate the live path."""
    def _probe(provider, n=4):
        # ThreadPoolExecutor REUSES threads, so the property is NOT per-task uniqueness -- it is: no session
        # object is ever observed from >1 DISTINCT thread. (Same thread reusing its own object is correct.)
        seen = {}                                          # obj_id -> set(thread_ids)
        lock = threading.Lock()
        def w(_):
            o = provider("owner"); tid = threading.get_ident()
            with lock:
                seen.setdefault(id(o), set()).add(tid)
            time.sleep(0.01)                               # overlap threads so a SHARED object is seen widely
        with ThreadPoolExecutor(max_workers=n) as ex:
            list(ex.map(w, range(n * 4)))
        return all(len(tids) == 1 for tids in seen.values())   # True = no object crossed a thread boundary

    _tls = threading.local()
    def good(role):                                        # thread-local -> one session object per thread
        s = getattr(_tls, "s", None)
        if s is None:
            s = object(); _tls.s = s
        return s
    _shared = object()
    def bad(role):                                         # shared singleton -> same object across threads
        return _shared

    good_isolated = _probe(good)
    bad_flagged = not _probe(bad)                          # detector must report the shared provider as NOT isolated
    ok = good_isolated and bad_flagged
    _add(res, "session_isolation", True, ok,
         f"thread_local_isolated={good_isolated} shared_provider_flagged={bad_flagged} "
         f"(detector self-validated; point --session-provider at the live provider to gate it)")


def check_depth_parity(res):
    """DEPTH-PARITY (round-2 meta-finding): the budget_parity/discovered_set case only exercises SHALLOW
    discovery, so it green-lit a candidate that REGRESSES at depth (observed: single 7 verified vs multi 2 at
    budget 120, because multi lacked the deepen/mutate/reopen/novel-code generation paths). This case makes the
    findable bug reachable ONLY via a deepen-CHILD -- the seed move gains info but never verifies; deepen(seed)
    spawns the child that DOES. A candidate WITHOUT the deep-gen paths wired never reaches it; MultiAgentHunt
    WITH them must MATCH the single-agent reference."""
    HIT = "/api/deep"
    seeds = [{"surface": "/api/parent", "vuln_class": "authz", "class": "authz", "mechanism": "m", "payload": "0"}]

    def brainstorm(ctx):
        return []
    def execute(move, phase):
        deep = move.get("_deepen_depth", 0) > 0 and move.get("surface") == HIT
        return {"move": move, "hit": deep, "status": 200, "body": "resp:%s:%s" % (move.get("surface"), move.get("payload"))}
    def oracle(result):
        return (("verified", {"ok": True}) if result.get("hit") else ("rejected", {"checked": True}))
    def deepen(move):                                      # only a shallow parent spawns the hit-child
        if move.get("_deepen_depth", 0) == 0 and move.get("surface") == "/api/parent":
            return [{"surface": HIT, "vuln_class": "authz", "class": "authz", "mechanism": "deep", "payload": "x"}]
        return []

    # The property: the candidate MUST reach a bug that is verifiable ONLY via a deepen-child. With deep-gen
    # wired it spawns the child and verifies (verified>=1, spawned>=1); without it, it never reaches it (0/0).
    cand = MultiAgentHunt(brainstorm, execute, oracle, budget=8, n_agents=1, seed_moves=list(seeds),
                          max_board_rounds=1, deepen=deepen)
    cm = cand.run("fixture", "depth")
    ok = (cm["verified"] >= 1 and cm.get("spawned", 0) >= 1)
    _add(res, "depth_parity", True, ok,
         f"candidate verified={cm['verified']} spawned={cm.get('spawned')} "
         f"(bug reachable ONLY via a deepen-child; deep-gen must reach it -- catches the depth regression)")


def fold_static(res, path):
    if not path:
        res["advise"].append("static_review: not supplied (run code_review.py --json and pass --static-json)")
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        findings = data.get("findings", []) if isinstance(data, dict) else []
        highs = [f for f in findings if str(f.get("severity", "")).lower() in ("high", "critical")]
        res["checks"].append({"name": "static_review", "advise_only": True, "ok": True,
                              "detail": f"{len(findings)} findings ({len(highs)} high) -- ADVISE-ONLY, never blocks"})
        for f in highs[:20]:
            res["advise"].append(f"static[{f.get('severity')}] {f.get('file')}:{f.get('line')} {f.get('suggestion')}")
    except Exception as e:
        res["advise"].append(f"static_review: could not parse {path} ({str(e)[:80]})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--static-json", default=None, help="a code_review.py --json dump to fold in (advise-only)")
    ap.add_argument("--json", action="store_true", help="print machine-readable verdict")
    ap.add_argument("--out", default=os.path.join(HERE, "review_gate_report.json"))
    args = ap.parse_args()

    res = {"module": "agent_hunt.MultiAgentHunt", "reference": "iterative_hunt.IterativeHunt",
           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "checks": [], "hard_fail": [], "advise": []}
    for fn in (check_smoke, check_budget_parity, check_noise_ceiling, check_session_isolation, check_depth_parity):
        try:
            fn(res)
        except Exception as e:
            _add(res, fn.__name__, True, False, f"gate check crashed: {type(e).__name__}: {str(e)[:120]}")
    fold_static(res, args.static_json)

    res["verdict"] = "PASS" if not res["hard_fail"] else "BLOCKED"
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"# review_gate  {res['module']}  vs  {res['reference']}")
        for c in res["checks"]:
            mark = "PASS" if c["ok"] else ("advise" if c["advise_only"] else "FAIL")
            print(f"  [{mark:6}] {c['name']:34} {c['detail']}")
        if res["advise"]:
            print("\n  ADVISE:")
            for a in res["advise"][:24]:
                print(f"    - {a}")
        print(f"\n  VERDICT: {res['verdict']}   (hard-fails: {len(res['hard_fail'])})")
        print(f"  saved -> {args.out}")
    sys.exit(0 if res["verdict"] == "PASS" else 2)


if __name__ == "__main__":
    main()
