#!/usr/bin/env python3
"""agent_hunt_bench.py -- benchmark MULTI-AGENT (agent_hunt.MultiAgentHunt) vs the current SINGLE-agent
mechanism, on a deterministic synthetic workload, isolating parallelism from LLM/network variance.

Synthetic 'target': a fixed set of findable bugs (distinct (angle,surface,class) fingerprints) hidden
among decoys. `brainstorm` proposes candidate moves (simulated LLM latency); `execute` runs a probe
(simulated I/O latency); `oracle` verifies iff the move's fingerprint matches a findable bug. Same
callables feed every configuration, so the ONLY variable is agent count / brainstorm mode.

The single-agent baseline is MultiAgentHunt(n_agents=1): identical novelty brain + code path, truly
sequential -- the fair apples-to-apples control. We ALSO run the real operator.iterative_hunt.
IterativeHunt with the same callables as a cross-check that n=1 reproduces the current mechanism.

Usage:
    python agent_hunt_bench.py                    # default: budget=40, latencies modelled, n in {1,4,8}
    AGENT_BENCH_EXEC_MS=300 AGENT_BENCH_BOARD_MS=500 python agent_hunt_bench.py
"""
from __future__ import annotations
import os, sys, time, random, json, itertools

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from agent_hunt import MultiAgentHunt  # type: ignore

EXEC_MS = int(os.environ.get("AGENT_BENCH_EXEC_MS", "300"))    # simulated per-probe I/O latency
BOARD_MS = int(os.environ.get("AGENT_BENCH_BOARD_MS", "500"))  # simulated per-brainstorm LLM latency
BUDGET = int(os.environ.get("AGENT_BENCH_BUDGET", "40"))
SEED = int(os.environ.get("AGENT_BENCH_SEED", "1234"))

# --- synthetic target: 8 surfaces x classes; 6 (surface,class) combos are findable bugs -------------
SURFACES = [f"/api/s{i}" for i in range(8)]
CLASSES = ["injection", "xss", "authz", "idor", "ssrf", "auth", "mass_assignment", "race"]
MECHANISMS = ["boolean-diff", "reflection", "cross-user", "callback", "bypass", "over-post"]
_rng = random.Random(SEED)
FINDABLE = set(_rng.sample([(s, c) for s in SURFACES for c in CLASSES], 6))  # the 6 hidden bugs


def make_synth():
    """Fresh, independent synthetic callables (own RNG) so every run sees the same target + proposals."""
    rng = random.Random(SEED)
    found_lock = []  # closure state

    def _move(s, c):
        return {"surface": s, "vuln_class": c, "class": c,
                "mechanism": rng.choice(MECHANISMS), "method": "POST",
                "payload": "v%d" % rng.randint(0, 9999)}  # payload varies but is EXCLUDED from the fingerprint

    def brainstorm(context):
        time.sleep(BOARD_MS / 1000.0)                      # model the board fan-out cost/latency
        batch = []
        for _ in range(8):                                 # ~8 proposals per round (matches observed ~70/40)
            s = rng.choice(SURFACES); c = rng.choice(CLASSES)
            batch.append(_move(s, c))
        # occasionally propose a payload-only dup of a findable bug (should be deduped by fingerprint)
        if FINDABLE:
            s, c = rng.choice(sorted(FINDABLE)); batch.append(_move(s, c))
        return batch

    def execute(move, phase):
        # jitter the probe latency so parallel speedup is realistic (not a fixed constant)
        time.sleep((EXEC_MS + rng.randint(-60, 60)) / 1000.0)
        key = (move.get("surface"), move.get("vuln_class"))
        # realistic result shape (status + UNIQUE body) so the info-gain classifier scores real work, not noise
        return {"move": move, "hit": key in FINDABLE, "status": 200,
                "body": "resp:%s:%s:%s" % (move.get("surface"), move.get("vuln_class"), move.get("payload"))}

    def oracle(result):
        # a REJECTED oracle still returns a receipt (it evaluated the hypothesis) -- an empty receipt would
        # read as no-evidence noise under _info_gain, which would (wrongly) not spend budget on real refutations
        return (("verified", {"synthetic": True}) if result.get("hit")
                else ("rejected", {"synthetic": True, "checked": True}))

    return brainstorm, execute, oracle


def run_cfg(n_agents, per_agent_brainstorm=False, time_budget=None):
    bs, ex, orc = make_synth()
    h = MultiAgentHunt(bs, ex, orc, budget=BUDGET, n_agents=n_agents,
                       per_agent_brainstorm=per_agent_brainstorm, max_board_rounds=15)
    return h.run(target="synthetic", objective="find the 6 hidden bugs", time_budget=time_budget)


def crosscheck_iterativehunt():
    """Run the REAL IterativeHunt with the same synthetic callables (cross-check n=1 fidelity)."""
    try:
        from iterative_hunt import IterativeHunt  # type: ignore
        bs, ex, orc = make_synth()
        ih = IterativeHunt(bs, ex, orc, budget=BUDGET, max_board_rounds=15)
        t0 = time.time()
        res = ih.run("synthetic", "find the 6 hidden bugs")
        wall = time.time() - t0
        # IterativeHunt's result shape varies; harvest what we can
        verified = res.get("verified") if isinstance(res, dict) else None
        return {"mode": "IterativeHunt(current, sequential)", "wall_s": round(wall, 3),
                "verified": verified, "raw_keys": list(res.keys()) if isinstance(res, dict) else str(type(res))}
    except Exception as e:
        return {"mode": "IterativeHunt(current)", "error": str(e)[:200]}


def main():
    print(f"# agent_hunt benchmark  (findable bugs=6, budget={BUDGET}, exec~{EXEC_MS}ms, board~{BOARD_MS}ms, seed={SEED})\n")

    print("## A) BUDGET-BOXED (same budget of executed hypotheses) -- measures SPEED + successes-in-budget")
    rows = []
    for n in (1, 4, 8):
        m = run_cfg(n)
        rows.append(m)
        print(f"  n={n:<2} wall={m['wall_s']:>6}s  proposals={m['proposals']:>3}  executed={m['executed']:>3}  "
              f"verified={m['verified']}/6  surfaces={m['distinct_surfaces']}  classes={m['distinct_classes']}")
    base = rows[0]["wall_s"] or 1e-9
    for m in rows:
        m["speedup_vs_n1"] = round(base / (m["wall_s"] or 1e-9), 2)
    print("  speedup vs n=1:", {f"n={r['mode']}": r["speedup_vs_n1"] for r in rows})

    print("\n## B) per-agent brainstorm variant (n=4) -- the cost/diversity trade (more proposals, N-x board $)")
    m = run_cfg(4, per_agent_brainstorm=True)
    print(f"  n=4 per-agent  wall={m['wall_s']}s  proposals={m['proposals']}  executed={m['executed']}  "
          f"verified={m['verified']}/6  board_rounds={m['board_rounds']}")

    print("\n## C) TIME-BOXED (fixed wall-clock) -- measures MORE-successes-per-unit-time")
    tb = round(rows[0]["wall_s"] * 0.5, 2) or 5.0   # half the sequential run's time
    print(f"  time_budget={tb}s")
    for n in (1, 4, 8):
        m = run_cfg(n, time_budget=tb)
        print(f"  n={n:<2} executed={m['executed']:>3}  verified={m['verified']}/6  proposals={m['proposals']}")

    print("\n## D) cross-check: real IterativeHunt with the same synthetic callables")
    print("  ", crosscheck_iterativehunt())


if __name__ == "__main__":
    main()
