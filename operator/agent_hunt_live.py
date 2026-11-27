#!/usr/bin/env python3
"""agent_hunt_live.py -- drive the MULTI-AGENT novel-discovery loop (agent_hunt.MultiAgentHunt) against a
LIVE mirror, reusing the operator path's real brainstorm/execute/oracle wiring (iterative_hunt_live.run_hunt).

This is the novel-discovery STAGE (pipeline stage 7) run through the parallel scheduler instead of the
single-agent loop. It reuses -- unchanged -- the real callables:
  brainstorm = tiered_brainstorm (board fan-out; the $ cost)         [iterative_hunt]
  execute    = make_execute(base, session_for_role, stack)           [iterative_hunt_live]  (network probes: PARALLEL)
  oracle     = make_oracle(store, session_for_role, authz..., base)  [iterative_hunt_live]  (DB-witnessed ledger)
and the same Planner seeds + session_factory auth.

CONCURRENCY / TRUST: execute (network probes on distinct surfaces) fans out to n_agents worker threads,
BUT the oracle writes to a shared hash-chained FindingStore JSONL and does DB before/after witnessing --
so the oracle critical section is serialized under one lock (single-writer, exactly as the board design
mandates for the novelty state). Parallelism buys concurrent probing + concurrent brainstorm; the ledger
stays consistent and every finding is still oracle-verified. No heavy ZAP leg is involved.

Usage (defaults = the max-discovery config the owner identified as "best so far"):
    python agent_hunt_live.py --objective "reach as deep as you can" --role owner \
        --budget 24 --agents 4 --per-agent-brainstorm --max-board-rounds 20
"""
from __future__ import annotations
import os, sys, time, json, argparse, threading, re

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "shared"))

from iterative_hunt import tiered_brainstorm                     # real board brainstorm
import iterative_hunt_live as IHL                                # make_execute / make_oracle / BASE
from verified_findings import FindingStore                       # hash-chained ledger
from agent_hunt import MultiAgentHunt                            # the parallel mechanism under test


def build_live(objective, role, budget, base, store_path, max_seeds=None, max_angle_share=None):
    """Reproduce iterative_hunt_live.run_hunt's real setup and return (brainstorm, execute, safe_oracle,
    seeds, ih_kw, store) ready to drive MultiAgentHunt. Every step is offline-safe (falls back like run_hunt).

    max_seeds: keep only the top-ranked N Planner seeds (surface-anchored, most-valuable first) so the rest
    of the budget is RESERVED for board novel-discovery. Without this, many seeds saturate the budget and the
    board brainstorm never fires (board_rounds=0) -- so per_agent_brainstorm has no effect."""
    store = FindingStore(store_path)

    # AUTONOMOUS reachability (same self-driving as run_hunt, so the MULTI-AGENT path reaches the real target
    # with NO manual env): (1) proxy_guard routes egress through the VPN'd WSL proxy if the owner opted in;
    # (2) origin_resolver detects a WAF'd front door, finds the leaked origin, confirms the real app via
    # Host:, sets AEGIS_HOST_HEADER and rebinds `base` to the origin. Fail-open.
    try:
        import proxy_guard
        proxy_guard.ensure(base)
    except Exception:
        pass
    try:
        import origin_resolver
        _ores = origin_resolver.resolve(base)
        if _ores.get("origin_ip"):
            print(f"[origin] {_ores['reason']}", flush=True)
            base = _ores["base"]
    except Exception:
        pass

    # AUTH + PER-LEG-AWARE SESSION MODEL (F2 fix). Two observed failure modes, neither fixable by a flat default:
    #   (a) per-worker THREAD-LOCAL isolation silently DROPS the sql_raw auth-bypass leg -- that leg builds its
    #       own sub-sessions and errors "'NoneType' object is not callable" under the wrapper -> a false NEGATIVE
    #       (misses a HIGH); and
    #   (b) a single SHARED session under parallel workers lets a sibling's re-auth undo another worker's logout
    #       -> the session_not_invalidated false POSITIVE.
    # Fix = ONE SHARED/direct factory (matches run_hunt -- correct for EVERY leg incl. sql_raw) + SERIALIZE the
    # session-state-mutating legs under a lock (see _exec wrapper below) so no two mutate session state at once.
    # Read-only legs stay parallel (that is the speed). AEGIS_AH_THREADLOCAL_SESSION=1 restores per-worker
    # isolation for experiments only.
    _have_session = False
    try:
        import session_factory as _sf
        _sf.from_env(base)                                 # probe: confirm it constructs (offline-safe)
        _have_session = True
    except Exception as e:
        print(f"[live] session_factory unavailable ({str(e)[:80]}) -> unauthenticated", flush=True)
    if _have_session and os.environ.get("AEGIS_AH_THREADLOCAL_SESSION") == "1":
        _tls = threading.local()
        def session_for_role(role_):                       # opt-in per-worker isolation (breaks sql_raw; tests only)
            f = getattr(_tls, "factory", None)
            if f is None:
                import session_factory as _sf2
                f = _sf2.from_env(base); _tls.factory = f
            return f(role_)
    elif _have_session:
        import session_factory as _sfshared
        session_for_role = _sfshared.from_env(base)        # DEFAULT: one shared/direct factory (like run_hunt)
    else:
        session_for_role = None
    authz_baseline_role = role if _have_session else None

    # THE PLANNER: fingerprint -> rank DB/ATT&CK combos -> board-devised NOVEL approaches -> seed_moves.
    sess = None
    try:
        from planner import plan_session
        sess = plan_session(objective, base, roles=[role], mode="operator", base=base)
    except Exception as e:
        print(f"[live] planner unavailable ({str(e)[:80]}) -> no seeds", flush=True)
    seeds = sess.initial_seeds() if sess else []
    seeds = [dict(m, role=m.get("role", role)) for m in seeds]
    if max_seeds is not None and len(seeds) > max_seeds:
        print(f"[live] capping seeds {len(seeds)} -> {max_seeds} (reserving budget for board novel discovery)",
              flush=True)
        seeds = seeds[:max_seeds]

    _stack = []
    try:
        if sess and sess.plans:
            _stack = (sess.plans[0].get("fingerprint") or {}).get("stack") or []
    except Exception:
        _stack = []

    _exec = IHL.make_execute(base, session_for_role=session_for_role, stack=_stack)
    # F2: serialize SESSION-STATE-MUTATING legs (auth / login / logout / session / injection auth-bypass) so
    # parallel workers can't race on the shared session (fixes the session-invalidation FP); read-only legs
    # stay parallel. sql_raw/inject build injected-login sub-sessions -> treated as session-mutating too.
    _SESSION_MUTATING = re.compile(r"logout|login|session|fixation|invalidat|auth[-_ ]?bypass|sql[_-]?raw|inject",
                                   re.I)
    _sess_lock = threading.Lock()
    _raw_exec = _exec
    def _exec(move, phase):                                # noqa: F811 -- guarded wrapper over make_execute
        blob = " ".join(str(move.get(k, "")) for k in ("action", "technique", "vuln_class", "class", "surface", "path"))
        if _SESSION_MUTATING.search(blob):
            with _sess_lock:
                return _raw_exec(move, phase)
        return _raw_exec(move, phase)
    _oracle = IHL.make_oracle(store, session_for_role=session_for_role,
                              authz_baseline_role=authz_baseline_role, base=base)

    # single-writer oracle: serialize the shared ledger + DB before/after witness while execute stays parallel.
    _lock = threading.Lock()
    def safe_oracle(result):
        with _lock:
            return _oracle(result)

    # reopen / intel / code_writer / deepen / mutate -- same extras run_hunt gives IterativeHunt.
    reopen = (lambda ctx, why: sess.reopen(ctx, why)) if sess else None
    intel = (sess.intel if sess else None)
    code_writer = None
    if os.environ.get("AEGIS_NOVEL_CODE", "1") != "0":
        try:
            from novel_code import make_code_writer
            code_writer = make_code_writer()
        except Exception:
            code_writer = None
    _deepen = _mutate = None
    try:
        from hunt_strategies import deepen_on_clean as _doc, mutate as _mutate
        _deepen = lambda mv: _doc(mv)
    except Exception:
        _deepen = _mutate = None

    # role-seed every board-proposed move (as run_hunt does).
    def brainstorm(ctx):
        return [dict(m, role=m.get("role", role)) for m in (tiered_brainstorm(ctx) or [])]

    ih_kw = dict(reopen=reopen, intel=intel, code_writer=code_writer, deepen=_deepen, mutate=_mutate)
    if max_angle_share is not None:
        ih_kw["max_angle_share"] = max_angle_share          # breadth knob -> internal IterativeHunt._angle_cap
    return brainstorm, _exec, safe_oracle, seeds, ih_kw, store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--objective", default="reach as deep as you can across every surface and role")
    ap.add_argument("--role", default="owner")
    ap.add_argument("--budget", type=int, default=24)
    ap.add_argument("--agents", type=int, default=4)
    ap.add_argument("--per-agent-brainstorm", action="store_true")
    ap.add_argument("--max-board-rounds", type=int, default=20)
    ap.add_argument("--max-seeds", type=int, default=None,
                    help="keep only top-N planner seeds so budget is reserved for board novel discovery")
    ap.add_argument("--max-angle-share", type=float, default=None,
                    help="cap any single angle to this fraction of budget (breadth knob; engine default 0.35)")
    ap.add_argument("--base", default=IHL.BASE)
    ap.add_argument("--store", default=os.path.join(HERE, "agent_hunt_findings.jsonl"))
    args = ap.parse_args()

    print(f"# agent_hunt_live  target={args.base}  role={args.role}  budget={args.budget}  "
          f"agents={args.agents}  per_agent_brainstorm={args.per_agent_brainstorm}  "
          f"max_board_rounds={args.max_board_rounds}", flush=True)
    print(f"# objective: {args.objective}\n", flush=True)

    brainstorm, execute, oracle, seeds, ih_kw, store = build_live(
        args.objective, args.role, args.budget, args.base, args.store,
        max_seeds=args.max_seeds, max_angle_share=args.max_angle_share)
    print(f"[live] planner seeds={len(seeds)}  ledger={args.store}", flush=True)

    hunt = MultiAgentHunt(brainstorm, execute, oracle,
                          budget=args.budget, n_agents=args.agents,
                          per_agent_brainstorm=args.per_agent_brainstorm,
                          max_board_rounds=args.max_board_rounds,
                          seed_moves=seeds, **ih_kw)

    t0 = time.time()
    metrics = hunt.run(args.base, args.objective)
    metrics["wall_s"] = round(time.time() - t0, 2)

    # verified findings from the shared ledger (ground truth, not the scheduler's tally).
    verified = []
    try:
        verified = store.verified()
    except Exception as e:
        print(f"[live] store.verified() failed: {str(e)[:100]}", flush=True)

    print("\n===== MULTI-AGENT LIVE RESULT =====", flush=True)
    print(json.dumps(metrics, indent=2), flush=True)
    print(f"\nverified findings (ledger): {len(verified)}", flush=True)
    for f in verified:
        summ = f.get("summary") or f.get("claim_type") or "?"
        sev = f.get("severity", "?")
        print(f"  [{sev.upper():8}] {f.get('claim_type','?'):24} {str(summ)[:90]}", flush=True)

    # audit sample (CLAIM/RESULT trail proving the single-winner claim + parallel dispatch).
    print(f"\naudit lines: {len(hunt.audit)}  (sample)", flush=True)
    for line in hunt.audit[:8]:
        print("  ", line, flush=True)

    out = os.path.join(HERE, "agent_hunt_live_result.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"metrics": metrics, "verified": verified, "audit": hunt.audit[:200]}, fh, indent=2, default=str)
    print(f"\nsaved -> {out}", flush=True)


if __name__ == "__main__":
    main()
