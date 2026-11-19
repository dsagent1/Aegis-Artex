#!/usr/bin/env python3
"""agent_hunt.py -- MULTI-AGENT novel-discovery loop (pull-based central scheduler + parallel workers).

Board-consulted design (BOARD_AGENT_INTEGRATION.md / BOARD_DIRECTION_QUESTION.md): the current
single-agent IterativeHunt has TWO parts -- (1) DEDUP (hypothesis fingerprint + seen_surfaces/
seen_classes + budget) and (2) DIRECTION (breadth-first + hard per-angle cap + novelty-ordered pick).
The board proved N INDEPENDENT pickers keep dedup (via claims) but BREAK direction, so the correct
design is PULL-BASED: ONE central novelty brain owns seen_*/angle-counts/novelty-ordering/budget and
ASSIGNS the next fingerprint; the N agents are pure claim+execute+report workers.

This does NOT fork the novelty mechanism. MultiAgentHunt HOLDS an internal IterativeHunt as the novelty
brain and DELEGATES the decisions to it -- _context (so the real board brainstorm gets a proper, rich
context), _novelty, _angle_cap -- plus the module-level fingerprint (_hypo_identity/_sig) and angle_of.
The single-writer scheduler (main thread) runs _pick/_integrate against ONE shared HuntState; execute+
oracle fan out to a thread pool (that is where parallelism -- the speed -- comes from). Only the LLM
brainstorm calls cost money; execute/oracle are owned compute.

Same callable contract as IterativeHunt:
    brainstorm(context) -> [move, ...]      # candidate proposals (real: board fan-out; the $ cost)
    execute(move, phase) -> result          # run against the target (owned compute; parallelised)
    oracle(result) -> (verdict, receipt)    # deterministic ground truth "verified"/"rejected"
"""
from __future__ import annotations
import os, sys, time
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from iterative_hunt import IterativeHunt, _hypo_identity, _sig, angle_of, HuntState  # type: ignore


def _surface(m): return _hypo_identity(m)[1]
def _vclass(m):  return _hypo_identity(m)[2]


class MultiAgentHunt:
    def __init__(self, brainstorm, execute, oracle, *, budget=40, n_agents=4,
                 max_board_rounds=15, seed_moves=None, per_agent_brainstorm=False,
                 phase="probe", **ih_kw):
        self.brainstorm, self.execute, self.oracle = brainstorm, execute, oracle
        self.budget = budget
        self.n_agents = max(1, n_agents)
        self.max_board_rounds = max_board_rounds
        self.seed_moves = list(seed_moves or [])
        self.per_agent_brainstorm = per_agent_brainstorm   # False = central generation (cost-optimal default)
        self.phase = phase
        # the internal IterativeHunt is the NOVELTY BRAIN -- we drive its decision helpers, never its run().
        self._ih = IterativeHunt(brainstorm, execute, oracle, budget=budget,
                                 max_board_rounds=max_board_rounds, seed_moves=seed_moves, **ih_kw)
        self.st = HuntState(budget=budget)                 # ONE shared novelty state (single-writer: scheduler)
        self.claimed: set = set()
        self.candidates: list = []
        self.audit: list = []
        self.proposals = self.executed = self.verified = self.rejected = self.board_rounds = 0
        self.noise = 0                                     # non-information-gaining executions (bounded separately)
        self.noise_ceiling = budget                        # like iterative_hunt max_noise: noise can't pad the budget
        self.spawned = 0                                    # deep-gen follow-ups enqueued (mutate/deepen/reopen/code)
        self.wall = 0.0

    # ---- delegate the novelty decisions to the internal IterativeHunt (single source of truth) ----
    def _ctx(self, target, objective):
        try:
            return self._ih._context(self.st, target, objective)
        except Exception:
            return {"target": target, "objective": objective, "phase": getattr(self.st, "phase", "exploit"),
                    "budget_remaining": self.st.budget, "confirmed": self.st.confirmed,
                    "coverage": {"angle_counts": dict(self.st.angle_counts), "angle_cap": self._angle_cap()}}

    def _novelty(self, m):
        try:
            return self._ih._novelty(m, self.st)
        except Exception:
            return ((angle_of(m) not in self.st.angle_counts)
                    + (_surface(m) not in self.st.seen_surfaces)
                    + (_vclass(m) not in self.st.seen_classes))

    def _angle_cap(self):
        try:
            return self._ih._angle_cap()
        except Exception:
            return max(2, int(round(0.35 * self.budget)))

    def _capped(self):
        cap = self._angle_cap()
        return {a for a, n in self.st.angle_counts.items() if n >= cap}

    # ---- selection: ONE serialization point -> preserves breadth/cap/novelty-order globally ----
    def _pick(self, inflight_angles=None):
        capped = self._capped()
        kept = []
        for m in self.candidates:
            s = _sig(m)
            if s in self.claimed or s in self.st.tried:
                continue                                   # DEDUP (claim / already tried)
            if angle_of(m) in capped:
                continue                                   # per-angle HARD CAP
            kept.append(m)
        self.candidates = kept
        if not kept:
            return None
        # PRIORITY SPLIT (opt-in): when a priority profile is active, a worker AVOIDS an angle another
        # worker is running RIGHT NOW, so the N concurrent agents spread across distinct directions instead
        # of all piling onto the converged class. Inert (identical ordering) when AEGIS_PRIORITY is unset.
        infl = inflight_angles or set()
        split = False
        if infl:
            try:
                import t0_bandit as _tb
                split = _tb.priority_active()
            except Exception:
                split = False
        if split:
            kept.sort(key=lambda m: (angle_of(m) in infl, -self._novelty(m),
                                     self.st.angle_counts.get(angle_of(m), 0)))
        else:
            kept.sort(key=lambda m: (-self._novelty(m), self.st.angle_counts.get(angle_of(m), 0)))
        move = kept[0]
        self.candidates.remove(move)
        return move

    # ---- single-writer state update after a worker returns (mirrors IterativeHunt's post-attempt update) ----
    def _integrate(self, move, result, verdict, receipt):
        # DEDUP is unconditional: never re-run this exact hypothesis, even if it turned out to be noise.
        self.st.tried.add(_sig(move))
        self.claimed.discard(_sig(move))
        # INFORMATION-GAIN BUDGET (mirrors iterative_hunt._info_gain): only real work spends budget + advances
        # coverage; noise (transport error, guard-block, unreachable/no-oracle receipt, repeat signature) is
        # bounded separately by noise_ceiling and can NEVER pad the real-attempt budget. Reuse the engine's own
        # classifier so the parallel budget means exactly what the single-agent budget means.
        try:
            gain = self._ih._info_gain(move, verdict, receipt, result, self.st)
        except Exception:
            gain = 0 if verdict == "error" else 1
        self.st.attempts.append({"move": move, "verdict": verdict, "gain": gain, "delta": 0})
        if not gain:
            self.noise += 1
            self.st.noise += 1
            return
        a = angle_of(move)
        self.st.angle_counts[a] = self.st.angle_counts.get(a, 0) + 1
        self.st.seen_surfaces.add(_surface(move))
        self.st.seen_classes.add(_vclass(move))
        self.st.real_attempts += 1
        self.st.budget = max(0, self.st.budget - 1)
        self.executed += 1                                 # executed == REAL (information-gaining) attempts
        if verdict == "verified":
            self.verified += 1
            self.st.confirmed.append({"move": move, "verdict": verdict})
        else:
            self.rejected += 1
        self._deepgen(move, gain, verdict)                 # DEEP-GEN: spawn mutate/deepen follow-ups

    # ---- DEEP-GEN: the generation paths IterativeHunt.run() has that a bare parallel scheduler lacks. Without
    # these, MultiAgentHunt saturates shallow (board brainstorm only) and REGRESSES vs single-agent at depth
    # (observed: single 7 verified / multi 2 at budget 120). All delegate to the internal IterativeHunt and are
    # defensively wrapped -- a generation failure must never break the scheduler. ----
    def _deepgen(self, move, gain, verdict):
        ih = self._ih
        try:                                               # MODE-2 mutate: a real refutation -> one structural variant
            if verdict != "verified" and getattr(ih, "mutate", None) \
                    and move.get("_mut_depth", 0) < getattr(ih, "max_mutations", 2):
                m = ih.mutate(move)
                if m and _sig(m) not in self.st.tried and _sig(m) not in self.claimed:
                    self.candidates.append(dict(m, _mut_depth=move.get("_mut_depth", 0) + 1)); self.spawned += 1
        except Exception:
            pass
        try:                                               # MECH-1 deepen: info-gaining clean leg -> deeper families
            if gain > 0 and getattr(ih, "deepen", None) \
                    and move.get("_deepen_depth", 0) < getattr(ih, "max_deepen", 1):
                for k in (ih.deepen(move) or []):
                    if _sig(k) not in self.st.tried and _sig(k) not in self.claimed:
                        self.candidates.append(dict(k, _deepen_depth=move.get("_deepen_depth", 0) + 1)); self.spawned += 1
        except Exception:
            pass

    def _write_code(self, move, target, objective):
        # NOVEL-CODE: if the board asked for a probe to be WRITTEN (needs_code / new_code-without-code), let the
        # code_writer write it now, bounded per direction (mirrors IterativeHunt line 950). Offline-safe.
        try:
            ih = self._ih
            if getattr(ih, "code_writer", None) and (move.get("needs_code")
                                                     or (move.get("new_code") and not move.get("code"))):
                _dir = None
                try:
                    import reach as _r
                    _dir = _r.direction_of(move) if hasattr(_r, "direction_of") else None
                except Exception:
                    _dir = None
                return ih._maybe_write_code(move, self.st, _dir or "server", target, objective)
        except Exception:
            pass
        return move

    def _reopen(self, target, objective):
        # RE-OPEN on stall: pull the next candidate plan's moves (mirrors IterativeHunt._try_reopen).
        try:
            if self._ih._try_reopen(self.st, target, objective, "multi-agent-stall"):
                if getattr(self.st, "queue", None):
                    self.candidates.extend(self.st.queue); self.spawned += len(self.st.queue); self.st.queue = []
                return True
        except Exception:
            pass
        return False

    def _refill(self, ctx):
        if self.board_rounds >= self.max_board_rounds:
            return
        rounds = self.n_agents if self.per_agent_brainstorm else 1
        for _ in range(rounds):
            if self.board_rounds >= self.max_board_rounds:
                break
            try:
                batch = self.brainstorm(ctx) or []         # LLM/network call -- one failure must not kill the hunt
            except Exception as e:
                batch = []
                self.audit.append(("BRAINSTORM_ERR", "", "", str(e)[:80]))
            self.candidates.extend(batch)
            self.proposals += len(batch)
            self.board_rounds += 1
            self.st.board_rounds_total += 1

    def _agent_run(self, move):                            # runs in a worker thread (parallel)
        result = self.execute(move, self.phase)
        verdict, receipt = self.oracle(result)
        return move, result, verdict, receipt

    def run(self, target=None, objective=None, *, time_budget=None):
        t0 = time.time()
        self.candidates.extend(self.seed_moves)
        with ThreadPoolExecutor(max_workers=self.n_agents) as pool:
            inflight = {}
            stalls = 0
            while True:
                if self.executed >= self.budget:
                    break
                if self.noise >= self.noise_ceiling:       # noise ceiling -- a dead/noisy target can't spin forever
                    break
                if time_budget is not None and (time.time() - t0) >= time_budget:
                    break
                avail = [m for m in self.candidates
                         if _sig(m) not in self.claimed and _sig(m) not in self.st.tried]
                if len(avail) < self.n_agents:
                    self._refill(self._ctx(target, objective))
                budget_left = self.budget - self.executed - len(inflight)
                while len(inflight) < self.n_agents and budget_left > 0:
                    move = self._pick({angle_of(m) for m in inflight.values()})
                    if move is None:
                        break
                    move = self._write_code(move, target, objective)   # DEEP-GEN: write novel-code probe if asked
                    self.claimed.add(_sig(move))
                    self.audit.append(("CLAIM", _sig(move), f"a{len(inflight)}", None))
                    inflight[pool.submit(self._agent_run, move)] = move
                    budget_left -= 1
                if not inflight:
                    if self.board_rounds >= self.max_board_rounds and not self.candidates:
                        if self._reopen(target, objective):   # DEEP-GEN: pull the next scenario before quitting
                            continue
                        break
                    self._refill(self._ctx(target, objective))
                    stalls += 1
                    if stalls > self.max_board_rounds + 2:
                        break
                    continue
                stalls = 0
                done, _ = wait(list(inflight), timeout=90, return_when=FIRST_COMPLETED)
                if not done:
                    break
                for fut in done:
                    move = inflight.pop(fut)
                    try:
                        _m, result, verdict, receipt = fut.result()
                    except Exception as e:
                        result, verdict, receipt = {}, "error", {"error": str(e)[:120]}
                    try:
                        self._integrate(move, result, verdict, receipt)
                    except Exception as e:
                        self.claimed.discard(_sig(move))
                        self.audit.append(("INTEGRATE_ERR", "", "", str(e)[:80]))
                    self.audit.append(("RESULT", _sig(move), "a", verdict))
        self.wall = time.time() - t0
        return self.metrics()

    def metrics(self) -> dict:
        return {
            "mode": f"multi-agent(n={self.n_agents}{',per-agent-brainstorm' if self.per_agent_brainstorm else ''})",
            "wall_s": round(self.wall, 3), "proposals": self.proposals, "executed": self.executed,
            "verified": self.verified, "rejected": self.rejected, "noise": self.noise,
            "spawned": self.spawned, "board_rounds": self.board_rounds,
            "distinct_surfaces": len(self.st.seen_surfaces), "distinct_classes": len(self.st.seen_classes),
            "audit_lines": len(self.audit),
        }
