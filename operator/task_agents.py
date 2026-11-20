#!/usr/bin/env python3
"""Hierarchical task-specific agents (HPTSA-inspired) -- a DEPTH layer over the breadth-first loop.

HPTSA (Fang et al. 2024) found that a *hierarchical* structure -- a planning agent that dispatches
*task-specific* expert subagents, one specialized per vulnerability class -- out-performs a single flat
agent on real web vulns. The gain is from SPECIALIZATION + SEPARATING PLANNING FROM EXPLOITATION, not
from any new exploit primitive. This module adopts exactly that STRUCTURE on top of Aegis's existing,
oracle-verified machinery -- it adds no attack capability:

  PLANNER  -> pick the vuln CLASSES worth pursuing on THIS target (relevance-gated by the environment
              survey -- the same filter the Planner's fusion uses, so no off-target class is ever spawned).
  MANAGER  -> allocate a DEPTH sub-budget per class by priority, run each class SPECIALIST, then MERGE +
              DEDUP their oracle-verified findings into the shared FindingStore.
  SPECIALIST -> the SAME iterative-hunt loop (same vectors, same ground-truth oracles, same store),
              CONSTRAINED to one class so it goes DEEP (chaining / in-class variants) instead of the
              global loop's deliberate breadth (novelty-over-convergence). Shares execute+oracle+store.

Why this complements what we already have:
  * the multi-MODEL board gives brain *diversity*; this gives task *specialization* (orthogonal).
  * the classical planner (redteam/planning.py) picks the goal PATH; this parallelizes the per-class HUNT.
  * the flat loop is breadth-first by design; this is the opt-in DEPTH counterpart.

Opt-in. Dependency-light. Testable with stub brainstorm/execute/oracle (see shared/_task_agents_tests.py).
Env: AEGIS_TASK_AGENTS=0 disables; AEGIS_TASK_PARALLEL=1 runs specialists in a bounded thread pool.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from iterative_hunt import IterativeHunt, _oracle_type, angle_of  # reuse the loop + its classifiers


# Canonical web vuln classes a specialist can own, each with the keywords that map a move/surface to it
# and a rough priority weight (higher = gets more of the depth budget when relevant). Extend freely.
CLASS_KEYWORDS = {
    "sqli":        (("sqli", "sql", "postgres", "mysql", "mariadb", "mssql", "sqlite", "union select",
                     "boolean-blind", "filterinjection"), 5),
    "xss":         (("xss", "cross-site script", "dom-xss", "reflected", "stored-xss"), 4),
    "ssrf":        (("ssrf", "server-side request", "oob", "metadata"), 5),
    "ssti":        (("ssti", "template injection", "jinja", "freemarker"), 4),
    "authz":       (("idor", "authz", "broken-access", "role_overreach", "object-level", "bola"), 5),
    "authn":       (("auth", "login", "session", "jwt", "mfa", "credential", "brute"), 4),
    "csrf":        (("csrf", "cross-site request forgery", "samesite"), 2),
    "upload":      (("upload", "unrestricted file", "webshell"), 3),
    "redirect":    (("open redirect", "openredir"), 1),
    "secrets":     (("secret", "api key", "leak_in_response", "fieldleak", "disclosure"), 3),
    "injection":   (("command injection", "os command", "rce", "deserial"), 5),
    "misconfig":   (("misconfig", "security header", "cors", "ratelimit"), 2),
}


def classify_move(move: dict) -> str:
    """Best-effort vuln-class for a move: explicit field first, else keyword-match its technique/claim/oracle."""
    if not isinstance(move, dict):
        return ""
    explicit = str(move.get("vuln_class") or move.get("class") or "").lower().strip()
    if explicit in CLASS_KEYWORDS:
        return explicit
    hay = " ".join(str(move.get(k, "")) for k in
                   ("technique", "claim", "claim_type", "angle", "expected_oracle", "oracle", "why_novel")).lower()
    if explicit:
        hay = explicit + " " + hay
    best = ""
    for cls, (kws, _w) in CLASS_KEYWORDS.items():
        if any(kw in hay for kw in kws):
            return cls           # first keyword hit wins (ordered by how specific the class list is)
    return best


def relevant_classes(survey: dict, requested: Optional[Iterable[str]] = None) -> list:
    """PLANNER step: which classes are worth a specialist on THIS target. `survey` is the environment
    fingerprint (surfaces/stack/roles/tags). A class is kept only if the survey mentions one of its
    keywords (relevance gate) OR it was explicitly requested. Returns classes ORDERED by priority weight
    so the manager funds the highest-value lanes first. No survey -> keep all requested/known (fail-open
    to the full set, since a specialist is still oracle-gated and cannot over-claim)."""
    pool = list(requested) if requested else list(CLASS_KEYWORDS)
    hay = " ".join(str(v) for v in _flatten(survey)).lower() if survey else ""
    kept = []
    for cls in pool:
        if cls not in CLASS_KEYWORDS:
            continue
        kws, w = CLASS_KEYWORDS[cls]
        if (not hay) or (requested and cls in set(requested)) or any(kw in hay for kw in kws) or cls in hay:
            kept.append((w, cls))
    kept.sort(key=lambda t: (-t[0], t[1]))
    return [c for _w, c in kept]


def _flatten(x):
    if isinstance(x, dict):
        for v in x.values():
            yield from _flatten(v)
    elif isinstance(x, (list, tuple, set)):
        for v in x:
            yield from _flatten(v)
    else:
        yield x


def _class_weight(cls: str) -> int:
    return CLASS_KEYWORDS.get(cls, ((), 1))[1]


def allocate_budget(classes: list, total: int) -> dict:
    """MANAGER step: split a DEPTH budget across specialists in proportion to class priority, with a
    floor of 1 each so no funded lane starves. Deterministic + order-stable."""
    classes = [c for c in classes if c]
    if not classes or total <= 0:
        return {}
    weights = {c: _class_weight(c) for c in classes}
    wsum = sum(weights.values()) or 1
    alloc = {c: max(1, (total * weights[c]) // wsum) for c in classes}
    # trim/greedily-add to hit `total` exactly (highest weight adjusts first)
    order = sorted(classes, key=lambda c: (-weights[c], c))
    diff = total - sum(alloc.values())
    i = 0
    while diff != 0 and order:
        c = order[i % len(order)]
        if diff > 0:
            alloc[c] += 1; diff -= 1
        elif alloc[c] > 1:
            alloc[c] -= 1; diff += 1
        i += 1
        if i > 10000:
            break
    return alloc


def class_constrained_brainstorm(brainstorm: Callable, cls: str):
    """Wrap a brainstorm so a SPECIALIST only ever executes IN-CLASS moves. It tags the context with a
    `focus_class` (a cooperative brainstorm can target it) AND hard-FILTERS the returned moves to `cls`
    (so specialization holds even if the underlying brainstorm ignores the hint). The loop's own novelty
    dedup then spreads the specialist's depth budget across genuinely distinct in-class hypotheses."""
    def _b(context):
        ctx = dict(context or {})
        ctx["focus_class"] = cls
        ctx["focus_keywords"] = CLASS_KEYWORDS.get(cls, ((), 0))[0]
        moves = brainstorm(ctx) or []
        kept = [m for m in moves if classify_move(m) == cls]
        # if the brainstorm produced nothing in-class this round, pass its moves through UNfiltered only
        # when none matched any known class (avoid starving a specialist on an un-tagged but valid probe)
        if not kept and moves and all(not classify_move(m) for m in moves):
            for m in moves:
                m.setdefault("vuln_class", cls)
            return moves
        return kept
    return _b


@dataclass
class SpecialistResult:
    vuln_class: str
    budget: int
    verified: list = field(default_factory=list)      # finding_ids this specialist got to 'verified'
    attempts: int = 0
    summary: dict = field(default_factory=dict)


@dataclass
class TeamResult:
    classes: list
    allocation: dict
    specialists: list = field(default_factory=list)   # list[SpecialistResult]
    verified_total: int = 0
    parallel: bool = False

    def describe(self) -> str:
        head = f"hierarchical team: {len(self.specialists)} specialist(s), {self.verified_total} verified"
        lines = [head] + [f"  [{s.vuln_class}] budget={s.budget} attempts={s.attempts} "
                          f"verified={len(s.verified)}" for s in self.specialists]
        return "\n".join(lines)


class HierarchicalTeam:
    """The HPTSA planner+manager. `run_specialist` defaults to driving an IterativeHunt per class with a
    class-constrained brainstorm, sharing one execute/oracle/store; inject a stub for testing."""

    def __init__(self, brainstorm, execute, oracle, *, store=None, seed_moves=None,
                 run_specialist: Optional[Callable] = None, **hunt_kwargs):
        self.brainstorm, self.execute, self.oracle = brainstorm, execute, oracle
        self.store = store
        self.seed_moves = seed_moves or []
        self.hunt_kwargs = hunt_kwargs
        self._run_specialist = run_specialist or self._default_run_specialist

    def _default_run_specialist(self, cls: str, budget: int) -> SpecialistResult:
        before = self._verified_ids()
        seeds = [m for m in self.seed_moves if classify_move(m) == cls]
        hunt = IterativeHunt(class_constrained_brainstorm(self.brainstorm, cls),
                             self.execute, self.oracle, budget=budget, seed_moves=seeds, **self.hunt_kwargs)
        summary = {}
        try:
            summary = hunt.run() or {}
        except Exception as e:                         # a crashing specialist never sinks the whole team
            summary = {"error": str(e)[:200]}
        after = self._verified_ids()
        new = [fid for fid in after if fid not in before]
        return SpecialistResult(vuln_class=cls, budget=budget, verified=new,
                                attempts=int(summary.get("attempts", summary.get("tries", 0)) or 0),
                                summary=summary if isinstance(summary, dict) else {})

    def _verified_ids(self) -> set:
        if not self.store:
            return set()
        try:
            return {f["finding_id"] for f in self.store.verified()}
        except Exception:
            return set()

    def run(self, *, survey: dict = None, classes: Iterable[str] = None, total_budget: int = 40) -> TeamResult:
        if os.environ.get("AEGIS_TASK_AGENTS", "1") == "0":
            return TeamResult(classes=[], allocation={}, specialists=[])
        picked = relevant_classes(survey, classes)
        alloc = allocate_budget(picked, total_budget)
        picked = [c for c in picked if c in alloc]      # only funded lanes run
        parallel = os.environ.get("AEGIS_TASK_PARALLEL", "0") == "1" and len(picked) > 1
        results = []
        if parallel:
            from concurrent.futures import ThreadPoolExecutor
            workers = min(len(picked), int(os.environ.get("AEGIS_TASK_WORKERS", "3")))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(self._run_specialist, c, alloc[c]): c for c in picked}
                for f in futs:
                    results.append(f.result())
            results.sort(key=lambda s: -_class_weight(s.vuln_class))
        else:
            for c in picked:                            # sequential: priority order (relevant_classes sorted)
                results.append(self._run_specialist(c, alloc[c]))
        total = sum(len(s.verified) for s in results)
        return TeamResult(classes=picked, allocation=alloc, specialists=results,
                          verified_total=total, parallel=parallel)


if __name__ == "__main__":                              # pragma: no cover
    import argparse, json
    ap = argparse.ArgumentParser(description="HPTSA-style hierarchical task-agent planner (preview)")
    ap.add_argument("--survey", help="JSON survey/fingerprint (surfaces/stack/tags)")
    ap.add_argument("--classes", nargs="*", help="restrict to these vuln classes")
    ap.add_argument("--budget", type=int, default=40)
    a = ap.parse_args()
    sv = json.loads(a.survey) if a.survey else {}
    picked = relevant_classes(sv, a.classes)
    alloc = allocate_budget(picked, a.budget)
    print("relevant classes (priority order):", picked)
    print("depth-budget allocation:", alloc)
