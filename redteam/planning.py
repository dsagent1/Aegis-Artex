"""#5 -- classical (STRIPS/PDDL-style) planner over the persistent attack graph.

The attack GRAPH (attack_graph.py) is topology -- "who can reach whom". This adds the PLANNING brain on
top: a STRIPS-style classical planner that searches sequences of grounded ACTIONS (each with
preconditions / add-effects / delete-effects / cost) to drive an INITIAL state to a GOAL state. It is
distinct from, and complementary to, the board's technique ranking:

  * the Planner (operator/planner.py) ranks WHICH techniques are relevant and devises novel ones;
  * this classical planner ORDERS grounded steps into a goal-directed chain and proves a goal is reachable
    (or proves it is NOT, with the current facts) -- a searchable, explainable plan, not a brainstorm.

It is pure + dependency-free (A* with an admissible unmet-goal-count heuristic), so it is unit-testable
without a live target and runs anywhere. Operators are produced from the SAME ground truth the loop uses:
`operators_from_graph` turns persistent attack-graph edges into actions, and `operators_from_techniques`
turns technique-DB entries into actions -- so the plan the search returns is grounded in verified
reachability + known techniques, never free-floating.
"""
from __future__ import annotations

import heapq
import itertools
import math
from dataclasses import dataclass, field
from typing import Iterable, Optional

try:
    from attack_graph import AttackGraph           # when run from redteam/
except Exception:                                   # pragma: no cover
    from redteam.attack_graph import AttackGraph    # when imported as a package


# A "fact" is a hashable string, e.g. "at(web)", "cred(app_db)", "owns(dc01)". A STATE is a frozenset.
Fact = str
State = frozenset


@dataclass(frozen=True)
class Operator:
    """A grounded STRIPS action: applicable when `pre` ⊆ state; yields state ∪ add − dele."""
    name: str
    pre: frozenset = field(default_factory=frozenset)
    add: frozenset = field(default_factory=frozenset)
    dele: frozenset = field(default_factory=frozenset)
    cost: float = 1.0

    def applicable(self, state: State) -> bool:
        return self.pre <= state

    def apply(self, state: State) -> State:
        return frozenset((set(state) - set(self.dele)) | set(self.add))


def op(name, pre=(), add=(), dele=(), cost=1.0) -> Operator:
    return Operator(name, frozenset(pre), frozenset(add), frozenset(dele), float(cost))


@dataclass
class Plan:
    actions: list           # list[Operator] in order
    cost: float
    goal: frozenset
    expanded: int = 0       # search nodes expanded (search effort -- for diagnostics)

    @property
    def found(self) -> bool:
        return self.actions is not None

    def describe(self) -> str:
        if self.actions is None:
            return "NO PLAN (goal unreachable from the current facts)"
        steps = " -> ".join(a.name for a in self.actions)
        return f"{steps}  (steps={len(self.actions)}, cost={self.cost:g}, expanded={self.expanded})"


def _h(state: State, goal: State) -> int:
    """Count of still-unmet goal facts. Admissible ONLY when each action adds at most one goal fact AND
    costs >= 1; `plan()` uses the operator-aware `_admissible_h` below (which stays admissible for
    multi-goal / low-cost operators), so it keeps A*'s optimality guarantee in the general case."""
    return len(goal - state)


def _admissible_h(goal: State, max_goal_adds: int, min_cost: float):
    """Build an operator-aware admissible heuristic: one action adds at most `max_goal_adds` goal facts
    and costs at least `min_cost`, so reaching `unmet` unmet goals costs >= ceil(unmet/max_goal_adds) *
    min_cost -- a true lower bound (never an overestimate), unlike the naive unmet-count which overshoots
    when a single cheap operator grants several goal facts at once."""
    k = max(1, int(max_goal_adds))

    def _hh(state: State) -> float:
        unmet = len(goal - state)
        if unmet <= 0:
            return 0.0
        return math.ceil(unmet / k) * min_cost
    return _hh


def plan(init: Iterable[Fact], goal: Iterable[Fact], operators: Iterable[Operator],
         *, max_expansions: int = 20000) -> Plan:
    """A* search for a least-cost action sequence from `init` to a state that satisfies every goal fact.
    Returns Plan(found=False) when the goal cannot be reached with the given operators (a real, useful
    answer: 'with what we know, there is no path')."""
    start = frozenset(init)
    goalf = frozenset(goal)
    ops = list(operators)
    if goalf <= start:
        return Plan(actions=[], cost=0.0, goal=goalf, expanded=0)
    # operator-aware admissible heuristic (keeps A* optimal for multi-goal / low-cost operators)
    _adds = [len(goalf & o.add) for o in ops if (goalf & o.add)]
    _costs = [o.cost for o in ops if o.cost > 0]
    h = _admissible_h(goalf, max(_adds) if _adds else 1, min(_costs) if _costs else 0.0)
    counter = itertools.count()                     # tie-breaker -> stable, avoids comparing states
    openq = [(h(start), 0.0, next(counter), start, [])]
    best = {start: 0.0}
    expanded = 0
    while openq and expanded < max_expansions:
        f, g, _, state, acts = heapq.heappop(openq)
        if g > best.get(state, float("inf")):
            continue                                # a cheaper route to `state` was already settled
        if goalf <= state:
            return Plan(actions=acts, cost=g, goal=goalf, expanded=expanded)
        expanded += 1
        for o in ops:
            if not o.applicable(state):
                continue
            ns = o.apply(state)
            ng = g + o.cost
            if ng < best.get(ns, float("inf")):
                best[ns] = ng
                heapq.heappush(openq, (ng + h(ns), ng, next(counter), ns, acts + [o]))
    return Plan(actions=None, cost=float("inf"), goal=goalf, expanded=expanded)


# ---------------------------------------------------------------------------------------------------
# Grounding: build operators from the SAME ground truth the loop already holds.
# ---------------------------------------------------------------------------------------------------
def at(node) -> Fact:
    return f"at({node})"


def operators_from_graph(graph: AttackGraph) -> list:
    """Each attacker-usable edge  A --rel--> B  becomes an action:
        name = rel@A->B, pre = {at(A)}, add = {at(B)}, cost = edge cost.
    So a classical plan over these operators is exactly a least-cost attack PATH -- but expressed as a
    searchable action model the planner can combine with technique/credential facts below."""
    ops = []
    for src, es in graph.edges.items():
        for dst, rel, c in es:
            ops.append(op(f"{rel}@{src}->{dst}", pre=[at(src)], add=[at(dst)], cost=c))
    return ops


def operators_from_techniques(entries: Iterable[dict]) -> list:
    """Turn technique-DB entries into planning actions. Each entry may declare:
        {name, requires:[facts], grants:[facts], consumes:[facts], cost}
    so a technique that NEEDS a credential and GRANTS a foothold composes with graph-movement actions in
    one search (e.g. 'phish -> cred -> use_cred -> at(host) -> privesc -> owns(host)')."""
    ops = []
    for e in entries or []:
        name = e.get("name") or e.get("technique") or "technique"
        ops.append(op(name,
                      pre=e.get("requires") or (),
                      add=e.get("grants") or (),
                      dele=e.get("consumes") or (),
                      cost=float(e.get("cost", 2.0))))
    return ops


def plan_to_goal_node(graph: AttackGraph, start_node, goal_node, *,
                      extra_operators: Optional[Iterable[Operator]] = None,
                      extra_init: Iterable[Fact] = (), **kw) -> Plan:
    """Convenience: plan from being at `start_node` to being at `goal_node` over the graph (plus any
    extra technique operators / seed facts). Mirrors AttackGraph.best_path but through the action model,
    so credential/technique prerequisites are respected -- and it says NO PLAN when they are not met."""
    ops = operators_from_graph(graph) + list(extra_operators or [])
    return plan([at(start_node), *extra_init], [at(goal_node)], ops, **kw)


def seed_moves_from_plan(p: Plan, max_moves: int = 3) -> list:
    """Expose the first few plan steps as MODE-1 anchor seed_moves for the iterative-hunt loop, so the
    classical plan actually steers early execution (goal-directed), not just reports a path."""
    if not p.found:
        return []
    out = []
    for a in p.actions[:max_moves]:
        out.append({"origin": "classical_plan", "action": a.name,
                    "pre": sorted(a.pre), "effect": sorted(a.add), "cost": a.cost})
    return out
