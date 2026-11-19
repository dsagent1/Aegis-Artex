"""_planning_tests.py -- #5 classical planner + persistent attack-graph self-test.

Proves: (a) the STRIPS/PDDL-style A* planner returns an OPTIMAL plan, says NO PLAN when a goal is
unreachable, and respects technique/credential preconditions; (b) operators-from-graph planning matches
the graph's own best_path; (c) the attack graph persists (save/load round-trip) and MERGES across runs so
the planner searches an ever-richer map. Pure stdlib, no network. Run:
    python redteam/_planning_tests.py
"""
import sys, os, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import attack_graph as ag          # noqa: E402
import planning as pl              # noqa: E402

_PASS = 0


def ok(cond, label):
    global _PASS
    assert cond, "FAIL: " + label
    _PASS += 1
    print("PASS", label)


def _chain_graph():
    g = ag.AttackGraph()
    g.add_edge("web", "app", "has_session", 1)
    g.add_edge("app", "db", "has_cred", 1)
    g.add_edge("db", "dc01", "can_privesc", 3)
    g.add_edge("web", "dc01", "trusts", 9)      # a direct-but-expensive alternative
    return g


def test_astar_optimal():
    g = _chain_graph()
    p = pl.plan_to_goal_node(g, "web", "dc01")
    ok(p.found, "A*: plan found web->dc01")
    # cheapest chain is web->app->db->dc01 (1+1+3=5), NOT the direct trusts edge (cost 9)
    ok(abs(p.cost - 5.0) < 1e-9, "A*: returns OPTIMAL cost 5 (not the cost-9 direct edge)")
    ok([a.name for a in p.actions][0] == "has_session@web->app", "A*: first step is the cheap chain")


def test_no_plan():
    g = ag.AttackGraph()
    g.add_edge("web", "app", "has_session", 1)   # app is a dead-end, dc01 unreachable
    p = pl.plan_to_goal_node(g, "web", "dc01")
    ok(not p.found and "NO PLAN" in p.describe(), "A*: unreachable goal -> honest NO PLAN")


def test_technique_preconditions():
    # Reaching db needs a credential that only a 'phish' technique grants. Without the technique op there
    # is NO plan to at(db); WITH it, the planner composes phish -> use_cred -> at(db).
    use_cred = pl.op("use_cred@app->db", pre=["at(app)", "cred(db)"], add=["at(db)"], cost=1)
    reach_app = pl.op("sess@web->app", pre=["at(web)"], add=["at(app)"], cost=1)
    phish = pl.op("phish_db_cred", pre=["at(app)"], add=["cred(db)"], cost=4)
    p0 = pl.plan(["at(web)"], ["at(db)"], [reach_app, use_cred])            # no way to get cred(db)
    ok(not p0.found, "technique: no plan without the credential-granting technique")
    p1 = pl.plan(["at(web)"], ["at(db)"], [reach_app, use_cred, phish])     # technique supplies cred
    ok(p1.found and any(a.name == "phish_db_cred" for a in p1.actions),
       "technique: planner composes phish -> use_cred to meet the precondition")


def test_operators_from_techniques():
    ops = pl.operators_from_techniques([
        {"name": "steal_token", "requires": ["at(app)"], "grants": ["cred(db)"], "cost": 2},
        {"name": "dump_lsass", "requires": ["at(dc01)"], "grants": ["owns(dc01)"], "consumes": [], "cost": 1},
    ])
    ok(len(ops) == 2 and ops[0].add == frozenset(["cred(db)"]), "operators_from_techniques builds actions")


def test_graph_plan_vs_best_path():
    # best_path sorts HOPS-first (picks the 1-hop cost-9 'trusts' edge); the A* planner is COST-optimal
    # (the 3-hop cost-5 chain). The planner is therefore never MORE expensive than best_path -- that
    # cost-optimality is exactly what the classical layer adds over the topology's shortest-hop view.
    g = _chain_graph()
    bp = g.best_path("web", "dc01")
    p = pl.plan_to_goal_node(g, "web", "dc01")
    ok(bp and p.found and p.cost <= bp["cost"] + 1e-9, "classical plan is cost-optimal (<= best_path cost)")
    ok(p.cost < bp["cost"], "classical plan beats hop-first best_path on cost here (5 < 9)")


def test_persistence_roundtrip():
    g = _chain_graph()
    d = tempfile.mkdtemp(); path = os.path.join(d, "ag.json")
    g.save(path)
    g2 = ag.AttackGraph.load(path)
    ok(g2.nodes.keys() == g.nodes.keys(), "persist: nodes round-trip")
    p = pl.plan_to_goal_node(g2, "web", "dc01")
    ok(p.found and abs(p.cost - 5.0) < 1e-9, "persist: planner searches the RELOADED graph, same optimum")
    ok(ag.AttackGraph.load(os.path.join(d, "nope.json")).nodes == {}, "persist: missing store -> empty graph (no raise)")


def test_merge_grows_across_runs():
    d = tempfile.mkdtemp(); path = os.path.join(d, "ag.json")
    # run 1 learns web->app
    g1 = ag.AttackGraph(); g1.add_edge("web", "app", "has_session", 1); g1.save(path)
    # run 2 learns app->db->dc01 and merges into the persisted graph
    acc = ag.AttackGraph.load(path)
    g2 = ag.AttackGraph(); g2.add_edge("app", "db", "has_cred", 1); g2.add_edge("db", "dc01", "can_privesc", 3)
    acc.merge(g2).save(path)
    merged = ag.AttackGraph.load(path)
    # neither run alone could reach dc01 from web; the ACCUMULATED graph can
    ok(not pl.plan_to_goal_node(g1, "web", "dc01").found, "merge: run-1 graph alone cannot reach dc01")
    ok(pl.plan_to_goal_node(merged, "web", "dc01").found, "merge: accumulated graph reaches dc01")
    # merge is idempotent on edges (no duplicates)
    acc.merge(g2); n_edges = sum(len(v) for v in acc.edges.values())
    ok(n_edges == 3, "merge: edge-dedup keeps the graph clean across repeats (%d)" % n_edges)


def test_seed_moves_from_plan():
    g = _chain_graph()
    sm = pl.seed_moves_from_plan(pl.plan_to_goal_node(g, "web", "dc01"), max_moves=2)
    ok(len(sm) == 2 and sm[0]["origin"] == "classical_plan", "seed_moves: plan steps exposed as anchors")


def main():
    for t in (test_astar_optimal, test_no_plan, test_technique_preconditions,
              test_operators_from_techniques, test_graph_plan_vs_best_path,
              test_persistence_roundtrip, test_merge_grows_across_runs, test_seed_moves_from_plan):
        t()
    print("\n%d/%d PASS" % (_PASS, _PASS))


if __name__ == "__main__":
    main()
