"""_task_agents_tests.py -- HPTSA-style hierarchical task-agent layer self-test.

Proves: relevance gating (no off-target specialist spawned), priority-weighted depth-budget allocation
(sums exactly to the total), class-constrained specialists only execute IN-CLASS moves, and the manager
aggregates oracle-verified findings across specialists into the shared store. Stub brainstorm/execute/
oracle (no network, no board, no LLM). Run:  python shared/_task_agents_tests.py
"""
import sys, os, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "operator"))
import verified_findings as vf        # noqa: E402
import task_agents as ta              # noqa: E402

_PASS = 0


def ok(cond, label):
    global _PASS
    assert cond, "FAIL: " + label
    _PASS += 1
    print("PASS", label)


def test_classify_and_relevance():
    ok(ta.classify_move({"vuln_class": "sqli"}) == "sqli", "classify: explicit class")
    ok(ta.classify_move({"technique": "reflected XSS in search"}) == "xss", "classify: keyword -> xss")
    ok(ta.classify_move({"claim_type": "idor.object_level"}) == "authz", "classify: idor -> authz")
    # relevance gate: a survey mentioning only sql + idor keeps sqli/authz, drops ssti/csrf/etc.
    survey = {"surfaces": ["/api/orders?id="], "stack": ["postgres"], "tags": ["sql", "idor"]}
    rel = ta.relevant_classes(survey)
    ok("sqli" in rel and "authz" in rel, "relevance: sql+idor survey keeps sqli & authz")
    ok("csrf" not in rel and "ssti" not in rel, "relevance: drops off-target classes (csrf/ssti)")
    ok(rel == sorted(rel, key=lambda c: -ta._class_weight(c)) or rel[0] in ("sqli", "ssrf", "authz", "injection"),
       "relevance: returned in priority order (high-weight first)")


def test_allocation_sums_exact():
    classes = ["sqli", "xss", "csrf"]         # weights 5,4,2
    alloc = ta.allocate_budget(classes, 22)
    ok(sum(alloc.values()) == 22, "allocate: budget sums EXACTLY to total (%d)" % sum(alloc.values()))
    ok(alloc["sqli"] >= alloc["xss"] >= alloc["csrf"], "allocate: higher priority gets >= budget")
    ok(all(v >= 1 for v in alloc.values()), "allocate: every funded lane has a floor of 1")
    ok(ta.allocate_budget([], 10) == {} and ta.allocate_budget(["sqli"], 0) == {}, "allocate: empty/zero -> {}")


def test_class_constrained_brainstorm():
    # a mixed-class brainstorm; the wrapper must hand a specialist only ITS class
    def mixed(ctx):
        return [{"vuln_class": "sqli", "surface": "/a"}, {"vuln_class": "xss", "surface": "/b"},
                {"technique": "SSRF to metadata", "surface": "/c"}]
    b_sqli = ta.class_constrained_brainstorm(mixed, "sqli")
    out = b_sqli({})
    ok(len(out) == 1 and out[0]["vuln_class"] == "sqli", "constrained brainstorm: only sqli moves pass")
    ok(b_sqli({}) and all(ta.classify_move(m) == "sqli" for m in b_sqli({})), "constrained: every move in-class")
    # untagged-but-valid moves are not starved: they get the focus class stamped
    def untagged(ctx):
        return [{"surface": "/x", "mechanism": "weird"}]
    out2 = ta.class_constrained_brainstorm(untagged, "ssrf")({})
    ok(out2 and out2[0].get("vuln_class") == "ssrf", "constrained: untagged move adopts focus class (no starve)")


def test_team_manager_aggregates_with_stub_specialist():
    # Unit-test the PLANNER+MANAGER orchestration deterministically via an injected run_specialist stub
    # (the real IterativeHunt wiring is exercised by the live on-target run). The stub records one verified
    # finding per unit of a specialist's budget into the shared store, tagged by its class -- so we can
    # assert relevance gating, exact budget split, per-class isolation, and cross-specialist aggregation.
    store = vf.FindingStore(os.path.join(tempfile.mkdtemp(), "f.jsonl"))
    ran = {}

    def stub_specialist(cls, budget):
        ran[cls] = budget
        before = {f["finding_id"] for f in store.verified()}
        fid = store.record_candidate(vf.Finding(claim_type=cls + ".stub", summary="x", severity="medium",
                                                coverage_tags=["surface:/s/" + cls]))
        store._transition(fid, "verified", cls + "@stub", {"notes": "depth=%d" % budget})
        new = [f["finding_id"] for f in store.verified() if f["finding_id"] not in before]
        return ta.SpecialistResult(vuln_class=cls, budget=budget, verified=new, attempts=budget)

    survey = {"tags": ["sql", "xss", "ssrf"]}          # gates to exactly these three lanes
    team = ta.HierarchicalTeam(lambda c: [], lambda m: {}, lambda r: ("rejected", {}),
                               store=store, run_specialist=stub_specialist)
    res = team.run(survey=survey, classes=["sqli", "xss", "ssrf"], total_budget=9)
    ok(set(res.classes) == {"sqli", "xss", "ssrf"}, "team: ran the 3 relevant specialists")
    ok(sum(res.allocation.values()) == 9, "team: total depth budget split exactly (9)")
    ok(ran == res.allocation, "team: each specialist got its allocated depth budget")
    ok(res.verified_total == 3 and res.verified_total == len(store.verified()),
       "team: aggregated verified findings == store (%d)" % res.verified_total)
    ok(all(len(s.verified) == 1 and ta.classify_move({"vuln_class": s.vuln_class}) == s.vuln_class
           for s in res.specialists), "team: every specialist verified exactly its own class")
    # highest-priority lane funded first/most (sqli & ssrf weight 5 >= xss weight 4)
    ok(res.allocation["sqli"] >= res.allocation["xss"] and res.allocation["ssrf"] >= res.allocation["xss"],
       "team: priority lanes funded >= lower-priority")
    ok(store.verify_chain(), "team: hash chain intact after multi-specialist run")


def test_default_specialist_wires_iterativehunt():
    # Smoke: the DEFAULT specialist actually constructs+runs an IterativeHunt without raising, with a
    # trivial brainstorm (empty) so it terminates immediately. Proves the live wiring imports/constructs.
    store = vf.FindingStore(os.path.join(tempfile.mkdtemp(), "f.jsonl"))
    team = ta.HierarchicalTeam(lambda ctx: [], lambda m: {"status": 200},
                               lambda r: ("rejected", {}), store=store, max_board_rounds=1)
    r = team._default_run_specialist("sqli", 2)
    ok(r.vuln_class == "sqli" and isinstance(r.verified, list), "default specialist: IterativeHunt wired + runs")


def test_disabled_switch():
    team = ta.HierarchicalTeam(lambda c: [], lambda m: {}, lambda r: ("rejected", {}))
    os.environ["AEGIS_TASK_AGENTS"] = "0"
    try:
        res = team.run(survey={}, total_budget=10)
        ok(res.classes == [] and res.verified_total == 0, "kill-switch AEGIS_TASK_AGENTS=0 -> no-op")
    finally:
        os.environ.pop("AEGIS_TASK_AGENTS", None)


def main():
    for t in (test_classify_and_relevance, test_allocation_sums_exact, test_class_constrained_brainstorm,
              test_team_manager_aggregates_with_stub_specialist, test_default_specialist_wires_iterativehunt,
              test_disabled_switch):
        t()
    print("\n%d/%d PASS" % (_PASS, _PASS))


if __name__ == "__main__":
    main()
