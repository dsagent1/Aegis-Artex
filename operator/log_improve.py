#!/usr/bin/env python3
"""log_improve.py -- CLOSE THE SELF-IMPROVEMENT LOOP: feed a REAL run's log (run_log.py telemetry:
failures, suspect-verifieds, timeline) TOGETHER WITH the source code responsible to the board of
coder-improvers, and get concrete, minimal FIXES for what actually went wrong / the hiccups.

The gap this closes: code_review.py reviews the source in the abstract (code only, no run context); run_log.py
records what happened (failures + verdicts) but nothing consumes it. So the improver never sees the evidence.
This joins them: for each FAILURE TYPE (and each SUSPECT-VERIFIED finding) in a campaign's run-log, it pulls
the mapped source, bundles {evidence + code}, fans out to the same board as code_review (_ask), and the
consultant consolidates a ranked improvement plan -> RUN_IMPROVE_<campaign>.md.

Usage:  python operator/log_improve.py <campaign> [--log <stdout.log>] [--models ...] [--out FILE]
        python operator/log_improve.py --run-log RUN_LOG_x.md            # improve from an existing run-log
"""
from __future__ import annotations
import argparse, os, sys, json, re, time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import run_log as RL
import code_review as CR
from code_suggester import CODE_SUGGESTERS

# failure-type / signal -> the source files most likely responsible (repo-relative). Board sees these + the
# evidence. Kept small per entry so the bundle stays within token budget.
FAIL_CODE_MAP = {
    "VERDICT":            ["operator/iterative_hunt_live.py", "operator/test_suggestions.py", "shared/verified_findings.py"],
    "SUSPECT_VERIFIED":   ["operator/iterative_hunt_live.py", "operator/meta_oracle.py", "operator/code_driver.py"],
    "CODER":              ["operator/code_driver.py", "operator/code_suggester.py"],
    "MISHAP":             ["operator/intervene.py", "operator/autoloop.py"],
    "FAIL:supervised_kill": ["operator/step_runner.py", "operator/supervisor.py"],
    "FAIL:traceback":     ["operator/complete_test.py", "operator/step_runner.py"],
    "FAIL:exception":     ["operator/complete_test.py", "operator/step_runner.py"],
    "FAIL:db_error":      ["operator/test_suggestions.py"],
    "FAIL:unreachable":   ["operator/executor_registry.py", "operator/ds_orchestrator.py"],
    "FAIL:no_code":       ["operator/code_driver.py", "operator/code_suggester.py"],
    "FAIL:login_fail":    ["operator/test_suggestions.py", "operator/complete_test.py"],
    "FAIL:cf_timeout":    ["operator/cf_agent.py", "operator/code_suggester.py"],
    "FAIL:run_error":     ["operator/code_driver.py", "operator/step_runner.py"],
}
# GOAL-SURFACE modules: always shown to the board (even with no logged failure) so it can propose fixes that
# ADVANCE the North Star -- more depth (footholds/beacons/chains), more tooling (use/create tools, Kali<->Arch),
# more reach/discovery (vectors) -- not merely repair what broke. Capped smaller to stay in token budget.
GOAL_MODULES = ["operator/vectors.py", "operator/distro_backend.py", "operator/reach.py",
                "redteam/foothold.py", "operator/tool_gap_resolver.py"]
GOAL_FILE_CHARS = int(os.environ.get("AEGIS_IMPROVE_GOAL_CHARS", "4200"))

# oracle_ids that the board + meta-oracle bake-off found can PASS without a real, exploit-caused breach ->
# any 'verified' via one of these is SUSPECT and must be reviewed (the artifact class).
SUSPECT_ORACLES = ("stateful.invariant", "stateful.", "rate.no_rate_limit", "distinguishing-2xx", "authz")

PER_FILE_CHARS = int(os.environ.get("AEGIS_IMPROVE_FILE_CHARS", "7000"))
REVIEW_TOKENS = int(os.environ.get("AEGIS_IMPROVE_TOKENS", "2600"))

# THE NORTH STAR the improvement leg optimises FOR (owner testing own contained machines).
GOAL = (
    "FRAMEWORK GOAL (the North Star every improvement must advance): on the owner's OWN contained machines, "
    "DISCOVER as much as possible and go as DEEP as possible; USE every available tool and CREATE new tools "
    "when a needed one is missing; leave traces, PLANT BEACONS and DEPLOY proof code on the target -- that is "
    "in-doctrine DEPTH OF PROOF, not a violation (owner's own kit). The ONLY hard limit is NON-DESTRUCTIVE: "
    "never erase/delete/corrupt data or drop tables. Success is measured RELATIVE TO THE ATTAINABLE FRONTIER "
    "in the tested environment (reaching 100% of everything is unattainable by default) -- the aim is to be a "
    "TOP-RATED tool within its class for THIS context. Trustworthiness (only oracle-verified findings count, "
    "no false positives) is the QUALITY GATE on that goal, never a substitute for it.")

IMPROVER_ROLE = (
    "You are a senior member of the AEGIS code-improver board. " + GOAL + "\n\n"
    "You are given (1) EVIDENCE from a REAL run's log -- failures and suspect findings with where they "
    "occurred -- and (2) the SOURCE CODE responsible. For each problem, find the CODE cause and propose a "
    "CONCRETE, MINIMAL fix. Rank every fix by how much it ADVANCES THE GOAL, tagging its primary axis: "
    "`discovery` (find more surfaces/classes), `depth` (reach further: chains, footholds, planted beacons/"
    "deployed proof, post-exploitation), `tooling` (use more tools / auto-provision or CREATE a missing tool "
    "/ wire Kali<->Arch), `reach` (access-first: get IN where currently blocked), `trust` (kill false "
    "positives / repair a broken oracle -- the gate), `budget` (stop wasted attempts so more of the budget "
    "buys real discovery/depth). Prefer fixes that unlock NEW depth or breadth over pure clean-up, but never "
    "at the cost of the non-destructive limit or of counting unverified findings. Reply STRICT JSONL, one "
    "object per line, no prose:\n"
    '{"file":"operator/x.py","line":0,"goal_axis":"discovery|depth|tooling|reach|trust|budget",'
    '"area":"oracle|driver|infra|tooling|design","severity":"high|med|low","effort":"S|M|L",'
    '"suggestion":"the concrete change","rationale":"which log evidence it addresses + how it advances the goal"}')


def _read_code(rel, cap=None):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return f"# ({rel} not found)"
    cap = cap or PER_FILE_CHARS
    txt = open(p, encoding="utf-8", errors="replace").read()
    if len(txt) > cap:
        txt = txt[:cap] + f"\n# ...[truncated {len(txt)-cap} chars; ask for more if needed]"
    return CR._scrub(txt)


def digest(campaign, since=0, log_path=None):
    """Build the run digest the board reasons over: summary + failures-by-type + suspect-verified findings."""
    cdir, ev = RL.build(campaign, since, log_path)
    try:
        p = json.load(open(os.path.join(cdir, "progress.json"), encoding="utf-8"))
    except Exception:
        p = {}
    L = [json.loads(l) for l in open(os.path.join(cdir, "findings.jsonl"), encoding="utf-8") if l.strip()] \
        if os.path.exists(os.path.join(cdir, "findings.jsonl")) else []
    trans = Counter(d.get("status") for d in L if d.get("type") == "transition")
    # failures grouped by type
    fails = [(k, det, where) for (ts, k, det, is_fail, where) in ev if is_fail]
    by_type = defaultdict(list)
    for k, det, where in fails:
        by_type[k].append(f"{('@'+where+' ') if where else ''}{det}")
    # SUSPECT-VERIFIED: verified transitions via a loose/artifact-prone oracle (meta-oracle never confirmed)
    suspect = []
    for d in L:
        if d.get("type") == "transition" and d.get("status") == "verified":
            oid = str(d.get("oracle_id", ""))
            if any(oid.startswith(s) or s in oid for s in SUSPECT_ORACLES):
                suspect.append(f"{oid} :: {json.dumps(d.get('oracle_receipt') or {})[:120]}")
    return {"campaign": campaign, "terminal": p.get("terminal_reason"), "verdicts": dict(trans),
            "by_type": {k: v for k, v in by_type.items()}, "suspect": suspect,
            "coverage_omissions": p.get("coverage_omissions")}


def _evidence_text(dg):
    out = [f"CAMPAIGN {dg['campaign']} terminal={dg['terminal']} verdicts={dg['verdicts']} "
           f"coverage_omissions={dg['coverage_omissions']}", ""]
    out.append("FAILURES (type -> occurrences):")
    for k, v in sorted(dg["by_type"].items(), key=lambda kv: -len(kv[1])):
        out.append(f"- {k} (x{len(v)}):")
        for line in v[:6]:
            out.append(f"    {line[:160]}")
    if dg["suspect"]:
        out.append("")
        out.append("SUSPECT-VERIFIED (passed a loose/artifact-prone oracle; meta-oracle did NOT confirm "
                   "exploit-causation -- treat as likely FALSE POSITIVES and propose how the CODE should gate them):")
        for s in dg["suspect"][:10]:
            out.append(f"- {s[:180]}")
    return "\n".join(out)


_GOAL_AXES = ("depth", "discovery", "tooling", "reach", "trust", "budget")


def _parse_goal(text, model):
    """Like CR._parse_findings but PRESERVES goal_axis so the plan can rank by goal contribution."""
    out = []
    for f in CR._parse_findings(text, model):
        ga = ""
        # re-find the raw line for this suggestion to recover goal_axis (CR._parse_findings drops it)
        for ln in (text or "").splitlines():
            if f["suggestion"][:30] and f["suggestion"][:30] in ln and '"goal_axis"' in ln:
                m = re.search(r'"goal_axis"\s*:\s*"([a-z]+)"', ln)
                if m:
                    ga = m.group(1)
                break
        f["goal_axis"] = ga if ga in _GOAL_AXES else "trust"
        out.append(f)
    return out


def _dedup_goal(findings):
    uniq = CR._dedup_findings(findings)
    # attach the majority goal_axis per merged item (match back by file+suggestion gist)
    ax_by_key = {}
    for f in findings:
        gist = " ".join(re.findall(r"[a-z0-9]+", (f.get("suggestion") or "").lower())[:8])
        ax_by_key.setdefault((f.get("file"), gist), Counter())[f.get("goal_axis", "trust")] += 1
    for u in uniq:
        gist = " ".join(re.findall(r"[a-z0-9]+", (u.get("suggestion") or "").lower())[:8])
        c = ax_by_key.get((u.get("file"), gist))
        u["goal_axis"] = (c.most_common(1)[0][0] if c else "trust")
    return uniq


def _files_for(dg):
    keys = set(dg["by_type"]) | ({"SUSPECT_VERIFIED"} if dg["suspect"] else set())
    files = []
    for k in keys:
        for f in FAIL_CODE_MAP.get(k, []):
            if f not in files:
                files.append(f)
    return files or ["operator/iterative_hunt_live.py", "operator/code_driver.py"]


def run(campaign, since=0, log_path=None, models=None, out=None):
    from concurrent.futures import ThreadPoolExecutor
    CR._load_secret_env()
    models = models or list(CODE_SUGGESTERS)
    dg = digest(campaign, since, log_path)
    evid = _evidence_text(dg)
    files = _files_for(dg)
    code_blob = "\n\n".join(f"===== FILE: {f} =====\n{_read_code(f)}" for f in files)
    goal_files = [f for f in GOAL_MODULES if f not in files]
    goal_blob = "\n\n".join(f"===== GOAL-SURFACE FILE: {f} =====\n{_read_code(f, GOAL_FILE_CHARS)}" for f in goal_files)
    user = (f"RUN EVIDENCE (from the run-log):\n{evid}\n\n"
            f"SOURCE CODE responsible for the failures above (fix these):\n{code_blob}\n\n"
            f"GOAL-SURFACE MODULES (no logged failure required -- propose changes here that ADVANCE THE GOAL: "
            f"more depth/footholds/beacons, more tool use/creation + Kali<->Arch routing, more reach/discovery):\n"
            f"{goal_blob}\n\n"
            "Now emit your JSONL fixes (concrete file+change), each tagged with its goal_axis and tied to the "
            "evidence or to a concrete goal-advancing opportunity.")
    print(f"[log_improve] {campaign}: {sum(len(v) for v in dg['by_type'].values())} failures, "
          f"{len(dg['suspect'])} suspect-verified, {len(files)} fail-files + {len(goal_files)} goal-files "
          f"-> {len(models)} improvers", flush=True)

    def _do(m):
        try:
            txt = CR._ask(m, IMPROVER_ROLE, user, max_tokens=REVIEW_TOKENS, temperature=0.3)
            return m, _parse_goal(txt, m)
        except Exception as e:
            return m, [{"file": "?", "area": "design", "severity": "low", "effort": "M", "goal_axis": "trust",
                        "suggestion": f"[{m} error] {str(e)[:80]}", "rationale": "", "model": m}]

    findings = []
    with ThreadPoolExecutor(max_workers=min(len(models), 6)) as ex:
        for m, fs in ex.map(_do, models):
            findings.extend(fs)
            print(f"[log_improve]   {m}: {len(fs)} suggestion(s)", flush=True)
    uniq = _dedup_goal(findings)
    plan = CR._consolidate(uniq) if uniq else "(no suggestions returned)"
    md = _report(dg, uniq, plan, files + goal_files)
    out = out or os.path.join(ROOT, f"RUN_IMPROVE_{campaign}.md")
    open(out, "w", encoding="utf-8").write(md)
    print(f"[log_improve] plan written: {out}", flush=True)
    return out, dg, uniq, plan


def _report(dg, uniq, plan, files):
    ts = time.strftime("%Y-%m-%d %H:%M")
    out = [f"# RUN IMPROVE — {dg['campaign']}", f"_board-of-improvers pass over the run-log + code · {ts}_", "",
           f"- terminal: **{dg['terminal']}**  verdicts: {dg['verdicts']}",
           f"- failures reviewed: {sum(len(v) for v in dg['by_type'].values())} across {len(dg['by_type'])} types",
           f"- suspect-verified (likely FP): {len(dg['suspect'])}",
           f"- code reviewed: {', '.join(files)}", "",
           f"- goal-axis mix: {dict(Counter(u.get('goal_axis','trust') for u in uniq))}", "",
           "## CONSOLIDATED IMPROVEMENT PLAN (consultant)", "", plan, ""]
    # GOAL-ALIGNED view: group by the North-Star axis, goal-advancing axes (depth/discovery/tooling/reach)
    # first, then the trust/budget gate items. Within an axis, most severe + highest consensus first.
    out += ["## BY GOAL AXIS (North Star: discover more · go deeper · use/create tools · in-doctrine reach)", ""]
    for ax in _GOAL_AXES:
        items = [u for u in uniq if u.get("goal_axis", "trust") == ax]
        if not items:
            continue
        out.append(f"### {ax.upper()} ({len(items)})")
        for u in sorted(items, key=lambda u: (CR._SEV_RANK.get(u["severity"], 3), -u["consensus"])):
            out.append(f"- **[{u['severity']}]** `{u['file']}:{','.join(map(str,u['lines'])) or '-'}` "
                       f"(x{u['count']} {','.join(u['models'])}) — {u['suggestion']}")
        out.append("")
    out += ["## EVIDENCE (from run-log)", "", "```", _evidence_text(dg), "```"]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="board-of-improvers pass over a run's log + the responsible code")
    ap.add_argument("campaign", nargs="?", help="campaign name under operator/campaigns/")
    ap.add_argument("--log", default=None, help="stdout log to mine for leg-level failures")
    ap.add_argument("--since", type=float, default=0)
    ap.add_argument("--models", nargs="*", default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    if not a.campaign:
        ap.error("give a campaign name")
    out, dg, uniq, plan = run(a.campaign, a.since, a.log, a.models, a.out)
    print("\n" + plan[:1600])


if __name__ == "__main__":
    main()
