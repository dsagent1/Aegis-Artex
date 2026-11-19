#!/usr/bin/env python3
"""step_runner.py -- the STEP-ADAPTER SEAM (board build-order step 2).

A thin, resumable one-step interface over the canonical engine so the AutoLoop can run ONE pipeline
stage at a time, as a SUPERVISED KILLABLE CHILD PROCESS, WITHOUT rewriting complete_test.run_complete.
It imports the existing `complete_test._leg` (hunt legs) / remediation and emits a typed Outcome as a
single JSON line on stdout. run_complete keeps working unchanged; AutoLoop shells out to this.

Contracts (JSON, kept small + stable):
  Action  = {id, kind: operator|exploitgym|redteam|remediation, role, budget, campaign, base,
             objective?, auth?}
  Outcome = {action_id, kind, status: ok|error|skipped, confirmed, coverage, error?, campaign, store}

Usage (the AutoLoop calls this via supervisor.supervise):
  python step_runner.py --kind operator --role owner --budget 8 --campaign C --base https://host:8443
  python step_runner.py --kind operator ... --dry     # emit a stub Outcome, run nothing (offline test)
"""
import os, sys, json, time, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

HUNT_KINDS = ("operator", "exploitgym", "redteam")


def _emit(outcome):
    sys.stdout.write("\n__OUTCOME__ " + json.dumps(outcome) + "\n")
    sys.stdout.flush()


def run_step(a):
    outcome = {"action_id": a.id, "kind": a.kind, "status": "error", "confirmed": 0,
               "coverage": None, "campaign": a.campaign, "store": None}
    if a.dry:                                   # offline seam test: no engine, deterministic stub
        outcome.update(status="ok", confirmed=0, coverage={"n_covered": 0, "n_total": 0}, dry=True)
        return outcome
    try:
        import complete_test as CT
    except Exception as e:
        outcome["error"] = f"import complete_test failed: {e}"
        return outcome

    # per-stage env tags so board_ask + cost_meter pick the stage profile (matches complete_test._leg)
    os.environ["AEGIS_BOARD_STAGE"] = a.kind
    os.environ["AEGIS_STAGE"] = a.kind
    os.environ["AEGIS_CAMPAIGN"] = a.campaign
    camp_dir = os.path.join(CT.HERE, "campaigns", a.campaign)
    os.makedirs(camp_dir, exist_ok=True)
    store = os.path.join(camp_dir, "findings.jsonl")
    os.environ["AEGIS_LEDGER"] = store
    outcome["store"] = store

    try:
        if a.kind in HUNT_KINDS:
            roe = None
            if a.kind == "redteam" and a.auth:
                try:
                    roe = json.load(open(a.auth, encoding="utf-8"))
                except Exception:
                    roe = None
            leg = CT._leg(a.kind, objective=a.objective, role=a.role, budget=a.budget,
                          campaign=a.campaign, store=store, base=a.base,
                          extra_seeds=a.extra_seeds, roe=roe)
            conf = leg.get("confirmed") or []
            outcome.update(status=("error" if leg.get("error") else "ok"),
                           confirmed=len(conf),
                           coverage=(leg.get("report") or {}).get("coverage"),
                           error=leg.get("error"))
        elif a.kind == "remediation":
            import subprocess
            os.environ["AEGIS_BOARD_STAGE"] = "remediation"; os.environ["AEGIS_STAGE"] = "remediation"
            rem = os.path.join(camp_dir, "complete_test_remediation.md")
            cmd = [sys.executable, os.path.join(CT.HERE, "remediation_board.py"),
                   "--findings", store, "--panel", "ds,cf,qwen", "--synthesize", "--report", rem, "--write-ledger"]
            r = subprocess.run(cmd, cwd=CT.ROOT if hasattr(CT, "ROOT") else CT.HERE,
                               capture_output=True, text=True, timeout=2400)
            outcome.update(status=("ok" if r.returncode == 0 else "error"),
                           error=(None if r.returncode == 0 else f"remediation exit {r.returncode}"),
                           report=rem)
        else:
            outcome["error"] = f"unknown kind {a.kind!r}"
    except Exception as e:
        outcome["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    return outcome


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run ONE Aegis pipeline stage (step-adapter seam)")
    ap.add_argument("--kind", required=True, choices=HUNT_KINDS + ("remediation",))
    ap.add_argument("--id", default=None)
    ap.add_argument("--role", default="dispatcher")
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--base", default=None)
    ap.add_argument("--objective", default=None)
    ap.add_argument("--auth", default=None)
    ap.add_argument("--extra-seed", dest="extra_seeds", action="append", default=None)
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args(argv)
    a.id = a.id or f"{a.kind}-{int(time.time())}"
    print(f"[step_runner] kind={a.kind} campaign={a.campaign} budget={a.budget} base={a.base} dry={a.dry}",
          file=sys.stderr, flush=True)
    outcome = run_step(a)
    _emit(outcome)
    return 0 if outcome.get("status") in ("ok", "skipped") else 1


if __name__ == "__main__":
    sys.exit(main())
