#!/usr/bin/env python3
"""Grey-box BOARD-DRIVEN novelty hunt against the target mirror: authenticate as a low-priv
insider (DISPATCHER by default) and let the multi-model board brainstorm "what else can we try",
the oracle judge each move, and the Planner RE-OPEN on stall. Non-destructive (guard blocks
erase/drop/DELETE); wrapped in DB snapshot -> run -> restore so any write leaves no residue.

Run from Windows (reaches https://localhost:8443 + the board LLM). Findings -> hunt_findings.jsonl.
"""
import os, sys, json, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "shared"))

import requests
requests.packages.urllib3.disable_warnings()

from iterative_hunt import IterativeHunt, board_brainstorm
from iterative_hunt_live import make_execute, make_oracle
from verified_findings import FindingStore

BASE = os.environ.get("AEGIS_TARGET", "https://localhost:8443")
ROLE = os.environ.get("HUNT_ROLE", "dispatcher")
BUDGET = int(os.environ.get("HUNT_BUDGET", "30"))
ACCT = {"owner": "Owner User", "dispatcher": "Dispatcher Two", "finance": "Finance User",
        "warehouse": "Warehouse User", "technician": "Technician One"}

def session_for_role(role):
    s = requests.Session(); s.verify = False
    name = ACCT.get((role or "").lower(), ACCT["dispatcher"])
    try:
        s.post(BASE + "/api/auth/login", json={"name": name, "pin": "123456"}, timeout=12)
    except Exception:
        pass
    return s

def snap(op, name="greyboxhunt"):
    try:
        subprocess.run([sys.executable, os.path.join(HERE, "mirror_snapshot.py"), op, name],
                       capture_output=True, timeout=180)
    except Exception as e:
        print(f"[snap {op}] {e}")

def main():
    objective = os.environ.get("HUNT_OBJECTIVE") or (
                 f"You are an authenticated but LOW-PRIVILEGE {ROLE.upper()} insider on this ERM app. "
                 "Discover what else you can reach or do BEYOND your role: novel broken-access-control, "
                 "business-logic abuse, mass-assignment on writes, IDOR variants, privilege chains, "
                 "workflow/state bypasses. Non-destructive only (never erase/drop/delete).")
    store = FindingStore(os.path.join(HERE, "hunt_findings.jsonl"))
    try:
        from planner import plan_session
        sess = plan_session(objective, BASE, roles=[ROLE], mode="operator", base=BASE)
    except Exception as e:
        print(f"[planner] unavailable ({e}) -> no seeds/re-open, board brainstorm only")
        sess = None
    seeds = sess.initial_seeds() if sess else []
    reopen = (lambda ctx, why: sess.reopen(ctx, why)) if sess else None
    print(f"[hunt] role={ROLE} budget={BUDGET} seeds={len(seeds)} reopen={'on' if reopen else 'off'}")

    hunt = IterativeHunt(board_brainstorm, make_execute(BASE, session_for_role), make_oracle(store),
                         budget=BUDGET, seed_moves=seeds, reopen=reopen,
                         intel=(sess.intel if sess else None))
    orig = hunt.brainstorm
    hunt.brainstorm = lambda ctx: [dict(m, role=m.get("role", ROLE)) for m in (orig(ctx) or [])]

    snap("snapshot")
    t0 = time.time()
    try:
        rep = hunt.run(BASE, objective)
    finally:
        snap("restore")
        print(f"[hunt] restored snapshot; elapsed={int(time.time()-t0)}s")
    print("=== HUNT REPORT ===")
    print(json.dumps(rep, indent=2, default=str)[:4000])
    print("=== VERIFIED (this store) ===")
    for f in store.verified()[-15:]:
        print("  -", f.get("status"), "|", f.get("claim_type"), "|", (f.get("summary") or "")[:110])

if __name__ == "__main__":
    main()
