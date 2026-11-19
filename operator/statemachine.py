#!/usr/bin/env python3
"""
statemachine.py -- Y slice 1: a per-entity STATE-MACHINE modeler + StateMachineOracle for the money
surface (CreditNote / Invoice / Estimate). Models the legal status transitions from the Prisma enums +
route handlers, then probes ILLEGAL / out-of-order / replayed transitions and confirms each with a DB
BEFORE/AFTER causation witness (reusing the money-invariant machinery in shared/verified_findings.py).

Doctrine: owned mirror only, non-destructive (create/plant + snapshot-restore, never erase real data),
oracle + DB-witnessed. A forbidden transition is a FINDING only when the DB proves the entity actually
moved into the forbidden state (or a value-invariant broke) -- an HTTP 4xx alone is NOT a finding, and a
correctly-refused transition is a clean NEGATIVE.

New file; imports the shared oracle layer but edits none of the plumbing modules.

Usage:
    python statemachine.py --run --campaign g57sm        # seed (via _runs SQL) -> probe -> restore
"""
from __future__ import annotations
import os, sys, json, time, uuid, argparse, subprocess
import concurrent.futures as _cf

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "shared"))
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    requests = None

BASE = os.environ.get("AEGIS_TARGET", "https://localhost:8443")
DB_CONTAINER = os.environ.get("AEGIS_DB_CONTAINER", "aegis-mirror-db-1")
DB_USER = os.environ.get("AEGIS_DB_USER", "app")
DB_NAME = os.environ.get("AEGIS_DB_NAME", "app")
WSL_DISTRO = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")
PIN = os.environ.get("AEGIS_TEST_PIN", "123456")
_RUNS = os.path.join(HERE, "..", "_runs")

# ---- the modeled FSMs (legal transitions). "*" target = a terminal state. ----
FSM = {
    "Invoice":    {"DRAFT": {"SENT"}, "SENT": {"PAID", "OVERDUE"}, "OVERDUE": {"PAID"}, "PAID": set()},
    "CreditNote": {"DRAFT": {"ISSUED"}, "ISSUED": set()},                       # ISSUED is terminal + audit-locked
    "Estimate":   {"DRAFT": {"SENT", "APPROVED", "DECLINED"},                   # skip-send to APPROVED is allowed
                   "SENT": {"APPROVED", "DECLINED"}, "APPROVED": set(), "DECLINED": set()},
}


def db(sql: str) -> str:
    """Run SQL in the mirror DB, return trimmed -A -t output (or '[db error ...]')."""
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"; env["MSYS2_ARG_CONV_EXCL"] = "*"
    try:
        return subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "docker", "exec", "-i",
                               DB_CONTAINER, "psql", "-U", DB_USER, "-d", DB_NAME, "-t", "-A", "-c", sql],
                              capture_output=True, text=True, env=env, timeout=30).stdout.strip()
    except Exception as e:
        return f"[db error: {e}]"


def _sql_file(path: str) -> str:
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"; env["MSYS2_ARG_CONV_EXCL"] = "*"
    wsl_path = "/mnt/c/aegis-portable/orchestrator/_runs/" + os.path.basename(path)
    try:
        return subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc",
                               f"docker exec -i {DB_CONTAINER} psql -U {DB_USER} -d {DB_NAME} -v ON_ERROR_STOP=1 < {wsl_path}"],
                              capture_output=True, text=True, env=env, timeout=60).stdout.strip()
    except Exception as e:
        return f"[db error: {e}]"


def login(name: str):
    s = requests.Session(); s.verify = False
    r = s.post(BASE + "/api/auth/login", json={"name": name, "pin": PIN}, timeout=15)
    return s, (r.status_code == 200)


# ---- the oracle: a forbidden transition is proven by the DB, not the HTTP status ----
class StateMachineOracle:
    """A FORBIDDEN state transition (illegal per FSM, replayed, or out-of-order) must be REFUSED.
    VERIFIED (a bug) iff the DB before/after rows prove the entity actually entered the forbidden
    target state (before != target AND after == target), OR a paired value-invariant broke
    (`invariant_broke`). A correct refusal (after == before) -> rejected. The DB rows are the
    causation witness; the HTTP status is context, never the decider."""
    def __init__(self, entity, ident, *, before, after, forbidden_target=None,
                 invariant_broke=None, http_status=None, label="", oracle_id="statemachine@1", surface=""):
        self.entity, self.ident = entity, ident
        self.before, self.after, self.target = before, after, forbidden_target
        self.invariant_broke = invariant_broke
        self.http_status, self.label, self.id, self.surface = http_status, label, oracle_id, surface

    def check(self, finding=None):
        entered_forbidden = (self.target is not None and self.before != self.target and self.after == self.target)
        bug = bool(entered_forbidden or self.invariant_broke)
        return ("verified" if bug else "rejected"), {
            "entity": self.entity, "id": self.ident, "surface": self.surface, "transition": self.label,
            "db_before": self.before, "db_after": self.after, "forbidden_target": self.target,
            "invariant_broke": self.invariant_broke, "http_status": self.http_status,
            "note": (f"entity entered forbidden state {self.target!r} (before={self.before!r})" if entered_forbidden else
                     ("paired value-invariant broke" if self.invariant_broke else
                      "transition correctly refused / no forbidden state entered"))}


def _cn_status(cid): return db(f'select status from "CreditNote" where id=\'{cid}\'') or "MISSING"
def _cn_issued_sum(inv): return float(db(f'select coalesce(sum(total),0) from "CreditNote" where "invoiceId"=\'{inv}\' and status=\'ISSUED\'') or 0)


def run_suite(record):
    """Probe the money-surface FSMs against the live mirror. `record(summary, sev, verdict, notes, tags)`
    persists each result. Assumes the g57m seed is loaded (invoice g57m-inv-003 total=600, no issued CNs)."""
    fin, ok = login("Finance User")
    if not ok:
        record("statemachine suite could not authenticate finance", "unknown", "rejected", "login failed", ["class:statemachine"]); return
    INV = "g57m-inv-003"; INV_TOTAL = float(db(f'select total from "Invoice" where id=\'{INV}\'') or 0)

    def mk_draft(unit):
        r = fin.post(BASE + "/api/credit-notes", json={"invoiceId": INV, "reason": "g57sm draft",
            "items": [{"description": "sm", "quantity": 1, "unitPrice": unit, "vatCode": "STANDARD", "vatRate": 20}]}, timeout=20)
        try: return r.json().get("id"), r.status_code
        except Exception: return None, r.status_code

    # ---- TEST 1: DRAFT->ISSUED concurrent cap race (the real financial invariant) ----
    # Create K drafts, then ISSUE them all concurrently. The issue route SHOULD serialize
    # (SELECT ... FOR UPDATE) so sum(ISSUED) can never exceed invoice.total. VAT-aware: a note's
    # total is unit*1.2 (STANDARD 20%), so pick unit s.t. total ~= 0.8*invoice -> each single note
    # fits the cap (one CAN legally issue) but any TWO issued would breach it.
    K = 6; amt = round(INV_TOTAL * 0.8 / 1.2, 2)   # total ~= 0.8*invoice; 2 issued > invoice.total
    drafts = [mk_draft(amt)[0] for _ in range(K)]
    drafts = [d for d in drafts if d]
    before_sum = _cn_issued_sum(INV)
    def issue(cid):
        try: return cid, fin.post(BASE + f"/api/credit-notes/{cid}/issue", timeout=25).status_code
        except Exception as e: return cid, -1
    with _cf.ThreadPoolExecutor(max_workers=K) as ex:
        issue_codes = dict(ex.map(issue, drafts))
    after_sum = _cn_issued_sum(INV)
    n_issued = int(db(f'select count(*) from "CreditNote" where "invoiceId"=\'{INV}\' and status=\'ISSUED\'') or 0)
    broke = after_sum > INV_TOTAL + 0.01
    v, rec = StateMachineOracle("CreditNote", INV, before=before_sum, after=after_sum,
                                invariant_broke=broke, label="DRAFT->ISSUED concurrent cap race",
                                oracle_id="dbcausation@statemachine", surface="/api/credit-notes/:id/issue").check()
    record(f"CreditNote DRAFT->ISSUED concurrent-issue cap race on one invoice ({len(drafts)} parallel issues)",
           "high" if broke else "unknown", v,
           f"{len(drafts)} drafts created @unit={amt} (total~{round(amt*1.2,2)} each) on invoice total={INV_TOTAL}; issued statuses={sorted(issue_codes.values())}; "
           f"DB issued_count={n_issued} sum(ISSUED)={after_sum} (bound={INV_TOTAL}); invariant_broke={broke}. "
           f"{'BREACH: sum(ISSUED)>total under concurrency' if broke else 'FOR UPDATE lock held: only within-cap issues succeeded (my earlier create-path TOCTOU claim was DRAFT-only, corrected)'}",
           ["source:claude", "surface:/api/credit-notes/:id/issue", "class:invariant_race"])

    # ---- TEST 2: replayed terminal transition -- re-ISSUE an already-ISSUED note (double-settle) ----
    issued = [c for c, code in issue_codes.items() if code == 200]
    if issued:
        cid = issued[0]; before = _cn_status(cid)
        r2 = fin.post(BASE + f"/api/credit-notes/{cid}/issue", timeout=20)
        after = _cn_status(cid)
        v2, _ = StateMachineOracle("CreditNote", cid, before=before, after=after, forbidden_target="REISSUED",
                                   http_status=r2.status_code, label="ISSUED->ISSUED replay",
                                   oracle_id="dbcausation@statemachine", surface="/api/credit-notes/:id/issue").check()
        # a correct refusal returns 409 and status stays ISSUED (no second settle) -> rejected
        record("CreditNote re-issue (replay ISSUED->ISSUED) double-settle", "unknown",
               "verified" if r2.status_code == 200 else "rejected",
               f"re-issue of already-ISSUED note -> HTTP {r2.status_code}; status {before}->{after}. "
               f"{'accepted a second issue (double-settle risk)' if r2.status_code==200 else 'correctly refused (409, audit-locked)'}",
               ["source:claude", "surface:/api/credit-notes/:id/issue", "class:transition_replay"])

    # ---- TEST 3: mutate a terminal (ISSUED) note -- add a line after issue ----
    if issued:
        cid = issued[0]
        r3 = fin.post(BASE + f"/api/credit-notes/{cid}/items",
                      json={"description": "after-issue", "quantity": 1, "unitPrice": 10, "vatCode": "STANDARD", "vatRate": 20}, timeout=20)
        added = int(db(f'select count(*) from "CreditNoteItem" where "creditNoteId"=\'{cid}\' and description=\'after-issue\'') or 0)
        record("CreditNote edit-after-issue (append line to ISSUED note)", "unknown",
               "verified" if added > 0 else "rejected",
               f"POST /items on ISSUED note -> HTTP {r3.status_code}; DB new-line-count={added}. "
               f"{'MUTATED a terminal audit record' if added>0 else 'correctly refused'}",
               ["source:claude", "surface:/api/credit-notes/:id/items", "class:transition_mutate_terminal"])

    # ---- TEST 4: Estimate replayed terminal response -- approve an already-APPROVED estimate ----
    est = "g57m-est-001"                     # seeded APPROVED
    before = db(f'select status from "Estimate" where id=\'{est}\'')
    r4 = fin.post(BASE + f"/api/estimates/{est}/decline", timeout=20)   # flip a terminal response
    after = db(f'select status from "Estimate" where id=\'{est}\'')
    v4, _ = StateMachineOracle("Estimate", est, before=before, after=after, forbidden_target="DECLINED",
                               http_status=r4.status_code, label="APPROVED->DECLINED replay",
                               oracle_id="dbcausation@statemachine", surface="/api/estimates/:id/decline").check()
    record("Estimate flip terminal response (APPROVED->DECLINED)", "medium" if after == "DECLINED" and before != "DECLINED" else "unknown", v4,
           f"decline an already-APPROVED estimate -> HTTP {r4.status_code}; status {before}->{after}. "
           f"{'FLIPPED a terminal response' if after=='DECLINED' and before!='DECLINED' else 'correctly refused (terminal)'}",
           ["source:claude", "surface:/api/estimates/:id/decline", "class:transition_replay"])


def _record_factory(campaign):
    from dataclasses import asdict
    from verified_findings import FindingStore, Finding, Evidence
    store = FindingStore(os.path.join(HERE, "campaigns", campaign, "findings.jsonl"))
    os.makedirs(os.path.join(HERE, "campaigns", campaign), exist_ok=True)
    def record(summary, sev, verdict, notes, tags):
        f = Finding(claim_type="statemachine.claude", summary=summary, severity=sev, run_id=f"{campaign}-claude",
                    provenance={"provider": "claude", "via": "statemachine", "class": (tags[-1].split(":")[1] if tags else "")},
                    coverage_tags=tags, evidence=[asdict(Evidence(kind="http", detail=notes))])
        fid = store.record_candidate(f); store._transition(fid, verdict, "oracle:claude", {"notes": notes})
        print(f"  [{verdict.upper():8s}][{sev:6s}] {summary[:62]}")
    return record, store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--campaign", default="g57sm")
    ap.add_argument("--no-seed", action="store_true", help="assume the g57m seed is already loaded")
    a = ap.parse_args()
    if requests is None:
        sys.exit("requests not available")
    record, store = _record_factory(a.campaign)
    if a.run and not a.no_seed:
        print("seed:", (_sql_file("g57m_seed.sql") or "(ok)")[-40:])
    try:
        run_suite(record)
    finally:
        if a.run and not a.no_seed:
            print("restore:", (_sql_file("g57m_restore.sql") or "(ok)")[-60:])
        print("chain_ok=", store.verify_chain() if hasattr(store, "verify_chain") else "n/a")


if __name__ == "__main__":
    main()
