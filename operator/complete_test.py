"""complete_test.py -- the AEGIS COMPLETE TEST: the default full assessment, all four stages across the
CROSS-MODE RELAY. This is what "run the complete test" means: not one leg, but the whole chain.

    L1 Operator   (tier 1, non-destructive)        -- discover + confirm footholds
      |  (campaign ledger: only ORACLE-CONFIRMED footholds hand off, deduped, tier-gated, re-confirmed)
    L2 ExploitGym (tier 2, + audit)                -- RESUME L1, go DEEPER (escalate), never re-walk
      |
    L3 Red-Team   (tier 3, + FAIL-CLOSED authorization/scope, deeper escalation budget)
      |
    L4 Remediation (board code-fixes, two audiences) -- fix every VERIFIED weakness

One engine, three modes, shared vectors (docs/ARCHITECTURE): each leg is the same iterative-hunt loop with a
different DOCTRINE WRAPPER and a higher permission tier, resuming the prior legs' confirmed footholds from the
shared campaign ledger (campaign_ledger.py) and spending its budget only on NEW depth. L3 is FAIL-CLOSED: the
target must be in the Rules-of-Engagement scope or the leg does not run.

All legs write to ONE findings ledger + heartbeat so the live monitor (run_monitor.py findings --follow) shows
findings landing across every leg. Offline-safe: a leg that errors is logged and the chain continues, so
remediation still runs over whatever was confirmed.

Usage:
    python operator/complete_test.py --role dispatcher --budget 50 --campaign complete-<id> \
        --auth redteam/authorization.local.json --report operator/complete_test_report.md
"""
from __future__ import annotations
import os, sys, json, time, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "shared"))
sys.path.insert(0, os.path.join(ROOT, "redteam"))

from iterative_hunt_live import run_hunt, BASE

_TIER = {"operator": 1, "exploitgym": 2, "redteam": 3}


def _log(msg):
    print(f"[complete-test] {msg}", flush=True)


def _scope_ok(auth_path, base):
    """FAIL-CLOSED authorization gate for the Red-Team leg: the target host must be in the RoE scope."""
    if not auth_path or not os.path.exists(auth_path):
        return False, f"no authorization file ({auth_path}) -- fail-closed, Red-Team leg skipped"
    try:
        from urllib.parse import urlparse
        host = urlparse(base).hostname or ""
        roe = json.load(open(auth_path, encoding="utf-8"))
        hosts = set((roe.get("scope") or {}).get("hosts") or [])
        if host in hosts:
            return True, f"host {host} in RoE scope ({sorted(hosts)})"
        return False, f"host {host} NOT in RoE scope {sorted(hosts)} -- fail-closed"
    except Exception as e:
        return False, f"authorization parse failed ({e}) -- fail-closed"


def _leg(level, *, objective, role, budget, campaign, store, base, extra_seeds=None, roe=None):
    """Run one relay leg via the shared engine at this level/tier, resuming prior confirmed footholds."""
    tier = _TIER[level]
    # Red-Team's deeper escalation budget from the RoE (escalate_frac / max_escalate_steps), env-passed.
    if level == "redteam" and roe:
        rules = roe.get("rules_of_engagement") or {}
        os.environ["AEGIS_ESCALATE_FRAC"] = str(rules.get("escalate_frac", 0.5))
        os.environ["AEGIS_MAX_ESCALATE_STEPS"] = str(rules.get("max_escalate_steps", 8))
    os.environ["AEGIS_AUDIT"] = "1" if level in ("exploitgym", "redteam") else "0"
    # AEGIS board tuning: tag this leg's stage + trust so board_ask.consult selects the stage profile
    # (roster/budget/timeout/quorum/cost-cap) and cost_meter attributes spend per stage.
    os.environ["AEGIS_BOARD_STAGE"] = level
    os.environ["AEGIS_STAGE"] = level
    _r = (role or "").lower().strip()
    os.environ["AEGIS_TRUST"] = ("admin" if _r in ("owner", "admin", "superadmin", "root")
                                 else "anon" if _r in ("", "anon", "anonymous", "guest", "public")
                                 else "user")
    t0 = time.time()
    _log(f"=== LEG {tier} [{level}] start (budget={budget}, resume from prior confirmed footholds) ===")
    try:
        rep = run_hunt(objective, role, budget, store_path=store, base=base,
                       campaign=campaign, level=level, max_tier=tier, extra_seeds=extra_seeds)
    except Exception as e:
        _log(f"LEG {level} ERROR (chain continues): {e}")
        return {"level": level, "tier": tier, "error": str(e), "confirmed": []}
    conf = rep.get("confirmed") or []
    cov = rep.get("coverage", {})
    reach = rep.get("reach", {})
    _log(f"=== LEG {tier} [{level}] done in {time.time()-t0:.0f}s: confirmed={len(conf)} "
         f"coverage={cov.get('n_covered')}/{cov.get('n_total')} "
         f"both_dirs={reach.get('both_directions')} depth={reach.get('depth')} ===")
    return {"level": level, "tier": tier, "report": rep, "confirmed": conf}


def run_complete(*, role="dispatcher", budget=50, campaign=None, base=None,
                 auth_path=None, store=None, objective=None, report_path=None,
                 emit_fixes=True, resume=None):
    base = base or os.environ.get("AEGIS_TARGET", BASE)
    # RESUME: reuse a prior campaign's id so its foothold ledger AND its append-only findings are picked
    # up (legs dedup/resume prior confirmed footholds; remediation can read the prior findings). A fresh
    # run gets a NEW campaign id -> its own directory -> it can never collide with or clobber another run.
    campaign = resume or campaign or f"complete-{int(time.time())}"
    # Per-campaign, APPEND-ONLY findings ledger under campaigns/<id>/ (never rm, never overwrite -- the
    # ledger is hash-chained, so appending is safe and a new campaign is the ONLY way to "start fresh").
    # This fixes the old shortcoming where a shared operator/hunt_findings.jsonl was cleared each run,
    # destroying the prior leg's findings and leaving remediation with nothing to work on.
    camp_dir = os.path.join(HERE, "campaigns", campaign)
    os.makedirs(camp_dir, exist_ok=True)
    store = store or os.path.join(camp_dir, "findings.jsonl")
    report_path = report_path or os.path.join(camp_dir, "complete_test_report.md")
    os.environ["AEGIS_CAMPAIGN"] = campaign
    os.environ["AEGIS_LEDGER"] = store            # so the live monitor follows THIS run's ledger
    objective = objective or ("COMPLETE cross-mode relay test: discover, confirm, then escalate deeper each "
                              "leg. Priorities: money-integrity (credit-note/deposit idempotency + invariant "
                              "+ TOCTOU), rebuilt authorization grid (second-route bypass, response leakage, "
                              "field over-read, settings cross-write, row scoping), supply-chain CVEs. "
                              "Non-destructive: plant, never delete.")
    _log(f"campaign={campaign}  target={base}  role={role}  budget/leg={budget}  ledger={store}")

    # F10: mirror-fidelity preflight -- don't spend budget against an empty/drifted twin (empty tables =
    # blind read-tests; schema drift = 500s + inactive protection). AEGIS_FIDELITY_GATE=off|warn|strict.
    try:
        import mirror_fidelity
        proceed, fv = mirror_fidelity.gate(base)
        _log(f"[F10 fidelity] {'OK' if fv['ok'] else 'GAP'} -- {fv['notes']}")
        if not proceed:
            _log("[F10 fidelity] STRICT gate blocked the run (fix the mirror or set AEGIS_FIDELITY_GATE=warn).")
            return {"campaign": campaign, "report": None, "total_confirmed": 0,
                    "aborted": "mirror-fidelity", "fidelity": fv}
    except Exception as e:
        _log(f"[F10 fidelity] preflight unavailable ({str(e)[:80]}) -- proceeding")

    results = []
    # ---- L1 Operator ----
    results.append(_leg("operator", objective=objective, role=role, budget=budget,
                        campaign=campaign, store=store, base=base))
    # ---- L2 ExploitGym (resume L1) ----
    results.append(_leg("exploitgym", objective=objective, role=role, budget=budget,
                        campaign=campaign, store=store, base=base))
    # ---- L3 Red-Team (resume L1+L2), FAIL-CLOSED ----
    roe = None
    ok, why = _scope_ok(auth_path, base)
    _log(f"Red-Team authorization: {why}")
    if ok:
        try:
            roe = json.load(open(auth_path, encoding="utf-8"))
        except Exception:
            roe = None
        results.append(_leg("redteam", objective=objective, role=role, budget=budget,
                            campaign=campaign, store=store, base=base, roe=roe))
    else:
        results.append({"level": "redteam", "tier": 3, "skipped": why, "confirmed": []})

    # ---- L4 Remediation (board code-fixes over the campaign's confirmed findings) ----
    _log("=== STAGE 4 [remediation] board code-fixes over all verified findings ===")
    os.environ["AEGIS_BOARD_STAGE"] = "remediation"; os.environ["AEGIS_STAGE"] = "remediation"
    # per-campaign (this process writes it, then final_report reads it) -- a shared HERE path let two
    # overlapping campaigns clobber each other's remediation. (runlog/monlog below stay under scratchpad:
    # they are the LIVE run transcript written by the external relay_monitor.sh, not per-campaign here.)
    rem_report = os.path.join(camp_dir, "complete_test_remediation.md")
    rem_cmd = [sys.executable, os.path.join(HERE, "remediation_board.py"),
               "--findings", store, "--panel", "ds,cf,qwen", "--synthesize",
               "--report", rem_report, "--write-ledger"]
    if emit_fixes:
        rem_cmd.append("--emit-fixes")
    try:
        r = subprocess.run(rem_cmd, cwd=ROOT, capture_output=True, text=True, timeout=2400)
        _log(f"remediation exit={r.returncode}; report={rem_report}")
        rem_ok = (r.returncode == 0)
    except Exception as e:
        _log(f"remediation ERROR: {e}")
        rem_ok = False

    # GENERIC report: two-track (ADMIN scaffold/stack + CODE-improver) + severity + trust tiers + coverage +
    # RUN COSTS + suite health. final_report is the canonical format; fall back to the thin writer if it errors.
    try:
        import final_report
        summary = final_report.build(campaign, store, target=base,
                                     remediation_report=(rem_report if rem_ok else None),
                                     runlog=os.path.join(ROOT, "scratchpad", "complete_test.out"),
                                     monlog=os.path.join(ROOT, "scratchpad", "relay_mon2.out"),
                                     out=report_path)
        _log(f"COMPLETE TEST done. report -> {report_path}  ({summary.get('total')} findings: "
             f"{summary.get('admin')} admin / {summary.get('code')} code)")
    except Exception as e:
        _log(f"final_report failed ({e}); using thin fallback")
        summary = _write_report(results, campaign, base, report_path, rem_report if rem_ok else None)
    # Normalize the return so callers/CLI always get these keys regardless of which report path ran:
    # final_report.build()'s summary lacks campaign/total_confirmed, which made the CLI final print raise
    # KeyError('campaign') and exit 1 AFTER a fully-successful run (findings/reports intact). setdefault
    # never clobbers the thin-fallback's own values.
    if not isinstance(summary, dict):
        summary = {}
    summary.setdefault("campaign", campaign)
    summary.setdefault("report", report_path)
    summary.setdefault("total_confirmed", sum(len(r.get("confirmed", [])) for r in results))
    return summary


def _write_report(results, campaign, base, report_path, rem_report):
    lines = [f"# AEGIS Complete Test -- cross-mode relay", "",
             f"_Target **{base}** | campaign `{campaign}` | {time.strftime('%Y-%m-%d %H:%M')}_", "",
             "Four stages across the cross-mode relay: each leg RESUMES the prior legs' oracle-confirmed "
             "footholds from the shared campaign ledger and goes DEEPER. One engine, three modes, one campaign.", ""]
    lines.append("## Relay legs")
    lines.append("")
    lines.append("| Leg | Tier | Status | Confirmed (this leg) | Coverage | Both dirs | Depth |")
    lines.append("|---|---|---|---|---|---|---|")
    total_conf = 0
    for r in results:
        lvl = r["level"]; tier = r["tier"]
        if r.get("skipped"):
            lines.append(f"| {lvl} | {tier} | SKIPPED ({r['skipped'][:40]}) | 0 | - | - | - |")
            continue
        if r.get("error"):
            lines.append(f"| {lvl} | {tier} | ERROR ({r['error'][:40]}) | 0 | - | - | - |")
            continue
        rep = r.get("report", {}); cov = rep.get("coverage", {}); reach = rep.get("reach", {})
        n = len(r.get("confirmed", [])); total_conf += n
        lines.append(f"| {lvl} | {tier} | ok | {n} | {cov.get('n_covered')}/{cov.get('n_total')} "
                     f"| {reach.get('both_directions')} | {reach.get('depth')} |")
    lines.append("")
    lines.append(f"**Total confirmed footholds across the relay: {total_conf}** (deduped in the campaign ledger; "
                 "later legs escalate rather than re-find).")
    lines.append("")
    lines.append("See the tier-grouped findings in `tier_report.md` (run tier_report.py on this ledger) and the "
                 "code recommendations below.")
    lines.append("")
    if rem_report and os.path.exists(rem_report):
        lines.append("## Stage 4 -- Remediation & code recommendations")
        lines.append("")
        lines.append(f"Full two-audience remediation (admin updates + code-writer patches): `{os.path.basename(rem_report)}`")
        lines.append("")
        try:
            rem = open(rem_report, encoding="utf-8").read()
            head = rem[:4000]
            lines.append("<details><summary>remediation report (head)</summary>\n")
            lines.append(head)
            lines.append("\n</details>")
        except Exception:
            pass
    md = "\n".join(lines) + "\n"
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return {"campaign": campaign, "legs": results, "report": report_path,
            "remediation": rem_report, "total_confirmed": total_conf}


def smoke():
    """OFFLINE oracle preflight -- no network, no keys, no WSL, no board. Exercises the FP-resistant
    verdict logic of the two access-control oracles (AuthzOracle mutation-awareness, IdorOracle per-object
    intended-roles) plus the ledger hash-chain, through the PRODUCTION import path (verified_findings shim).
    Run it before committing a box to the heavy relay: `python operator/complete_test.py --smoke`.
    Returns True iff every assertion holds. Cheap enough for a memory-starved box."""
    import verified_findings as vf   # production shim -> canonical shared/verified_findings.py
    checks = []
    def ok(name, cond):
        checks.append(bool(cond)); print(("PASS" if cond else "FAIL"), "-", name, flush=True)

    class _Resp:
        def __init__(self, s, t=""): self.status_code = s; self.text = t
    class _Sess:
        def __init__(self, s, t=""): self._s, self._t = s, t
        def request(self, method, url, **kw): return _Resp(self._s, self._t)
    def _sessions(tested, baseline):
        return lambda role: _Sess(tested) if role == "dispatcher" else _Sess(baseline)

    ok("verified_findings imports (Authz+Idor present)",
       hasattr(vf, "AuthzOracle") and hasattr(vf, "IdorOracle"))

    # AuthzOracle -- mutation-awareness on WRITE methods
    st, rc = vf.AuthzOracle("http://x", "POST", "/api/invoices", "dispatcher", "viewer",
                            _sessions(409, 403)).check(None)
    ok("WRITE 409 vs baseline 403 -> verified (mutation-aware)",
       st == "verified" and rc.get("via") == "business-conflict")
    st, _ = vf.AuthzOracle("http://x", "POST", "/api/invoices", "dispatcher", "viewer",
                           _sessions(400, 403)).check(None)
    ok("WRITE 400 excluded from conflict -> rejected", st == "rejected")
    st, _ = vf.AuthzOracle("http://x", "GET", "/api/invoices", "dispatcher", "viewer",
                           _sessions(409, 403)).check(None)
    ok("GET 409 not treated as conflict -> rejected", st == "rejected")
    st, rc = vf.AuthzOracle("http://x", "POST", "/api/invoices/new", "dispatcher", "viewer",
                            _sessions(409, 403), intended_roles={"/api/invoices/*": ["dispatcher"]}).check(None)
    ok("per-surface intended_roles excuses the intended role",
       st == "rejected" and "intended-privileged" in rc.get("note", ""))
    st, _ = vf.AuthzOracle("http://x", "POST", "/api/settings", "dispatcher", "viewer",
                           _sessions(409, 403), intended_roles={"/api/invoices/*": ["dispatcher"]}).check(None)
    ok("intended map scoped per-surface (other surface NOT excused)", st == "verified")

    # IdorOracle -- object-level intended allow-map (fully offline)
    obs = [{"id": "job-1", "role": "dispatcher", "owner_status": 200, "attacker_status": 200,
            "owner_sha": "abc", "attacker_sha": "abc", "control_status": 404}]
    st, rc = vf.IdorOracle(obs).check(None)
    ok("clear IDOR (same object, control denied) -> verified", st == "verified" and rc["n_leads"] == 1)
    st, rc = vf.IdorOracle(obs, intended={"job-1": ["dispatcher"]}).check(None)
    ok("per-object intended map skips owned object", st == "rejected" and rc["intended_skipped"] == 1)
    st, rc = vf.IdorOracle([dict(obs[0], intended_roles=["dispatcher"])]).check(None)
    ok("per-observation intended_roles honoured", st == "rejected" and rc["intended_skipped"] == 1)

    # ledger append + hash-chain integrity
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), f"aegis_smoke_{os.getpid()}.jsonl")
    try:
        if os.path.exists(tmp): os.remove(tmp)
        store = vf.FindingStore(tmp)
        store.record_candidate(vf.Finding(claim_type="test.smoke", summary="smoke",
                                          severity="low", oracle_id="t@1"))
        ok("ledger append + hash-chain verifies", store.verify_chain())
    finally:
        if os.path.exists(tmp): os.remove(tmp)

    passed = sum(checks)
    print(f"\n=== SMOKE: {passed}/{len(checks)} passed ===", flush=True)
    return passed == len(checks)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="AEGIS complete test -- 4-stage cross-mode relay")
    ap.add_argument("--smoke", action="store_true",
                    help="OFFLINE oracle preflight only (no network/keys/WSL/board); exits 0 if all pass")
    ap.add_argument("--role", default="dispatcher")
    ap.add_argument("--budget", type=int, default=50, help="budget PER LEG")
    ap.add_argument("--campaign", default=None)
    ap.add_argument("--resume", default=None,
                    help="resume a prior campaign id: reuse its append-only findings + foothold ledger "
                         "(continue/remediate a prior run) instead of starting a fresh campaign.")
    ap.add_argument("--target", default=None)
    ap.add_argument("--auth", default=os.path.join(ROOT, "redteam", "authorization.local.json"),
                    help="Red-Team Rules-of-Engagement (fail-closed; leg skipped if target not in scope)")
    ap.add_argument("--store", default=None)
    ap.add_argument("--report", default=None)
    ap.add_argument("--no-fixes", action="store_true", help="skip --emit-fixes in remediation")
    a = ap.parse_args()
    if a.smoke:
        sys.exit(0 if smoke() else 1)
    out = run_complete(role=a.role, budget=a.budget, campaign=a.campaign, base=a.target,
                       auth_path=a.auth, store=a.store, report_path=a.report, emit_fixes=not a.no_fixes,
                       resume=a.resume)
    print(json.dumps({"campaign": out.get("campaign"), "total_confirmed": out.get("total_confirmed"),
                      "report": out.get("report")}, indent=2, default=str))
    print("COMPLETE TEST EXIT: 0")


if __name__ == "__main__":
    main()
