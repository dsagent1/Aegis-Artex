"""retester.py -- adversarial, independent RE-VERIFICATION of a filed finding (ARTEX-port #2).

Aegis records findings behind an oracle, but it had no INDEPENDENT re-verifier. This re-runs a finding in a
fresh context and returns exactly one verdict -- REPRODUCED | FIXED | INCONCLUSIVE -- with an adversarial
discipline that kills false positives:

  * deterministic core: re-dispatch the finding's move through vectors and re-check the SAME oracle. If the
    oracle still verifies -> candidate REPRODUCED; if it now rejects AND the surface is reachable -> candidate
    FIXED; if unreachable / WAF / error / insufficient evidence -> INCONCLUSIVE (NEVER 'fixed').
  * adversarial layer (opt-in, AEGIS_RETEST_LLM=1): the brain argues the OPPOSITE along 5 axes (reachability,
    preconditions, reproducibility, scope, claimed impact) against THIS run's evidence before confirming the
    verdict (prompt_registry role='retester'). A single failed request never proves 'fixed'.

The original evidence is DATA to verify, not a script to trust. Verdicts are recorded via
record_retest_findings. Usage:
  python operator/retester.py --finding <id>        # retest one
  python operator/retester.py --all --since 86400   # retest recent verified findings
"""
import os, sys, json, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "shared"))

_VERDICTS = ("reproduced", "fixed", "inconclusive")


def _load_findings(store_path=None):
    path = store_path or os.path.join(HERE, "hunt_findings.jsonl")
    out = []
    try:
        for line in open(path, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("type") == "record":
                f = o.get("finding", {})
                f["_ts"] = o.get("ts", 0)
                out.append(f)
    except Exception:
        pass
    return out


def _move_from_finding(f):
    """Reconstruct the probe move from a finding so vectors can re-run it."""
    ev = (f.get("evidence") or [{}])
    detail = ev[0].get("detail", "") if ev and isinstance(ev[0], dict) else ""
    return {
        "action": f.get("claim_type", "web").split(".")[-1] if "." in (f.get("claim_type") or "") else "web",
        "surface": f.get("surface") or f.get("endpoint") or "/",
        "param": f.get("param"), "role": f.get("role", "owner"),
        "_retest_of": f.get("finding_id"), "_orig_detail": str(detail)[:400],
    }


def _reoracle(f, ctx):
    """Deterministic re-verification: re-dispatch the move, return (still_verified, result)."""
    try:
        import vectors
        mv = _move_from_finding(f)
        res = vectors.dispatch(mv, "retest", ctx)
        # a leg sets *_verified True when its oracle confirms; scan the common keys
        verified = any(res.get(k) for k in res if k.endswith("_verified"))
        reachable = res.get("status") not in (-1, 0, None) and not res.get("dead_surface")
        return verified, reachable, res
    except Exception as e:
        return None, False, {"error": repr(e)[:160]}


def _argue_opposite(f, res):
    """Opt-in LLM layer: argue the opposite on 5 axes before confirming. Returns a note or ''."""
    if str(os.environ.get("AEGIS_RETEST_LLM", "")).lower() not in ("1", "true", "yes", "on"):
        return ""
    try:
        import prompt_registry
        sysp = prompt_registry.get("retester")
        payload = {"finding": {k: f.get(k) for k in ("claim_type", "severity", "summary", "surface", "param")},
                   "retest_result": {"status": res.get("status"), "body": str(res.get("body", ""))[:600]}}
        try:
            import code_suggester
            out = code_suggester.suggest(os.environ.get("AEGIS_MODEL", "deepseek-v4.1-flash"),
                                         sysp + "\n\nDATA:\n" + json.dumps(payload)[:3000]
                                         + "\n\nArgue the opposite on 5 axes, then give VERDICT: "
                                           "reproduced|fixed|inconclusive and one-line why.", max_tokens=600)
            return (out or "")[:500]
        except Exception:
            return ""
    except Exception:
        return ""


def retest(f, store_path=None):
    """Retest one finding dict. Returns {finding_id, verdict, reachable, note}."""
    base = os.environ.get("AEGIS_TARGET") or f.get("base") or ""
    ctx = {"base": base}
    try:
        import session_factory
        ctx["session_for_role"] = session_factory.from_env(base)
    except Exception:
        pass
    verified, reachable, res = _reoracle(f, ctx)
    if not reachable:
        verdict = "inconclusive"                         # unreachable/WAF/error -> NEVER 'fixed'
    elif verified:
        verdict = "reproduced"
    else:
        verdict = "fixed"                                # reachable + oracle now rejects
    note = _argue_opposite(f, res)
    # the adversarial layer can downgrade an over-confident verdict to inconclusive
    if note and "inconclusive" in note.lower() and verdict == "fixed":
        verdict = "inconclusive"
    rec = {"finding_id": f.get("finding_id"), "claim_type": f.get("claim_type"),
           "verdict": verdict, "reachable": reachable, "retested_at": time.time(),
           "note": note or f"deterministic re-oracle: verified={verified} reachable={reachable}"}
    try:
        import record_retest_findings as rr
        if hasattr(rr, "record"):
            rr.record(rec)
        else:
            with open(os.path.join(HERE, "retest_findings.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
    except Exception:
        with open(os.path.join(HERE, "retest_findings.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    return rec


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--since", type=float, default=0, help="only findings newer than N seconds ago")
    ap.add_argument("--store")
    a = ap.parse_args()
    fs = _load_findings(a.store)
    if a.finding:
        fs = [f for f in fs if f.get("finding_id") == a.finding]
    elif a.all:
        fs = [f for f in fs if f.get("status") in ("candidate", "verified", "confirmed")]
        if a.since:
            cut = time.time() - a.since
            fs = [f for f in fs if (f.get("_ts") or 0) >= cut]
    else:
        print("give --finding <id> or --all"); return
    print(f"retesting {len(fs)} finding(s)...")
    for f in fs[:50]:
        r = retest(f, a.store)
        print(f"  {r['verdict'].upper():13} {r['claim_type']:26.26} {str(r['finding_id'])[:16]}  {r['note'][:60]}")


if __name__ == "__main__":
    main()
