"""
measure_gate.py -- STEP 0 of the corpus+chaining improvement roadmap (board-locked): the PRE-BUILD
MEASUREMENT GATE that decides whether the "wiring-not-corpus" thesis actually holds for THIS target
class before we invest in wiring nuclei/MSF as first-class loop vectors.

The thesis (from the 3-round board review): for a single internet-exposed app server, the exploit
corpus gap vs NodeZero/Pentera is mostly a WIRING gap -- the catalogs we already have access to
(nuclei ~10k templates, MSF ~2400 modules, the RAG feeds) just aren't parsed into structured loop
signal. This gate MEASURES that claim instead of assuming it.

What it computes (all offline, from the local RAG store's `vulns` table):
  1. RELEVANCE: fingerprint the stack (planner recon, or --stack), FTS-match stack-relevant CVEs.
  2. PRIORITIZATION: of those, the KEV + high-EPSS subset (what an attacker actually reaches for).
  3. COVERAGE (the decision number): of the prioritized set, the fraction that have a RUNNABLE path
     -- a nuclei template OR an MSF module OR an Exploit-DB / PoC-GitHub entry in `source`.
  4. nuclei-template relevance ratio (sanity: relevant/total nuclei rows).
  5. lead->oracle-confirmed CONVERSION baseline (telemetry): read from a findings ledger if present.

Decision rule (thresholds are TRIPWIRES, tune with data -- not truth; board consensus):
    coverage >= HOLD (default 0.70)     -> wiring thesis HOLDS; wire nuclei/MSF, skip A2 synthesizer.
    PIVOT (0.40) <= coverage < HOLD     -> wiring + TARGETED synthesis (build A2 to close the gap).
    coverage < PIVOT (default 0.40)     -> genuine CORPUS-ACQUISITION gap; escalate to code-bench-first.

Offline-safe: a missing/empty RAG DB never raises -- it reports db_unavailable and exits 0 (this is a
measurement, it must never block). Run it wherever the DB lives (default /opt/aegis-rag/ragl.sqlite on
Kali; point AEGIS_RAG_DB at a local copy to run on the host).

Usage:
  python operator/measure_gate.py --target https://localhost:8443
  python operator/measure_gate.py --stack node,express,postgres,nginx
  python operator/measure_gate.py --stack php,wordpress --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# --- import the RAG DB helpers + planner from the repo (offline-safe path wiring) ---
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for _p in (os.path.join(_REPO, "rag"), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# High-EPSS default: percentile >= 0.90 (top-decile exploit probability) OR raw epss >= 0.10.
EPSS_PCTL_MIN = float(os.environ.get("AEGIS_GATE_EPSS_PCTL", "0.90"))
EPSS_RAW_MIN = float(os.environ.get("AEGIS_GATE_EPSS_RAW", "0.10"))
HOLD = float(os.environ.get("AEGIS_GATE_HOLD", "0.70"))     # >= this: wiring thesis holds
PIVOT = float(os.environ.get("AEGIS_GATE_PIVOT", "0.40"))   # < this: corpus-acquisition gap

# sources in `vulns.source` that mean "a runnable check/exploit path exists for this CVE"
_DETERMINISTIC = ("nuclei", "msf")                 # directly wireable, structured-output
_SYNTHESIZABLE = ("exploitdb", "poc-github")       # a PoC seed the code bench can turn into a probe


def _fingerprint_stack(target: str | None, stack_csv: str | None) -> list:
    """Merge an explicit --stack with planner recon of a live --target. Fail-safe -> [] on any error."""
    terms = set()
    for t in (stack_csv or "").split(","):
        t = t.strip().lower()
        if t:
            terms.add(t)
    if target:
        try:
            from planner import Planner  # reuse the live-recon stack detector (no duplication)
            terms.update(Planner()._detect_stack(target))
        except Exception:
            pass
    return sorted(terms)


def _fts_query(terms: list) -> str:
    """FTS5 OR-query over the stack terms. Quote each to survive punctuation (e.g. 'asp.net')."""
    safe = []
    for t in terms:
        t = t.replace('"', " ").strip()
        if t:
            safe.append('"%s"' % t)
    return " OR ".join(safe)


def _covered(source: str, exploitdb_ids: str) -> str | None:
    """Classify a CVE's runnable-path coverage: 'deterministic' | 'synthesizable' | None."""
    src = (source or "").lower()
    if any(k in src for k in _DETERMINISTIC):
        return "deterministic"
    if any(k in src for k in _SYNTHESIZABLE) or (exploitdb_ids or "").strip():
        return "synthesizable"
    return None


def _conversion_baseline() -> dict:
    """lead->oracle-confirmed conversion telemetry. Reads a findings ledger if one is present; else
    reports 'requires a run'. Kept best-effort so the gate stays a pure static measurement."""
    for cand in (os.environ.get("AEGIS_FINDINGS_LEDGER"),
                 os.path.join(_HERE, "findings.jsonl"),
                 os.path.join(_HERE, "verified_findings.jsonl")):
        if cand and os.path.exists(cand):
            leads = confirmed = 0
            try:
                with open(cand, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except Exception:
                            continue
                        leads += 1
                        v = str(rec.get("verdict") or rec.get("status") or "").lower()
                        if rec.get("verified") is True or v in ("verified", "confirmed", "pass"):
                            confirmed += 1
            except Exception:
                continue
            rate = round(confirmed / leads, 3) if leads else None
            return {"source": os.path.basename(cand), "leads": leads,
                    "confirmed": confirmed, "conversion": rate}
    return {"source": None, "note": "requires a run (no findings ledger yet)"}


def measure(target=None, stack_csv=None, db_path=None) -> dict:
    stack = _fingerprint_stack(target, stack_csv)
    out = {"stack": stack, "thresholds": {"hold": HOLD, "pivot": PIVOT,
           "epss_pctl_min": EPSS_PCTL_MIN, "epss_raw_min": EPSS_RAW_MIN}}
    if not stack:
        out["decision"] = "no_stack"
        out["note"] = "no stack fingerprinted -- pass --stack or a reachable --target"
        return out

    try:
        import rag_db
    except Exception as e:
        out["decision"] = "db_unavailable"
        out["note"] = "rag_db import failed: %s" % e
        return out

    path = db_path or rag_db.DEFAULT_DB
    if not os.path.exists(path):
        out["decision"] = "db_unavailable"
        out["db_path"] = path
        out["note"] = ("RAG store not found. Run this where the DB lives (Kali: %s) or point "
                       "AEGIS_RAG_DB at a local copy." % rag_db.DEFAULT_DB)
        return out

    try:
        conn = rag_db.connect(path)
    except Exception as e:
        out["decision"] = "db_unavailable"
        out["note"] = "connect failed: %s" % e
        return out

    out["db_path"] = path
    try:
        out["store"] = rag_db.stats(conn)
    except Exception:
        out["store"] = {}

    ftsq = _fts_query(stack)
    try:
        rows = conn.execute(
            "SELECT v.cve_id, v.source, v.exploitdb_ids, v.kev, v.epss, v.epss_pctl, v.severity "
            "FROM vulns v JOIN vulns_fts f ON v.cve_id = f.cve_id "
            "WHERE vulns_fts MATCH ? AND v.cve_id LIKE 'CVE-%'",
            (ftsq,)).fetchall()
    except Exception as e:
        out["decision"] = "query_error"
        out["note"] = "FTS query failed: %s (q=%r)" % (e, ftsq)
        return out

    relevant = len(rows)
    # PRIORITIZE: KEV, or high-EPSS (percentile or raw). This is what an attacker actually reaches for.
    prioritized = []
    nuclei_relevant = 0
    for cve_id, source, edb, kev, epss, pctl, sev in rows:
        if "nuclei" in (source or "").lower():
            nuclei_relevant += 1
        is_kev = bool(kev)
        hi_epss = ((pctl is not None and pctl >= EPSS_PCTL_MIN) or
                   (epss is not None and epss >= EPSS_RAW_MIN))
        if is_kev or hi_epss:
            prioritized.append((cve_id, source, edb, is_kev))

    det = synth = 0
    uncovered_examples = []
    for cve_id, source, edb, is_kev in prioritized:
        cov = _covered(source, edb)
        if cov == "deterministic":
            det += 1
        elif cov == "synthesizable":
            synth += 1
        elif len(uncovered_examples) < 10:
            uncovered_examples.append({"cve": cve_id, "kev": is_kev, "source": source})

    n_prior = len(prioritized)
    covered_total = det + synth
    coverage = round(covered_total / n_prior, 3) if n_prior else None
    det_ratio = round(det / n_prior, 3) if n_prior else None

    out["relevant_cves"] = relevant
    out["prioritized_cves"] = n_prior          # KEV + high-EPSS, stack-relevant
    out["covered"] = {"deterministic": det, "synthesizable": synth, "total": covered_total}
    out["coverage"] = coverage                 # THE decision number
    out["deterministic_ratio"] = det_ratio     # fraction reachable with zero synthesis (pure wiring)
    out["nuclei_template_relevance"] = (
        round(nuclei_relevant / relevant, 3) if relevant else None)   # sanity, not decision
    out["uncovered_examples"] = uncovered_examples
    out["conversion_baseline"] = _conversion_baseline()

    # DECISION
    if n_prior == 0:
        out["decision"] = "insufficient_data"
        out["note"] = ("no KEV/high-EPSS CVEs matched the stack -- refresh the RAG feeds "
                       "(AEGIS_RAG_ONLINE=1) or widen --stack; cannot judge the thesis yet.")
    elif coverage >= HOLD:
        out["decision"] = "wiring_thesis_holds"
        out["recommendation"] = ("Wire nuclei + MSF as first-class vectors (STEP 2 / STEP 4). "
                                 "A2 auto-synthesizer is LOW marginal value -- defer it.")
    elif coverage >= PIVOT:
        out["decision"] = "wiring_plus_synthesis"
        out["recommendation"] = ("Wire nuclei + MSF, AND build the A2 auto-synthesizer to close the "
                                 "measured %d%%-gap on prioritized CVEs." % round((1 - coverage) * 100))
    else:
        out["decision"] = "corpus_acquisition_gap"
        out["recommendation"] = ("Thesis does NOT hold for this class -- escalate to code-bench-first "
                                 "novel-exploit synthesis; wiring alone won't reach parity.")
    return out


def _fmt(res: dict) -> str:
    lines = ["=== STEP 0 measurement gate ===",
             "stack: " + (", ".join(res.get("stack") or []) or "(none)")]
    dec = res.get("decision", "?")
    if res.get("coverage") is not None:
        lines.append("relevant CVEs: %s | prioritized (KEV+high-EPSS): %s"
                     % (res.get("relevant_cves"), res.get("prioritized_cves")))
        cov = res.get("covered", {})
        lines.append("covered: %s deterministic (nuclei/MSF) + %s synthesizable (PoC) = %s%% coverage, "
                     "%s%% deterministic-only"
                     % (cov.get("deterministic"), cov.get("synthesizable"),
                        round((res["coverage"] or 0) * 100), round((res.get("deterministic_ratio") or 0) * 100)))
        conv = res.get("conversion_baseline", {})
        lines.append("lead->confirmed conversion: %s"
                     % (conv.get("conversion") if conv.get("conversion") is not None else conv.get("note")))
    lines.append("DECISION: %s" % dec.upper())
    if res.get("recommendation"):
        lines.append("-> " + res["recommendation"])
    if res.get("note"):
        lines.append("note: " + res["note"])
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="STEP 0 pre-build measurement gate (wiring-not-corpus test)")
    ap.add_argument("--target", help="live target URL (planner recon fingerprints the stack)")
    ap.add_argument("--stack", help="explicit CSV stack terms, e.g. node,express,postgres")
    ap.add_argument("--db", help="RAG sqlite path (default AEGIS_RAG_DB or /opt/aegis-rag/ragl.sqlite)")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    a = ap.parse_args()
    res = measure(target=a.target, stack_csv=a.stack, db_path=a.db)
    if a.json:
        print(json.dumps(res, indent=2, default=str))
    else:
        print(_fmt(res))
    # NEVER block: a measurement gate always exits 0 (the DECISION field carries the verdict).
    return 0


if __name__ == "__main__":
    sys.exit(main())
