"""
synthesize_techniques.py -- STEP 5 / A2 of the corpus+chaining roadmap (board-locked: DEFERRED/OPTIONAL,
gated on the STEP 0 measurement gate). Mechanically MANUFACTURES runnable technique entries from the RAG
store's DETERMINISTIC CVE mappings -- the answer to Pentera/NodeZero's curated TTP inventory, but derived
from feeds we already pull, with zero hand-authoring.

Board guardrails, enforced here:
  * DETERMINISTIC mappings ONLY -- a CVE is synthesized iff it has a nuclei template (nuclei names CVE
    templates by their CVE-id, so template-id == CVE-id) OR an MSF module (stored as `MSF: <module>` in
    vulns.refs by ingest_msf). No fuzzy guessing.
  * PoC-GitHub / Exploit-DB-only CVEs are NOT auto-added -- they are QUEUED for the code bench to turn
    into a probe on demand (a human/oracle stays in the loop for those).
  * PRIORITIZE by KEV first, then high EPSS, SCOPED to the fingerprinted stack.
  * GATED on STEP 0: if the measurement gate says the wiring thesis already HOLDS (coverage >= HOLD),
    synthesis is low marginal value and is skipped unless --force. It runs when the gate says
    'wiring_plus_synthesis' (the 40-70% band) -- exactly the case it was designed for.
  * Output is a CANDIDATE file (rag/synthesized_techniques.json), NEVER merged into learned_techniques
    without a validation pass (>=80% precision on a held-out set -- see validate()).

Each emitted entry matches the techniques_db schema (id/class/desc/how_to_test/kali_tools/new_code/oracle
/applies_to/severity_hint) AND carries a loop-ready `seed_move` (action nuclei|msf) so the planner can run
it directly.

Usage:
  python rag/synthesize_techniques.py --stack node,express --json
  python rag/synthesize_techniques.py --target https://localhost:8443 --force --out rag/synthesized_techniques.json
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_REPO, "operator")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_MSF_RE = re.compile(r"MSF:\s*(\S+)")


def _sev_from(severity, cvss):
    s = (severity or "").lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    try:
        c = float(cvss)
        return "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"
    except Exception:
        return "medium"


def synthesize(target=None, stack_csv=None, db_path=None, limit=200, force=False, run_gate=True):
    # reuse the STEP 0 gate for the stack fingerprint, prioritization and the go/skip decision
    import measure_gate as MG
    stack = MG._fingerprint_stack(target, stack_csv)
    out = {"stack": stack, "techniques": [], "poc_queue": [], "counts": {}}
    if not stack:
        out["decision"] = "no_stack"
        return out

    gate = None
    if run_gate:
        gate = MG.measure(target=target, stack_csv=",".join(stack), db_path=db_path)
        out["gate_decision"] = gate.get("decision")
        if gate.get("decision") == "wiring_thesis_holds" and not force:
            out["decision"] = "skipped_gate"
            out["note"] = ("STEP 0 says the wiring thesis holds (coverage %.0f%%); synthesis is low "
                           "marginal value. Re-run with --force to synthesize anyway."
                           % ((gate.get("coverage") or 0) * 100))
            return out

    try:
        import rag_db
    except Exception as e:
        out["decision"] = "db_unavailable"; out["note"] = str(e); return out
    path = db_path or rag_db.DEFAULT_DB
    if not os.path.exists(path):
        out["decision"] = "db_unavailable"; out["db_path"] = path
        out["note"] = "RAG store not found at %s" % path
        return out
    conn = rag_db.connect(path)

    ftsq = MG._fts_query(stack)
    rows = conn.execute(
        "SELECT v.cve_id, v.source, v.refs, v.title, v.description, v.severity, v.cvss_v3, "
        "v.kev, v.epss, v.epss_pctl, v.exploitdb_ids "
        "FROM vulns v JOIN vulns_fts f ON v.cve_id=f.cve_id "
        "WHERE vulns_fts MATCH ? AND v.cve_id LIKE 'CVE-%'", (ftsq,)).fetchall()

    n_nuclei = n_msf = n_poc = 0
    seen = set()
    # PRIORITIZE: KEV first, then EPSS percentile desc.
    def _prio(r):
        kev, epss, pctl = r[7], r[8], r[9]
        return (1 if kev else 0, pctl or 0.0, epss or 0.0)
    for r in sorted(rows, key=_prio, reverse=True):
        (cve, source, refs, title, desc, sev, cvss, kev, epss, pctl, edb) = r
        is_kev = bool(kev)
        hi = ((pctl is not None and pctl >= MG.EPSS_PCTL_MIN) or (epss is not None and epss >= MG.EPSS_RAW_MIN))
        if not (is_kev or hi):
            continue
        src = (source or "").lower()
        severity = _sev_from(sev, cvss)
        made = False
        # --- deterministic map #1: nuclei template (template-id == CVE-id) ---
        if "nuclei" in src and cve not in seen:
            out["techniques"].append({
                "id": "synth.nuclei." + cve, "class": "KnownVuln", "cve": cve,
                "desc": (title or desc or cve)[:300], "severity_hint": severity,
                "how_to_test": "nuclei -id %s (template == CVE); a match is a LEAD, confirm with an "
                               "independent oracle" % cve,
                "kali_tools": ["nuclei -id %s" % cve], "new_code": [], "applies_to": stack,
                "oracle": "nuclei match (confirmation #1) -> 2nd independent oracle for a finding",
                "source": src, "kev": is_kev, "epss_pctl": pctl,
                "seed_move": {"action": "nuclei", "template_ids": [cve], "severity": "medium,high,critical",
                              "vuln_class": "known-vuln", "technique": "nuclei-cve", "why_novel":
                              "deterministic CVE->nuclei template (synthesized)"}})
            n_nuclei += 1; seen.add(cve); made = True
        # --- deterministic map #2: MSF module (from refs "MSF: <module>") ---
        mods = _MSF_RE.findall(refs or "")
        if mods and cve not in seen:
            module = mods[0]
            out["techniques"].append({
                "id": "synth.msf." + cve, "class": "KnownVuln", "cve": cve,
                "desc": (title or desc or cve)[:300], "severity_hint": severity,
                "how_to_test": "msf %s -> check (proof-only, no payload); a positive is a LEAD" % module,
                "kali_tools": ["msfconsole: use %s; check" % module], "new_code": [], "applies_to": stack,
                "oracle": "msf check/scanner positive (confirmation #1) -> 2nd independent oracle",
                "source": src, "module": module, "kev": is_kev, "epss_pctl": pctl,
                "seed_move": {"action": "msf", "module": module, "vuln_class": "known-vuln",
                              "technique": "msf-cve", "why_novel":
                              "deterministic CVE->MSF module (synthesized)"}})
            n_msf += 1; seen.add(cve); made = True
        # --- PoC-only: NOT synthesized -> queued for the code bench (human/oracle in the loop) ---
        if not made and (("poc-github" in src) or ("exploitdb" in src) or (edb or "").strip()):
            out["poc_queue"].append({"cve": cve, "desc": (title or "")[:160], "severity": severity,
                                     "kev": is_kev, "source": src, "exploitdb_ids": edb})
            n_poc += 1

    out["counts"] = {"nuclei": n_nuclei, "msf": n_msf, "poc_queued": n_poc,
                     "techniques": len(out["techniques"])}
    out["decision"] = "synthesized"
    out["note"] = ("CANDIDATE techniques -- NOT merged into learned_techniques. Validate (>=80%% precision) "
                   "before live use. %d PoC-only CVEs queued for the code bench." % n_poc)
    return out


def validate(synth_path, sample=None):
    """Validation-gate scaffold: a synthesized entry is 'sound' iff its deterministic mapping is real
    (nuclei template id == a CVE id, or an MSF module path shape). This is the CHEAP structural precision
    check; the LIVE precision check (does the template/module actually fire on a known-vulnerable mirror)
    is a run-time measurement recorded by the loop's lead->confirmed telemetry. Returns precision + a
    verdict vs the >=0.80 bar."""
    with open(synth_path, encoding="utf-8") as fh:
        data = json.load(fh)
    techs = data.get("techniques") or []
    if sample:
        techs = techs[:int(sample)]
    ok = 0
    for t in techs:
        cve = t.get("cve") or ""
        if t.get("id", "").startswith("synth.nuclei.") and re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            ok += 1
        elif t.get("id", "").startswith("synth.msf.") and re.match(r"(exploit|auxiliary)/", t.get("module", "")):
            ok += 1
    precision = round(ok / len(techs), 3) if techs else None
    return {"checked": len(techs), "sound": ok, "precision": precision,
            "passes_gate": (precision is not None and precision >= 0.80),
            "bar": 0.80, "note": "structural precision; live precision = loop lead->confirmed telemetry"}


def main():
    ap = argparse.ArgumentParser(description="A2 RAG->techniques synthesizer (deterministic, gated)")
    ap.add_argument("--target"); ap.add_argument("--stack"); ap.add_argument("--db")
    ap.add_argument("--out", default=os.path.join(_HERE, "synthesized_techniques.json"))
    ap.add_argument("--force", action="store_true", help="synthesize even if STEP 0 says wiring holds")
    ap.add_argument("--no-gate", action="store_true", help="skip the STEP 0 gate check")
    ap.add_argument("--validate", metavar="PATH", help="validate an existing synthesized file and exit")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.validate:
        print(json.dumps(validate(a.validate), indent=2)); return 0
    res = synthesize(target=a.target, stack_csv=a.stack, db_path=a.db,
                     force=a.force, run_gate=not a.no_gate)
    if res.get("decision") == "synthesized":
        try:
            with open(a.out, "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=2)
            res["written"] = a.out
        except Exception as e:
            res["write_error"] = str(e)
    if a.json:
        print(json.dumps(res, indent=2, default=str))
    else:
        print("decision:", res.get("decision"), "| counts:", res.get("counts"),
              "| note:", res.get("note", ""))
        if res.get("written"):
            print("written:", res["written"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
