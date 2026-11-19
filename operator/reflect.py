"""reflect.py -- #6 Reflective self-verification (Red-MIRROR-style). ADVISORY, never a gate.

For a VERIFIED finding, a cheap board pass ADVERSARIALLY argues it might be a FALSE POSITIVE -- misread
status, an SPA/catch-all 200 shell, INTENDED behavior for that role, a transient state artifact, a
deceptive/honeypot response, or an oracle that proved the wrong thing -- judging ONLY from the finding +
its oracle receipt + bound evidence. The oracle stays ground truth; this never changes status/evidence,
it just LOWERS the finding's confidence (#2) and flags high-risk findings for human review.

Verdict: {fp_risk: low|medium|high, reasons:[...], recommend: accept|review}. Env gate: AEGIS_REFLECT.
CLI:  python operator/reflect.py --store f.jsonl [--id <fid>]
"""
from __future__ import annotations
import os, sys, json, argparse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "shared")); sys.path.insert(0, HERE)
from verified_findings import FindingStore  # noqa: E402

VALID_FP_RISK = {"low", "medium", "high"}


def _board(sysp: str, user: str, max_tokens: int = 700) -> str:
    """One cheap OpenAI-compatible call (same path the planner's board uses)."""
    try:
        import remediation_board as RB
        ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
        return RB._post_openai_style(ep + "/chat/completions", os.environ.get("AEGIS_LLM_API_KEY", ""),
                                     os.environ.get("AEGIS_BOARD_MODEL", "deepseek-v4-flash"),
                                     sysp, user, max_tokens, think=False) or ""
    except Exception:
        return ""


def _brief(f: dict) -> dict:
    """A compact, de-noised view of the finding for the reflector (no secret dumps)."""
    rc = f.get("oracle_receipt") or {}
    be = [{"role": e.get("role"), "method": e.get("method"), "url": e.get("url"), "status": e.get("status")}
          for e in (f.get("bound_evidence") or [])]
    surface = next((str(t).split(":", 1)[1] for t in (f.get("coverage_tags") or [])
                    if str(t).startswith("surface:")), "")
    keep = ("status_code", "tested_status", "baseline_status", "over_reach", "note", "spa_fallback", "via")
    return {"claim_type": f.get("claim_type"), "summary": (f.get("summary") or "")[:300],
            "severity": f.get("severity"), "surface": surface, "oracle_id": f.get("oracle_id"),
            "confirmations": f.get("confirmations"), "poe": f.get("poe"),
            "receipt": {k: rc.get(k) for k in keep if k in rc}, "bound_evidence": be}


def reflect_finding(store: FindingStore, finding_id: str, *, record: bool = True) -> dict:
    f = store.findings().get(finding_id)
    if f is None:
        raise KeyError(f"no finding {finding_id!r} in {store.path}")
    if f.get("status") != "verified":
        return {"fp_risk": "low", "reasons": ["not a verified finding"], "recommend": "accept", "skipped": True}
    sysp = ("You are an adversarial REVIEWER on an authorized, contained security assessment. A finding was "
            "marked VERIFIED by an automated oracle. Your job: argue, as hard as the evidence allows, that it "
            "could be a FALSE POSITIVE -- misread status, an SPA/catch-all 200 shell, INTENDED behavior for "
            "that role, a transient state artifact, a deceptive/honeypot response, or an oracle that proved "
            "the wrong thing. Judge ONLY from the finding + receipt + bound evidence given; do NOT invent "
            "facts. Output ONLY JSON: {\"fp_risk\":\"low|medium|high\",\"reasons\":[\"..\"],\"recommend\":"
            "\"accept|review\"}. 'high' = a credible concrete FP path exists; 'low' = the evidence is solid. "
            "No prose, no fenced block.")
    raw = _board(sysp, json.dumps(_brief(f))[:6000])
    verdict = {"fp_risk": "low", "reasons": ["reflector returned no parseable verdict"], "recommend": "accept"}
    try:
        i, j = raw.find("{"), raw.rfind("}")
        v = json.loads(raw[i:j + 1]) if i >= 0 and j > i else {}
        if isinstance(v, dict) and v:
            fr = str(v.get("fp_risk", "low")).lower()
            rec = str(v.get("recommend", "")).lower()
            verdict = {"fp_risk": fr if fr in VALID_FP_RISK else "low",
                       "reasons": [str(x)[:160] for x in (v.get("reasons") or [])][:6],
                       "recommend": "review" if (rec == "review" or fr == "high") else "accept"}
    except Exception:
        pass
    if record:
        store.record_reflection(finding_id, verdict)
    return verdict


def reflect_all(store: FindingStore, *, only_verified: bool = True) -> dict:
    out = {}
    for fid, f in store.findings().items():
        if only_verified and f.get("status") != "verified":
            continue
        out[fid] = reflect_finding(store, fid)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="#6 reflective self-verification over a findings store (advisory).")
    ap.add_argument("--store", required=True)
    ap.add_argument("--id", default=None, help="one finding; omit to reflect ALL verified findings")
    ap.add_argument("--no-record", action="store_true")
    a = ap.parse_args(argv)
    store = FindingStore(a.store)
    if a.id:
        print(a.id, "->", json.dumps(reflect_finding(store, a.id, record=not a.no_record)))
    else:
        res = reflect_all(store)
        flagged = {k: v for k, v in res.items() if v.get("fp_risk") in ("medium", "high")}
        print(json.dumps({"reflected": len(res), "flagged_for_review": flagged}, indent=1))
        print("assurance:", json.dumps(store.assurance()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
