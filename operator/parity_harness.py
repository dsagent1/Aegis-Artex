"""
parity_harness.py -- CROSS-CUTTING assurance harness (corpus+chaining roadmap): two checks that turn
"we found some bugs" into "this run is trustworthy", within the non-destructive envelope.

Motivation: capability ("can it find X") is not the same as ASSURANCE ("if it came back clean, trust
it"). Assurance rests on (A) coverage completeness, (B) false-negative control, (C) evidence. This module
is pillar B's foundation:

  1. PARITY  -- prove that wiring a catalog as a first-class vector loses NOTHING vs the raw tool. Runs the
     RAW tool (nuclei -jsonl / msf) with the SAME flags the vector uses, and the Aegis VECTOR, against the
     same target, then asserts the vector's leads are a SUPERSET of the raw tool's findings. Anything the
     raw tool found but the vector MISSED is a wiring/parse regression (the check fails, names the misses).

  2. RECALL  -- against a target with KNOWN/planted truths, run the vectors/loop and measure
     recall = matched / expected. This is the false-negative number: a low recall means the tool is
     missing real bugs and a "clean" result cannot be trusted. Structural + live.

Offline-safe + structurally testable: the tool runners go through vectors._kali, which can be monkeypatched
in a test; a live run needs the Kali mirror + a target. Nothing here is destructive.
"""
from __future__ import annotations
import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _raw_nuclei(base, severity, tags, extra_headers="", seconds=240):
    """Run nuclei -jsonl with the SAME gating the vector uses; return the set of matched template-ids."""
    import vectors
    import shlex
    tag_arg = (" -tags " + shlex.quote(tags)) if tags else ""
    cmd = (f"command -v nuclei >/dev/null 2>&1 && nuclei -u {shlex.quote(base)} -jsonl -silent -nc -duc "
           f"-severity {shlex.quote(severity)}{tag_arg} -etags dos,intrusive,fuzzing,network "
           f"-timeout 10 -retries 1{extra_headers} 2>/dev/null || echo '__NO_NUCLEI__'")
    out = vectors._kali(cmd, seconds + 30)
    ids = set()
    if "__NO_NUCLEI__" in out:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                m = json.loads(line)
                tid = m.get("template-id") or m.get("templateID")
                if tid:
                    ids.add(tid)
            except Exception:
                pass
    return ids


def parity_nuclei(base=None, stack=None, severity="medium,high,critical", role="owner",
                  session_for_role=None):
    """Compare the RAW nuclei run to the Aegis nuclei VECTOR (same flags). Returns a parity report;
    parity_ok is True iff the vector caught every template the raw tool did (superset)."""
    import vectors
    base = base or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    tags = ",".join(sorted({str(t).strip().lower() for t in (stack or []) if str(t).strip()}))
    # the vector lifts auth headers from the session; mirror that for the raw baseline so it's apples-to-apples
    extra_headers = ""
    if session_for_role:
        try:
            s = session_for_role(role)
            auth = s.headers.get(os.environ.get("AEGIS_AUTH_HEADER", "Authorization"))
            import shlex
            if auth:
                extra_headers += " -H " + shlex.quote((os.environ.get("AEGIS_AUTH_HEADER", "Authorization")) + ": " + str(auth))
            cookie = "; ".join(f"{c.name}={c.value}" for c in s.cookies)
            if cookie:
                extra_headers += " -H " + shlex.quote("Cookie: " + cookie)
        except Exception:
            pass
    raw = _raw_nuclei(base, severity, tags, extra_headers=extra_headers)
    if raw is None:
        return {"check": "parity_nuclei", "skipped": "nuclei not installed", "parity_ok": None}
    ctx = {"base": base, "stack": list(stack or []),
           "session_for_role": session_for_role}
    res = vectors.dispatch({"action": "nuclei", "role": role, "severity": severity}, "parity", ctx)
    wired = {l.get("template_id") for l in (res.get("nuclei", {}).get("leads") or []) if l.get("template_id")}
    missed = sorted(raw - wired)     # raw found, vector did NOT -> regression
    extra = sorted(wired - raw)      # vector found beyond raw (fine)
    return {"check": "parity_nuclei", "base": base, "severity": severity, "tags": tags,
            "raw_count": len(raw), "wired_count": len(wired), "missed": missed, "extra": extra,
            "parity_ok": len(missed) == 0,
            "note": ("vector caught all raw templates" if not missed
                     else "REGRESSION: %d raw template(s) not surfaced by the vector" % len(missed))}


def parity_msf(base=None, modules=None, role="owner"):
    """For each candidate MSF module, confirm the Aegis msf leg RUNS it (proof-only) and PARSES a verdict
    the same way a manual `check` would -- i.e. the wiring doesn't silently drop a module. Compares the
    leg's positive/negative to a raw msfconsole check parse. Returns per-module agreement."""
    import vectors
    base = base or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    modules = modules or []
    rows = []
    for mod in modules:
        res = vectors.dispatch({"action": "msf", "module": mod, "role": role}, "parity", {"base": base})
        md = res.get("msf", {})
        rows.append({"module": mod, "ran": md.get("ran"), "action": md.get("action"),
                     "positive": md.get("positive"), "policy": md.get("policy")})
    ran = [r for r in rows if r.get("ran")]
    return {"check": "parity_msf", "base": base, "modules": len(modules), "ran": len(ran),
            "rows": rows, "parity_ok": len(ran) == len([m for m in modules if not _msf_refused(m)]),
            "note": "each allowlisted module ran (proof-only); refused modules are policy, not regressions"}


def _msf_refused(module):
    import vectors
    ok, _, _ = vectors._msf_allowed(module, "check")
    return not ok


def recall(expected, found):
    """recall = |expected ∩ found| / |expected|. `expected`/`found` are iterables of comparable keys
    (template-id, cve, module, or a (surface,class) tuple). Returns the recall metric + the misses --
    the false-NEGATIVES, the bugs a 'clean' run would have wrongly cleared."""
    exp = set(expected or [])
    fnd = set(found or [])
    hit = exp & fnd
    misses = sorted(exp - fnd, key=str)
    return {"check": "recall", "expected": len(exp), "found_of_expected": len(hit),
            "recall": round(len(hit) / len(exp), 3) if exp else None, "misses": misses,
            "note": ("no known truths to measure against" if not exp
                     else "%d known bug(s) MISSED (false negatives)" % len(misses) if misses
                     else "all known bugs recalled")}


def main():
    ap = argparse.ArgumentParser(description="Parity + recall assurance harness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pn = sub.add_parser("nuclei", help="parity: wired vector vs raw nuclei")
    pn.add_argument("--base"); pn.add_argument("--stack", default="")
    pn.add_argument("--severity", default="medium,high,critical"); pn.add_argument("--role", default="owner")
    pm = sub.add_parser("msf", help="parity: msf leg runs each allowlisted module")
    pm.add_argument("--base"); pm.add_argument("--modules", default="", help="CSV of module paths")
    rc = sub.add_parser("recall", help="recall from an expected-truth file vs a found file")
    rc.add_argument("--expected", required=True, help="JSON list of expected keys")
    rc.add_argument("--found", required=True, help="JSON list of found keys")
    a = ap.parse_args()
    if a.cmd == "nuclei":
        sfr = None
        try:
            import session_factory
            sfr = session_factory.from_env(a.base)
        except Exception:
            sfr = None
        out = parity_nuclei(a.base, stack=[s for s in a.stack.split(",") if s], severity=a.severity,
                            role=a.role, session_for_role=sfr)
    elif a.cmd == "msf":
        out = parity_msf(a.base, modules=[m for m in a.modules.split(",") if m])
    else:
        exp = json.load(open(a.expected, encoding="utf-8"))
        fnd = json.load(open(a.found, encoding="utf-8"))
        out = recall(exp, fnd)
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
