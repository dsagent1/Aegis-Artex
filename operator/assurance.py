"""
assurance.py -- PILLAR A of assurance parity (corpus+chaining roadmap): turn a run's "no findings" into a
DEFENSIBLE "clean", by measuring COVERAGE COMPLETENESS -- so an empty result means "we tested the whole
surface and it held", not "we found nothing where we happened to look".

It reads what the loop already produces (no loop-internal bookkeeping needed):
  * res['coverage']   -- the parity-CLASS completeness (coverage.summary): which of the OWASP/API classes
                         were probed at least once.
  * res['attempt_log']-- every attempt's move -> the (surface x class x role) cells actually exercised.
  * the CRAWL surfaces (discovered attack surface) -> SATURATION: were all discovered surfaces probed, or
    did we leave endpoints untouched (the invisible false-negative)?

Verdict:
  COMPLETE   -- every expected parity class probed AND every discovered surface probed by >=1 class.
  INCOMPLETE -- otherwise; the not-reached classes/surfaces are the explicit gaps a reviewer must see.
A run that finds nothing but is INCOMPLETE is reported as INCOMPLETE, never as "clean".

Optional RECALL (pillar B): pass a planted-truth key set to fold the false-negative number in.

Pure-read + offline-safe: any missing input degrades gracefully (the metric goes None, never raises).
"""
from __future__ import annotations
import os
from collections import defaultdict


def _class_of(move):
    try:
        import coverage as C
        return C.class_of(move or {})
    except Exception:
        return (move or {}).get("action", "web")


def _parity_classes():
    try:
        import coverage as C
        return set(C.PARITY_CLASSES)
    except Exception:
        return set()


def assess(res, *, discovered_surfaces=None, roles=None, expected_classes=None,
           planted=None, found_keys=None):
    """Build the assurance summary from a run result. Returns a dict (see keys below)."""
    res = res or {}
    exp_classes = set(expected_classes or _parity_classes())

    # ---- class completeness (reuse the loop's own coverage summary when present) ----
    covsum = res.get("coverage") if isinstance(res.get("coverage"), dict) else None
    covered_classes = set((covsum or {}).get("covered") or [])

    # ---- surface x class x role cells actually exercised (from the attempt log) ----
    attempts = res.get("attempt_log") or res.get("attempts") or []
    probed_by_surface = defaultdict(set)
    probed_surfaces, probed_roles, probed_classes = set(), set(), set()
    for a in attempts:
        mv = (a or {}).get("move") or {}
        surf = mv.get("surface") or mv.get("path") or ""
        role = str(mv.get("role") or "").lower()
        cls = _class_of(mv)
        probed_classes.add(cls)
        if role:
            probed_roles.add(role)
        if surf:
            probed_surfaces.add(surf)
            probed_by_surface[surf].add(cls)
    if not covered_classes:                    # fall back to classes seen in the attempt log
        covered_classes = probed_classes & exp_classes if exp_classes else probed_classes

    uncovered_classes = sorted(exp_classes - covered_classes) if exp_classes else []
    class_completeness = (round(len(exp_classes & covered_classes) / len(exp_classes), 3)
                          if exp_classes else None)

    # ---- crawl saturation: discovered surface vs surface actually probed ----
    discovered = {s for s in (discovered_surfaces or []) if s}
    unprobed_surfaces = sorted(discovered - probed_surfaces) if discovered else []
    saturation = (round(len(discovered & probed_surfaces) / len(discovered), 3)
                  if discovered else None)

    # ---- verdict ----
    reasons = []
    if uncovered_classes:
        reasons.append("%d parity class(es) never probed: %s"
                       % (len(uncovered_classes), ", ".join(uncovered_classes)))
    if unprobed_surfaces:
        reasons.append("%d discovered surface(s) never probed" % len(unprobed_surfaces))
    complete = (not uncovered_classes) and (not unprobed_surfaces) and bool(covered_classes)
    verdict = "COMPLETE" if complete else "INCOMPLETE"

    # ---- optional recall (false-negative number) ----
    recall = None
    if planted is not None:
        try:
            import parity_harness as PH
            recall = PH.recall(planted, found_keys or _found_keys(res))
        except Exception:
            recall = None

    n_verified = len(res.get("confirmed") or [])
    return {
        "verdict": verdict,
        "clean_and_complete": bool(complete and n_verified == 0),
        "reasons": reasons,
        "verified_findings": n_verified,
        "class_completeness": class_completeness,
        "classes_covered": sorted(covered_classes),
        "classes_not_reached": uncovered_classes,
        "surface_saturation": saturation,
        "surfaces_probed": len(probed_surfaces),
        "surfaces_discovered": len(discovered),
        "surfaces_not_reached": unprobed_surfaces[:50],
        "roles_probed": sorted(probed_roles),
        "recall": recall,
    }


def _found_keys(res):
    """Best-effort: keys (cve/template/module/surface) for confirmed findings, for a recall match."""
    keys = set()
    for c in (res.get("confirmed") or []):
        mv = (c or {}).get("move") or {}
        for k in ("cve", "template_id", "module", "surface", "path"):
            v = mv.get(k)
            if v:
                keys.add(v)
        for t in (mv.get("coverage_tags") or []):
            if str(t).startswith("cve:"):
                keys.add(str(t)[4:])
    return keys


def report(assess_out, objective="", target="") -> str:
    a = assess_out or {}
    L = ["=== ASSURANCE REPORT ===",
         "objective: " + (objective or "(n/a)"),
         "target:    " + (target or "(n/a)"),
         "",
         "VERDICT: %s" % a.get("verdict", "?")]
    if a.get("clean_and_complete"):
        L.append("  -> CLEAN + COMPLETE: full expected surface tested, no verified findings. Defensible pass.")
    elif a.get("verdict") == "COMPLETE":
        L.append("  -> COMPLETE with %d verified finding(s)." % a.get("verified_findings", 0))
    else:
        L.append("  -> INCOMPLETE: a 'no-findings' result here is NOT a clean bill. Gaps below.")
    def _pct(x):
        return "n/a" if x is None else "%d%%" % round(x * 100)
    L += ["",
          "class completeness : %s  (%d covered, %d not reached)"
          % (_pct(a.get("class_completeness")), len(a.get("classes_covered") or []),
             len(a.get("classes_not_reached") or [])),
          "surface saturation : %s  (%d of %d discovered surfaces probed)"
          % (_pct(a.get("surface_saturation")), a.get("surfaces_probed", 0), a.get("surfaces_discovered", 0)),
          "roles probed       : " + (", ".join(a.get("roles_probed") or []) or "(none)"),
          "verified findings  : %d" % a.get("verified_findings", 0)]
    if a.get("recall") is not None:
        r = a["recall"]
        L.append("recall (planted)   : %s  (%d/%d known, %d missed)"
                 % (_pct(r.get("recall")), r.get("found_of_expected", 0), r.get("expected", 0),
                    len(r.get("misses") or [])))
    if a.get("classes_not_reached"):
        L += ["", "NOT REACHED -- classes: " + ", ".join(a["classes_not_reached"])]
    if a.get("surfaces_not_reached"):
        L += ["NOT REACHED -- surfaces (%d): " % len(a["surfaces_not_reached"])
              + ", ".join(a["surfaces_not_reached"][:15])
              + (" ..." if len(a["surfaces_not_reached"]) > 15 else "")]
    return "\n".join(L)
