#!/usr/bin/env python3
"""coverage_gate.py -- ATTACK-SURFACE COVERAGE-COMPLETENESS GATE (G51).

The trust problem it closes (board must-fix #1, ds-g50 evidence): a run that ends "0 verified" is AMBIGUOUS
between "tested and clean" and "barely tested". An attacker enumerates the WHOLE surface; if the hunt only
exercised a subset, a clean verdict is not a safety signal. This gate makes "clean" MEAN "tested":

  DISCOVERED surface  = what the app actually exposes -> crawler.crawl() (headless per-role, ground truth:
                        every XHR/fetch the SPA calls), optionally unioned with a supplied surface file.
  EXERCISED surface   = what the run actually probed -> the `surface:<path>` coverage_tags on the campaign's
                        findings (candidates + verdicts), path-normalized the SAME way as the crawler.
  COVERAGE            = |exercised ∩ discovered| / |discovered|, overall + per discovered path.
  VERDICT             = COVERED (>= threshold) -> a clean/verified-0 run is MEANINGFUL;
                        INCOMPLETE (< threshold) -> clean is NOT a safety signal, lists the UNTESTED surfaces;
                        UNKNOWN -> surface discovery unavailable (no Playwright) -> cannot assert completeness.

Combined meaning (with the campaign's verified count):
  0 verified + COVERED    -> "tested & clean" (a real green light)
  0 verified + INCOMPLETE -> "inconclusive -- surface not fully tested" (NOT a green light)
  >0 verified             -> findings exist regardless; coverage says how much of the surface was reached.

Offline-safe; never destructive (crawler is GET-only). CI: exit 0 = COVERED, 2 = INCOMPLETE, 3 = UNKNOWN.

Usage:
  python operator/coverage_gate.py <campaign> [--base URL] [--roles technician,anon]
         [--threshold 0.85] [--surface-file f.json] [--json] [--out FILE]
"""
from __future__ import annotations
import argparse, json, os, sys, time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import crawler  # for crawl() + the SHARED path normaliser so both sides compare like-for-like


def _norm(path):
    """Normalise an api path the same way the crawler does (collapse ids -> {id}), so exercised vs discovered
    compare like-for-like. `path` may already be a template or a concrete path."""
    if not path:
        return None
    p = str(path).split("?")[0].strip()
    if not p.startswith("/"):
        # a coverage_tag surface can be 'image:...' (supply-chain) or a bare name -> not an http surface
        return None
    return crawler._norm_path("http://x" + p, "x")


def discovered(base, roles, per_role_seconds=20, surface_file=None):
    """Ground-truth surface. Live crawl (+ optional supplied surface file). Returns (set(paths), by_role, meta)."""
    sset, by_role, meta = set(), {}, {"source": []}
    if surface_file and os.path.exists(surface_file):
        try:
            d = json.load(open(surface_file, encoding="utf-8"))
            for s in d.get("surfaces", []):
                n = _norm(s)
                if n:
                    sset.add(n)
            for r, lst in (d.get("by_role") or {}).items():
                by_role[r] = sorted({_norm(x) for x in lst if _norm(x)})
            meta["source"].append("surface-file")
        except Exception as e:
            meta["surface_file_err"] = str(e)[:80]
    try:
        import session_factory
        sfr = session_factory.from_env(base)
    except Exception:
        sfr = None
    cr = crawler.crawl(base, session_for_role=sfr, roles=roles, per_role_seconds=per_role_seconds)
    if cr:
        meta["source"].append("crawler")
        for s in cr.get("surfaces", []):
            n = _norm(s)
            if n:
                sset.add(n)
        for r, lst in (cr.get("by_role") or {}).items():
            merged = set(by_role.get(r, [])) | {_norm(x) for x in lst if _norm(x)}
            by_role[r] = sorted(m for m in merged if m)
    meta["available"] = bool(cr) or bool(surface_file)
    return sset, by_role, meta


def exercised(campaign):
    """Surfaces the run actually probed: the `surface:<path>` coverage_tags on the campaign's findings
    (both candidate records and transitions), normalised. Returns (set(paths), technique_counter)."""
    cdir = os.path.join(HERE, "campaigns", campaign)
    fj = os.path.join(cdir, "findings.jsonl")
    sset, techs = set(), Counter()
    if not os.path.exists(fj):
        return sset, techs
    for ln in open(fj, encoding="utf-8"):
        ln = ln.strip()
        if not ln:
            continue
        try:
            d = json.loads(ln)
        except Exception:
            continue
        f = d.get("finding") if isinstance(d.get("finding"), dict) else d
        tags = f.get("coverage_tags") or []
        for t in tags:
            t = str(t)
            if t.startswith("surface:"):
                n = _norm(t[len("surface:"):])
                if n:
                    sset.add(n)
            elif t.startswith("technique:"):
                techs[t[len("technique:"):]] += 1
    return sset, techs


def gate(campaign, base, roles, threshold=0.85, surface_file=None, per_role_seconds=20):
    disc, by_role, meta = discovered(base, roles, per_role_seconds, surface_file)
    exd, techs = exercised(campaign)
    # verified count for the combined meaning
    verdicts = Counter()
    cdir = os.path.join(HERE, "campaigns", campaign)
    fj = os.path.join(cdir, "findings.jsonl")
    if os.path.exists(fj):
        for ln in open(fj, encoding="utf-8"):
            try:
                d = json.loads(ln)
            except Exception:
                continue
            if d.get("type") == "transition":
                verdicts[d.get("status")] += 1
    if not meta.get("available"):
        verdict = "UNKNOWN"
    else:
        covered = disc & exd
        ratio = (len(covered) / len(disc)) if disc else 0.0
        verdict = "COVERED" if (disc and ratio >= threshold) else "INCOMPLETE"
    untested = sorted(disc - exd)
    ratio = (len(disc & exd) / len(disc)) if disc else 0.0
    ver = verdicts.get("verified", 0)
    if verdict == "UNKNOWN":
        meaning = "surface discovery unavailable (no Playwright/target) -> completeness cannot be asserted"
    elif ver > 0:
        meaning = f"{ver} verified finding(s); {ratio:.0%} of the discovered surface was exercised"
    elif verdict == "COVERED":
        meaning = "TESTED & CLEAN -- 0 verified AND the discovered surface was covered (a real green light)"
    else:
        meaning = ("INCONCLUSIVE -- 0 verified but the surface was NOT fully tested; a clean result here is "
                   "NOT a safety signal until the untested surfaces below are exercised")
    return {"campaign": campaign, "verdict": verdict, "coverage_ratio": round(ratio, 3),
            "threshold": threshold, "discovered": sorted(disc), "exercised_on_surface": sorted(disc & exd),
            "untested": untested, "extra_exercised_not_discovered": sorted(exd - disc),
            "by_role_discovered": by_role, "verdicts": dict(verdicts), "techniques": dict(techs),
            "meaning": meaning, "discovery_meta": meta}


def render(g):
    out = [f"# COVERAGE GATE — {g['campaign']}", "",
           f"- verdict: **{g['verdict']}**  coverage: **{g['coverage_ratio']:.0%}** (threshold {g['threshold']:.0%})",
           f"- meaning: **{g['meaning']}**",
           f"- verdicts: {g['verdicts']}",
           f"- discovered surfaces: {len(g['discovered'])}  ·  exercised of those: {len(g['exercised_on_surface'])}"
           f"  ·  untested: {len(g['untested'])}",
           f"- discovery source: {g['discovery_meta'].get('source')}", ""]
    if g["untested"]:
        out += ["## UNTESTED discovered surfaces (an attacker reaches these; the run did not)", ""]
        out += [f"- `{s}`" for s in g["untested"]]
        out.append("")
    if g["extra_exercised_not_discovered"]:
        out += ["## Exercised but NOT in the discovered set (seeds/guesses beyond the crawl)", ""]
        out += [f"- `{s}`" for s in g["extra_exercised_not_discovered"][:40]]
        out.append("")
    if g["by_role_discovered"]:
        out += ["## Discovered surface by role", ""]
        for r, lst in g["by_role_discovered"].items():
            out.append(f"- **{r}** ({len(lst)}): {', '.join(lst) if lst else '(none)'}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="attack-surface coverage-completeness gate")
    ap.add_argument("campaign")
    ap.add_argument("--base", default=os.environ.get("AEGIS_TARGET", "https://localhost:8443"))
    ap.add_argument("--roles", default=os.environ.get("AEGIS_CRAWL_ROLES", "technician,anon"))
    ap.add_argument("--threshold", type=float, default=float(os.environ.get("AEGIS_COVERAGE_THRESHOLD", "0.85")))
    ap.add_argument("--surface-file", default=None, help="optional JSON {surfaces,by_role} to union with the live crawl")
    ap.add_argument("--per-role-seconds", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    roles = [r.strip() for r in a.roles.split(",") if r.strip()]
    g = gate(a.campaign, a.base, roles, a.threshold, a.surface_file, a.per_role_seconds)
    if a.json:
        print(json.dumps(g, indent=2))
    else:
        md = render(g)
        if a.out:
            open(a.out, "w", encoding="utf-8").write(md)
            print(f"coverage-gate written: {a.out}")
        print(md)
    sys.exit(0 if g["verdict"] == "COVERED" else (3 if g["verdict"] == "UNKNOWN" else 2))


if __name__ == "__main__":
    main()
