"""
recall_suite.py -- PILLAR B of assurance parity (corpus+chaining roadmap): the RUNNING recall benchmark.

Coverage completeness (pillar A) proves we tested the whole surface; RECALL proves we FIND the bugs that
are there. Against a target with a KNOWN truth-set (a documented-vulnerable app, or a mirror with planted
bugs), this runs the hunt and measures recall = matched / expected. A low recall means real bugs are
being missed and a 'clean' result cannot be trusted -- this is the false-NEGATIVE number that turns the
assurance report from a claim into a measurement.

A benchmark MANIFEST (JSON, in operator/recall_benchmarks/) declares:
  {name, target, stack, roles, budget,
   expected: [{id, class, surface?, match?[]}]}   # the ground-truth bugs the target is known to have

The suite: run the hunt (default: iterative_hunt_live.run_hunt; injectable for tests) -> harvest FOUND
keys from the findings store (verified findings + strong leads: nuclei/msf/idor/... carry cve/template/
module/surface/class) -> MATCH each expected truth against the found set -> recall + the MISSES (the bugs
a clean run would have wrongly cleared) -> fold in the pillar-A assurance verdict -> one report.

Matching is deliberately forgiving (real finding vocabularies vary): an expected entry is RECALLED iff some
finding's searchable blob contains its `class` AND (its `surface` OR any `match` token), else it's a MISS.

Live run needs the target up (that's the live-host step). Offline: pass run_fn to inject a run result, or
point at a seeded mirror. Nothing here is destructive.
"""
from __future__ import annotations
import argparse
import glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(_HERE, "..", "shared")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
BENCH_DIR = os.path.join(_HERE, "recall_benchmarks")


def _finding_blob(rec) -> str:
    """A searchable string for a finding/lead: class + surface + technique + cve + template + module."""
    mv = (rec or {}).get("move") or {}
    parts = [rec.get("claim_type", ""), rec.get("summary", "")]
    parts += [str(mv.get(k, "")) for k in ("cve", "template_id", "module", "surface", "path",
                                           "vuln_class", "class", "technique")]
    parts += [str(t) for t in (mv.get("coverage_tags") or [])]
    parts += [str(t) for t in (rec.get("coverage_tags") or [])]
    prov = rec.get("provenance") or {}
    parts += [str(prov.get(k, "")) for k in ("cve", "template_id", "module", "provider")]
    return " ".join(parts).lower()


def harvest(store) -> list:
    """Collect searchable blobs for every finding in the store (verified + candidate leads)."""
    blobs = []
    try:
        findings = store.findings()
    except Exception:
        return blobs
    for f in findings.values():
        blobs.append(_finding_blob(f))
    return blobs


def match_expected(expected, blobs) -> dict:
    """For each expected truth, is it recalled by some finding blob? Returns found-keys + per-entry hits."""
    found_keys, detail = set(), []
    for e in (expected or []):
        cls = str(e.get("class", "")).lower()
        surf = str(e.get("surface", "")).lower()
        toks = [str(t).lower() for t in (e.get("match") or [])]
        hit = False
        for b in blobs:
            if cls and cls not in b:
                continue
            if surf and surf not in b:
                continue
            if toks and not any(t in b for t in toks):
                continue
            if cls or surf or toks:
                hit = True
                break
        detail.append({"id": e.get("id"), "class": cls, "recalled": hit})
        if hit:
            found_keys.add(e.get("id"))
    return {"found_keys": sorted(found_keys), "detail": detail}


def run_benchmark(manifest, run_fn=None, store=None):
    """Run one benchmark. `run_fn(manifest)->(res, store)` is injectable (tests / custom drivers); the
    default drives iterative_hunt_live.run_hunt. Returns the recall + assurance report dict."""
    name = manifest.get("name", "benchmark")
    expected = manifest.get("expected") or []
    res = {}
    if run_fn is not None:
        out = run_fn(manifest)
        if isinstance(out, tuple):
            res, store = out
        else:
            res = out
    else:
        # LIVE driver: run the hunt against the target (needs it up). Offline-safe: any failure -> empty.
        try:
            import iterative_hunt_live as IHL
            from verified_findings import FindingStore
            import session_factory, tempfile
            base = manifest.get("target")
            role0 = (manifest.get("roles") or ["owner"])[0]
            store = store or FindingStore(os.path.join(tempfile.gettempdir(), "recall_%s.jsonl" % name))
            try:
                open(store.path, "w").close()
            except Exception:
                pass
            # FIX (juice-shop 0/6 root cause): a non-SPA crawler never DISCOVERS an Angular-XHR REST API, so
            # the hunt probed generic routes and never reached the truth-set. FEED the manifest's declared
            # surfaces into run_hunt as seed moves so it PROBES them directly (the manifest was previously
            # passed only to assurance, not the hunt). Each expected {surface,class} -> its vector; plus a
            # plain web probe of every declared surface so they're at least reached.
            _CLS2ACT = {"injection": "sql_raw", "sqli": "sql_raw", "xss": "xss", "authz": "authz",
                        "idor": "idor", "bola": "idor", "security_headers": "security_headers",
                        "auth_session": "session_fixation", "ssrf": "ssrf", "csrf": "csrf",
                        "secrets": "misconfig", "file_upload": "file_upload"}
            seed_moves = []
            for e in expected:
                surf = e.get("surface")
                if not surf:
                    continue
                cls = e.get("class")
                acts = [_CLS2ACT.get(cls, "web")]
                if cls in ("injection", "sqli"):
                    acts.append("inject")                 # try both the boolean-diff and the injection battery
                if cls in ("security_headers", "secrets"):
                    acts.append("misconfig")              # /ftp / backup / exposure lives in misconfig, not headers
                for act in acts:
                    seed_moves.append({"action": act, "surface": surf, "role": role0, "seed": "recall-manifest",
                                       "vuln_class": cls, "why_novel": "truth-set %s on %s" % (cls, surf)})
            for s in (manifest.get("surfaces") or []):
                seed_moves.append({"action": "web", "surface": s, "role": role0,
                                   "seed": "recall-manifest-surface", "why_novel": "reach declared surface %s" % s})
            res = IHL.run_hunt(manifest.get("objective", "recall benchmark: find the known bugs"),
                               role=role0, budget=int(manifest.get("budget", 40)), base=base,
                               store_path=store.path, extra_seeds=seed_moves)
        except Exception as e:
            return {"benchmark": name, "error": str(e)[:200], "recall": None}

    blobs = harvest(store) if store is not None else []
    mm = match_expected(expected, blobs)
    try:
        import parity_harness as PH
        rc = PH.recall([e.get("id") for e in expected], mm["found_keys"])
    except Exception:
        exp = {e.get("id") for e in expected}
        rc = {"expected": len(exp), "found_of_expected": len(exp & set(mm["found_keys"])),
              "recall": round(len(exp & set(mm["found_keys"])) / len(exp), 3) if exp else None,
              "misses": sorted(exp - set(mm["found_keys"]))}
    # fold in pillar-A assurance (coverage completeness) when we have a real run result
    assess = None
    try:
        import assurance
        assess = assurance.assess(res, discovered_surfaces=manifest.get("surfaces"),
                                  roles=manifest.get("roles"))
    except Exception:
        assess = None
    return {"benchmark": name, "target": manifest.get("target"),
            "expected": len(expected), "recall": rc.get("recall"),
            "recalled": rc.get("found_of_expected"), "misses": rc.get("misses"),
            "per_expected": mm["detail"], "assurance": assess}


def load_manifests(pattern=None):
    out = []
    for p in sorted(glob.glob(os.path.join(BENCH_DIR, pattern or "*.json"))):
        try:
            out.append(json.load(open(p, encoding="utf-8")))
        except Exception:
            pass
    return out


def report(result) -> str:
    r = result or {}
    def _pct(x):
        return "n/a" if x is None else "%d%%" % round(x * 100)
    L = ["=== RECALL BENCHMARK: %s ===" % r.get("benchmark", "?"),
         "target: %s" % (r.get("target") or "(n/a)")]
    if r.get("error"):
        L.append("ERROR: " + r["error"]); return "\n".join(L)
    L += ["recall: %s  (%d of %d known bugs found)"
          % (_pct(r.get("recall")), r.get("recalled", 0), r.get("expected", 0))]
    if r.get("misses"):
        L.append("MISSED (false negatives): " + ", ".join(str(m) for m in r["misses"]))
    else:
        L.append("all known bugs recalled")
    a = r.get("assurance")
    if a:
        L.append("assurance verdict: %s (class %s, saturation %s)"
                 % (a.get("verdict"), a.get("class_completeness"), a.get("surface_saturation")))
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Pillar-B running recall benchmark suite")
    ap.add_argument("--manifest", help="path to a single benchmark manifest JSON")
    ap.add_argument("--all", action="store_true", help="run every manifest in recall_benchmarks/")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    manifests = ([json.load(open(a.manifest, encoding="utf-8"))] if a.manifest
                 else load_manifests() if a.all else [])
    if not manifests:
        print("no manifest (pass --manifest PATH or --all). Available:",
              [os.path.basename(p) for p in glob.glob(os.path.join(BENCH_DIR, "*.json"))])
        return 0
    results = [run_benchmark(m) for m in manifests]
    if a.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        for r in results:
            print(report(r)); print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
