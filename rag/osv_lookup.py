"""osv_lookup.py -- OSV.dev COVERAGE ENGINE for the supply_chain vector.

Maps a detected dependency `name@version` (any ecosystem: npm / PyPI / Go / Maven / RubyGems / crates.io /
NuGet / Packagist) to KNOWN advisories, with OSV doing the **affected-version-RANGE match server-side** --
so a PATCHED version is NOT false-flagged (the version-only-banner false positive the dedicated scanners
produce). Free public feed (api.osv.dev), no key. Offline-safe: any network/parse failure returns [] and
never raises into a hunt.

This is a COVERAGE engine BEHIND the verification layer: it proposes range-precise candidate CVEs; the
oracle still confirms the CVE actually reproduces on the target/twin before it counts. Signature breadth
from OSV; truthfulness from our oracle.

CLI:  python rag/osv_lookup.py npm lodash 4.17.4
"""
import json
import urllib.request

OSV_API = "https://api.osv.dev/v1/query"


def _fixed_versions(vuln, ecosystem, name):
    """Introduced->fixed version events for THIS package (so a report can state the upgrade target)."""
    fixed = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("name") != name or (ecosystem and pkg.get("ecosystem") and pkg["ecosystem"].lower() != ecosystem.lower()):
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def _severity(vuln):
    """Best-effort severity: a CVSS vector/score if OSV carries one, else the DB-specific label."""
    for s in vuln.get("severity", []) or []:
        if s.get("score"):
            return s["score"]
    ds = vuln.get("database_specific", {}) or {}
    return ds.get("severity", "") or ""


def query(ecosystem, name, version, timeout=15):
    """Return a list of advisories affecting `name@version` in `ecosystem`. OSV range-matches the version
    server-side, so a fixed version returns [] for advisories patched at/under it. Never raises."""
    payload = {"version": str(version), "package": {"name": name, "ecosystem": ecosystem}}
    req = urllib.request.Request(OSV_API, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        r = json.load(urllib.request.urlopen(req, timeout=timeout))
    except Exception:
        return []
    out = []
    for v in r.get("vulns", []) or []:
        out.append({
            "id": v.get("id"),
            "aliases": v.get("aliases", []) or [],          # CVE/GHSA cross-refs
            "summary": (v.get("summary") or v.get("details") or "")[:160],
            "severity": _severity(v),
            "fixed": _fixed_versions(v, ecosystem, name),   # the upgrade target(s)
        })
    return out


def scan_manifest(deps, timeout=15):
    """`deps` = iterable of (ecosystem, name, version). Returns {(ecosystem,name,version): [advisories]} for
    the deps that have at least one range-matched advisory. The supply_chain vector feeds detected
    dependencies here; each hit becomes an oracle CANDIDATE (confirm reproduction before it counts)."""
    hits = {}
    for eco, name, ver in deps:
        adv = query(eco, name, ver, timeout=timeout)
        if adv:
            hits[(eco, name, ver)] = adv
    return hits


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("usage: python rag/osv_lookup.py <ecosystem> <name> <version>")
        sys.exit(2)
    eco, name, ver = sys.argv[1], sys.argv[2], sys.argv[3]
    adv = query(eco, name, ver)
    print(f"{name}@{ver} ({eco}): {len(adv)} advisory(ies)")
    for a in adv:
        print(f"  {a['id']}  {a.get('severity','')}  fixed={a['fixed']}  {a['summary'][:80]}")
