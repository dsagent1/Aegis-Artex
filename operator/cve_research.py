"""cve_research.py -- AUTONOMOUS live advisory research for a component+version (authorized-OSINT lane).

The approach to probing a KNOWN gap is normally STATED in the public advisory. This module is the machinery
that pulls it: given a component+version it resolves the applicable CVEs and their PUBLICLY-STATED approach
(NVD description + CVSS + references) and whether the live version is in the vulnerable range, so the n-day
developer (patch_differ / the code bench) grounds the probe in the real advisory instead of guessing from a
CVE id. It complements patch_differ's code-diff rung (the diff shows WHERE the fix is; the advisory often
states WHAT the bug is and HOW to reach it).

Doctrine: authorized-OSINT only (public vuln feeds -- the same lane as rag_update's online refresh), opt-in
(AEGIS_RAG_ONLINE=1 or AEGIS_CVE_RESEARCH=1), egress routed through the VPN proxy (AEGIS_EGRESS_PROXY /
HTTPS_PROXY) when set, never target data. Offline-safe: any network failure returns the local/empty result
and NEVER raises, so a hunt degrades gracefully.
"""
import os, json, re, ssl, urllib.request, urllib.parse

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _online() -> bool:
    return (os.environ.get("AEGIS_RAG_ONLINE") == "1"
            or str(os.environ.get("AEGIS_CVE_RESEARCH", "")).lower() in ("1", "true", "yes", "on"))


def _opener():
    handlers = []
    px = os.environ.get("AEGIS_EGRESS_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if px:
        handlers.append(urllib.request.ProxyHandler({"http": px, "https": px}))
    try:
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    except Exception:
        pass
    return urllib.request.build_opener(*handlers)


def _vtuple(v):
    nums = re.findall(r"\d+", str(v or ""))
    return tuple(int(x) for x in nums[:4]) if nums else (0,)


def _in_range(version, start_incl, end_excl, end_incl):
    v = _vtuple(version)
    if start_incl and v < _vtuple(start_incl):
        return False
    if end_excl and not (v < _vtuple(end_excl)):
        return False
    if end_incl and not (v <= _vtuple(end_incl)):
        return False
    return True


def _affects(cve, component, version):
    """Best-effort: scan the CVE's CPE configurations for the component + a version range that includes the
    live version. Returns (affects: True|False|None, fixed: str|None). None = component not matched / unknown."""
    comp = re.sub(r"[^a-z0-9]+", "", (component or "").lower())
    matched_component = False
    for cfg in (cve.get("configurations") or []):
        for node in (cfg.get("nodes") or []):
            for m in (node.get("cpeMatch") or []):
                crit = (m.get("criteria") or "").lower()
                if comp and comp in re.sub(r"[^a-z0-9]+", "", crit):
                    matched_component = True
                    si = m.get("versionStartIncluding"); ee = m.get("versionEndExcluding")
                    ei = m.get("versionEndIncluding")
                    if not version:
                        return True, (ee or None)
                    if _in_range(version, si, ee, ei):
                        return True, (ee or None)
                    # exact single-version CPE (…:plugin:VER:…)
                    parts = crit.split(":")
                    if len(parts) > 5 and parts[5] not in ("*", "-") and _vtuple(parts[5]) == _vtuple(version):
                        return True, None
    return (False if matched_component else None), None


def _nvd_query(component, limit=20, timeout=20):
    url = _NVD + "?" + urllib.parse.urlencode({"keywordSearch": component, "resultsPerPage": int(limit)})
    req = urllib.request.Request(url, headers={"User-Agent": "aegis-vuln-research/1.0 (authorized OSINT)"})
    try:
        with _opener().open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"_error": repr(e)[:160]}


def _parse_nvd(data, component, version):
    adv = []
    for v in (data.get("vulnerabilities") or []):
        cve = v.get("cve", {}) or {}
        cid = cve.get("id", "")
        descs = [d.get("value") for d in (cve.get("descriptions") or []) if d.get("lang") == "en"]
        summary = (descs[0] if descs else "")[:700]
        cvss = None
        metrics = cve.get("metrics", {}) or {}
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                try:
                    cvss = metrics[k][0].get("cvssData", {}).get("baseScore")
                except Exception:
                    cvss = None
                break
        refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")][:6]
        affects, fixed = _affects(cve, component, version)
        if affects is False:
            continue                                        # definitively a different version -> drop
        adv.append({"cve": cid, "cvss": cvss, "approach": summary, "references": refs,
                    "affects_this_version": affects, "fixed": fixed})
    adv.sort(key=lambda a: (a.get("affects_this_version") is True, a.get("cvss") or 0), reverse=True)
    return adv


def research(component, version="", limit=20, nvd_data=None):
    """Resolve the publicly-stated approach for a component+version. Returns
    {component, version, online, advisories:[{cve,cvss,approach,references,affects_this_version,fixed}], note}."""
    component = (component or "").strip()
    version = str(version or "")
    out = {"component": component, "version": version, "online": _online(), "advisories": []}
    if not component:
        out["note"] = "no component"
        return out
    data = nvd_data if nvd_data is not None else (_nvd_query(component, limit) if _online() else None)
    if data is None:
        out["note"] = "offline -- set AEGIS_RAG_ONLINE=1 or AEGIS_CVE_RESEARCH=1 for live advisory research"
        return out
    if data.get("_error"):
        out["note"] = "advisory source unreachable (%s) -- degraded to no advisories" % data["_error"]
        return out
    out["advisories"] = _parse_nvd(data, component, version)
    out["note"] = "%d advisory(ies); %d match this version" % (
        len(out["advisories"]), sum(1 for a in out["advisories"] if a.get("affects_this_version") is True))
    return out


def density(component, version="", nvd_data=None):
    """CLUMPINESS signal: vulnerabilities cluster -- a component with a DENSE CVE history is likelier to hide
    more (undiscovered) gaps, and dense areas are where escalation chains start. Returns a score from the CVE
    count (clustering), the count that affects THIS version (live relevance) and the peak CVSS (severity)."""
    r = research(component, version, nvd_data=nvd_data)
    adv = r.get("advisories", [])
    affecting = [a for a in adv if a.get("affects_this_version") is True]
    maxcvss = max([float(a.get("cvss") or 0) for a in adv] or [0.0])
    score = len(adv) * 1.0 + len(affecting) * 2.0 + maxcvss * 0.5
    return {"component": component, "version": version, "cve_count": len(adv),
            "affecting_count": len(affecting), "max_cvss": maxcvss, "score": round(score, 2),
            "online": r.get("online")}


def rank_by_density(components, nvd_by_comp=None):
    """components: iterable of (component, version). Returns density dicts sorted DENSEST-first, so the planner
    spends budget on the clustered/likely-vulnerable components before the thin ones. Offline-safe (score 0)."""
    out = []
    for item in components:
        comp, ver = (item if isinstance(item, (list, tuple)) else (item, ""))
        nd = (nvd_by_comp or {}).get(comp) if nvd_by_comp else None
        try:
            out.append(density(comp, ver, nvd_data=nd))
        except Exception:
            out.append({"component": comp, "version": ver, "cve_count": 0, "affecting_count": 0,
                        "max_cvss": 0.0, "score": 0.0})
    out.sort(key=lambda d: d["score"], reverse=True)
    return out


def grounding_brief(component, version, max_adv=4):
    """A compact, code-bench-ready block of the publicly-stated approaches for this component+version
    (version-affecting advisories first). Empty string if nothing relevant / offline."""
    r = research(component, version)
    adv = [a for a in r["advisories"] if a.get("affects_this_version") is not False][:max_adv]
    if not adv:
        return ""
    lines = ["PUBLIC ADVISORIES (the stated approach for this component+version):"]
    for a in adv:
        tag = "AFFECTS THIS VERSION" if a.get("affects_this_version") else "version-unconfirmed"
        lines.append("- %s (CVSS %s, %s): %s%s" % (a["cve"], a.get("cvss"), tag, a.get("approach", "")[:280],
                     (" | fixed in " + a["fixed"]) if a.get("fixed") else ""))
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    comp = sys.argv[1] if len(sys.argv) > 1 else "chaty-pro"
    ver = sys.argv[2] if len(sys.argv) > 2 else ""
    print(json.dumps(research(comp, ver), indent=2)[:3000])
