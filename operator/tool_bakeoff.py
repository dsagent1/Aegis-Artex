#!/usr/bin/env python3
"""
tool_bakeoff.py -- NON-DESTRUCTIVE tool bake-off across the ExploitGym scenarios, for the benchmark.

Runs standard OSS scanners against each CONTAINED, OWNED twin and compares per-scenario RECALL of the
intended vuln class vs the AEGIS operator:
  DAST (black-box, URL target): nuclei, sqlmap, nikto, wapiti, zap   (compare_recall.ADAPTERS)
  SAST (grey-box, source dir)  : semgrep                              (compare_recall.SOURCE_ADAPTERS)

The scanners are FIND/VERIFY tools run non-destructively against twins you own -- this is a measurement
(who covers what), NOT an autonomous attack. Emits a coverage/FP matrix (tool x scenario) + the
operator's row, so the benchmark can answer "where does the AI operator add coverage the standard
suites miss?" (historically the authz / business-logic / trust-chain classes DAST is weak on).

Core (scenario->class mapping, recall, matrix, markdown) is pure + offline-testable; the live tool runs
go through the injectable collectors. Owned/contained targets only.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare_recall as CR   # ADAPTERS, SOURCE_ADAPTERS, match_expected, CLASS_KW

# intended_vuln free-text -> our class key (most specific first)
INTENT_CLASS = [
    ("mass-assignment", "mass_assignment"), ("mass assignment", "mass_assignment"),
    ("ssrf", "ssrf"), ("server-side request", "ssrf"),
    ("privilege escalation", "privesc"), ("privesc", "privesc"),
    ("idor", "idor"), ("insecure direct object", "idor"),
    ("broken access", "authz"), ("access control", "authz"), ("authorization", "authz"),
    ("supply", "supply_chain"), ("dependency", "supply_chain"), ("known cve", "supply_chain"),
    ("command injection", "rce"), ("remote code", "rce"), ("rce", "rce"),
    ("sql", "injection"), ("injection", "injection"),
    ("xss", "xss"), ("cross-site scripting", "xss"),
    ("traversal", "traversal"), ("file inclusion", "traversal"),
    ("misconfig", "misconfig"), ("exposed", "misconfig"),
]

# fuller-parity Kali arsenal (individual find/verify tools -- the scanners HexStrike wraps, minus its
# autonomous orchestration). Run a subset per box for memory (nuclei,sqlmap,semgrep light; zap heaviest).
DAST_DEFAULT = ["nuclei", "sqlmap", "nikto", "wapiti", "zap", "nmap", "ffuf", "dalfox"]
# BlackArch/Arch recon+discovery arsenal (routed via distro_backend; attack-surface enumeration, passive/
# non-destructive). Kept separate: they enumerate SURFACE (feed coverage) rather than recall vuln-classes.
RECON_DEFAULT = ["katana", "gau", "waybackurls", "hakrawler", "x8", "gowitness"]
SAST_DEFAULT = ["semgrep"]


def class_of(intended_vuln: str) -> str:
    iv = (intended_vuln or "").lower()
    return next((c for sub, c in INTENT_CLASS if sub in iv), "")


def scenario_expected(sc) -> dict:
    """Derive a compare_recall-style `expected` entry from an ExploitGym scenario."""
    hops = getattr(getattr(sc, "evidence", None), "hops", None) or []
    surface = ((hops[0].get("check") or {}).get("path") if hops else "") or ""
    return {"id": getattr(sc, "id", "?"), "class": class_of(getattr(sc, "intended_vuln", "")),
            "surface": surface, "match": []}


def recalled(expected: dict, blobs) -> bool:
    """True iff the tool's output blobs recall the scenario's intended class (compare_recall's rule)."""
    per = CR.match_expected([expected], blobs or [])
    return bool(per and per[0].get("recalled"))


def build_matrix(expecteds: list, blobs_by_scen_tool: dict, operator_hits: dict) -> dict:
    """expecteds: [expected,...]; blobs_by_scen_tool: {scen_id: {tool: [blobs]}}; operator_hits: {scen_id: bool}.
    Returns {tools, scen_ids, rows:{name:{scen_id:bool}}, recall:{name:(hits,total)}, operator_unique:[scen_ids]}."""
    scen_ids = [e["id"] for e in expecteds]
    exp_by_id = {e["id"]: e for e in expecteds}
    tools = sorted({t for m in blobs_by_scen_tool.values() for t in m})
    rows = {}
    for tool in tools:
        rows[tool] = {sid: recalled(exp_by_id[sid], (blobs_by_scen_tool.get(sid) or {}).get(tool, []))
                      for sid in scen_ids}
    rows["AEGIS-operator"] = {sid: bool(operator_hits.get(sid)) for sid in scen_ids}
    recall = {name: (sum(1 for v in r.values() if v), len(scen_ids)) for name, r in rows.items()}
    # scenarios the operator recalled that NO standard tool did (the differentiator)
    op = rows["AEGIS-operator"]
    op_unique = [sid for sid in scen_ids if op[sid] and not any(rows[t][sid] for t in tools)]
    return {"tools": tools, "scen_ids": scen_ids, "rows": rows, "recall": recall, "operator_unique": op_unique}


def to_markdown(matrix: dict) -> str:
    scen_ids, rows, recall = matrix["scen_ids"], matrix["rows"], matrix["recall"]
    short = [s[:22] for s in scen_ids]
    L = ["# Tool bake-off -- non-destructive coverage across contained ExploitGym scenarios", "",
         "Recall of each scenario's INTENDED vuln class (find/verify only; owned twins).", "",
         "| tool/operator | " + " | ".join(short) + " | recall |",
         "|" + "---|" * (len(short) + 2)]
    order = [n for n in rows if n != "AEGIS-operator"] + ["AEGIS-operator"]
    for name in order:
        cells = ["✓" if rows[name][sid] else "·" for sid in scen_ids]
        h, t = recall[name]
        L.append(f"| {name} | " + " | ".join(cells) + f" | {h}/{t} |")
    if matrix["operator_unique"]:
        L += ["", "**Operator-unique coverage** (recalled by the operator, missed by every standard tool): "
              + ", ".join(matrix["operator_unique"])]
    return "\n".join(L)


def collect_live(scenarios, dast_tools, sast_tools, url_of, src_of) -> dict:
    """Run each tool ONE AT A TIME (memory-safe) and collect blobs. url_of(sc)->URL, src_of(sc)->source dir.
    Returns {scen_id: {tool: [blobs]}}. Live (Kali); owned/contained twins only."""
    out = {}
    for sc in scenarios:
        sid = getattr(sc, "id", "?")
        out[sid] = {}
        url = url_of(sc) if url_of else None
        src = src_of(sc) if src_of else None
        for tool in dast_tools:
            if tool in CR.ADAPTERS and url:
                blobs, _note = CR.ADAPTERS[tool](url)
                out[sid][tool] = blobs
        for tool in sast_tools:
            if tool in CR.SOURCE_ADAPTERS and src:
                blobs, _note = CR.SOURCE_ADAPTERS[tool](src)
                out[sid][tool] = blobs
    return out


def main():
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Non-destructive tool bake-off across ExploitGym scenarios.")
    ap.add_argument("scenarios_dir")
    ap.add_argument("--dast", default=",".join(DAST_DEFAULT))
    ap.add_argument("--sast", default=",".join(SAST_DEFAULT))
    ap.add_argument("--targets", help="JSON {scenario_id: url} for the provisioned twins (DAST)")
    ap.add_argument("--operator-hits", help="JSON {scenario_id: bool} from eg_results scorecards")
    ap.add_argument("--out", default=os.path.join(HERE, "..", "exploitgym", "TOOL_BAKEOFF.md"))
    a = ap.parse_args()
    sys.path.insert(0, os.path.join(HERE, "..", "exploitgym"))
    from exploitgym.scenario import load_dir
    scens = load_dir(a.scenarios_dir)
    expecteds = [scenario_expected(sc) for sc in scens]
    targets = json.load(open(a.targets)) if a.targets else {}
    op_hits = json.load(open(a.operator_hits)) if a.operator_hits else {}
    url_of = (lambda sc: targets.get(getattr(sc, "id", ""))) if targets else (lambda sc: None)
    src_of = lambda sc: os.path.join(a.scenarios_dir, "..", "targets",
                                     os.path.basename(getattr(sc.target, "build", "")))
    blobs = collect_live(scens, a.dast.split(","), a.sast.split(","), url_of, src_of)
    matrix = build_matrix(expecteds, blobs, op_hits)
    md = to_markdown(matrix)
    open(a.out, "w", encoding="utf-8").write(md)
    print(md)


if __name__ == "__main__":
    main()
