#!/usr/bin/env python3
"""G31: add STRUCTURED `preconditions` to techniques_db.json so the code_driver's applicability gate can
evaluate each technique against the live environment fingerprint (board: env-gated selection). Keeps the
existing free-text `applies_to` for other consumers. Idempotent -- re-runnable; only fills preconditions."""
import json, os, re, sys

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "techniques_db.json")

# map by SINK class first (id/class keyword -> the sink the technique needs)
SINK = {"ssti": "ssti", "template": "ssti", "ssrf": "ssrf", "xxe": "xxe", "xml": "xxe",
        "sqli": "sql", "nosqli": "sql", "sql": "sql", "deser": "deserialization", "pickle": "deserialization",
        "upload": "file_upload", "file": "file_upload"}


def preconditions_for(t):
    i = str(t.get("id", "")).lower()
    cls = str(t.get("class", "")).lower()
    blob = f"{i} {cls} {t.get('desc','')}".lower()
    pc = {}
    for kw, sink in SINK.items():
        if kw in i or kw in cls:
            pc["requires_sink"] = sink
            break
    if i.startswith("access.") or "authz" in blob or "idor" in blob or "role" in blob:
        pc["requires_roles"] = 2 if ("authz" in blob or "matrix" in blob or "idor" in blob) else 1
        pc["requires_endpoints"] = True
    if i.startswith(("logic.", "stateful.")) or "money" in blob or "idempot" in blob or "replay" in blob:
        pc["requires_endpoints"] = True
        pc["requires_mutation"] = True
    if i.startswith("recon.") or "discovery" in i:
        pc.setdefault("_note", "broadly applicable to any HTTP app")
    return pc


def main():
    d = json.load(open(DB, encoding="utf-8"))
    ts = d["techniques"] if isinstance(d, dict) else d
    changed = 0
    for t in ts:
        if isinstance(t.get("preconditions"), dict) and t["preconditions"]:
            continue
        pc = preconditions_for(t)
        if pc:
            t["preconditions"] = pc; changed += 1
    json.dump(d, open(DB, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"enriched {changed}/{len(ts)} techniques with structured preconditions")
    # show a few
    for t in ts:
        if t.get("id") in ("access.idor", "logic.money_bounds", "ssrf.outbound", "inj.ssti", "inj.sqli"):
            print(" ", t["id"], "->", t.get("preconditions"))


if __name__ == "__main__":
    main()
