"""digest.py -- cold-digest memory compression for long runs (ARTEX-port #7, pairs with frontier.py #5).

Hard targets need long runs; long runs blow the context window, and naive truncation drops exactly the
early recon facts a late-stage chain needs. This folds COLD exploration nodes (settled intents + findings
no longer feeding a live branch) into compact DIGEST summaries while keeping the HOT frontier (open/running
intents + their recent ancestors/children + recent findings) full-fidelity. A signature keeps an unchanged
cold block from being re-summarized. expand() restores a digest's members on demand.

  overview(run_id)        -> {hot:[...], digests:[{id,summary,members}], counts}
  expand(run_id, did)     -> the folded members of a digest
Gate AEGIS_DIGEST=0 (then overview returns everything hot).
"""
import os, json, time, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))


def _enabled():
    return str(os.environ.get("AEGIS_DIGEST", "1")).lower() not in ("0", "false", "no", "off")


def _findings(store_path=None, limit=400):
    path = store_path or os.path.join(HERE, "hunt_findings.jsonl")
    out = []
    try:
        for line in open(path, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("type") == "record":
                f = o.get("finding", {})
                out.append({"id": f.get("finding_id", ""), "ct": f.get("claim_type", "?"),
                            "sev": f.get("severity", "?"), "status": f.get("status", "?"),
                            "summary": (f.get("summary", "") or "")[:80],
                            "ts": o.get("ts", 0) if isinstance(o.get("ts"), (int, float)) else 0})
    except Exception:
        pass
    return out[-limit:]


def overview(run_id="default", store_path=None, hot_window=1800.0):
    """Compact situational overview: HOT (recent + VERIFIED) full; COLD folded into digests by claim-class."""
    fs = _findings(store_path)
    now = time.time()
    # HOT = verified (always) + anything within the recent time window; COLD = the settled rest
    hot = [f for f in fs if f["status"] in ("verified", "confirmed") or (now - f["ts"]) < hot_window]
    cold = [f for f in fs if f not in hot]
    if not _enabled():
        return {"hot": fs, "digests": [], "counts": {"total": len(fs)}}
    # fold cold by claim-class into digest blocks
    groups = {}
    for f in cold:
        groups.setdefault(f["ct"], []).append(f)
    digests = []
    for ct, members in sorted(groups.items()):
        sig = hashlib.sha1(("|".join(m["id"] for m in members)).encode()).hexdigest()[:10]
        sevs = {}
        for m in members:
            sevs[m["sev"]] = sevs.get(m["sev"], 0) + 1
        digests.append({"id": f"dg-{ct}-{sig}", "class": ct, "n": len(members),
                        "summary": f"{len(members)} {ct} (" + ",".join(f"{k}:{v}" for k, v in sevs.items())
                                   + ") -- settled; expand for members",
                        "member_ids": [m["id"] for m in members]})
    return {"hot": sorted(hot, key=lambda f: f["ts"])[-30:], "digests": digests,
            "counts": {"total": len(fs), "hot": len(hot), "cold_folded": len(cold), "digests": len(digests)}}


def expand(run_id="default", digest_id="", store_path=None):
    ov = overview(run_id, store_path)
    for d in ov["digests"]:
        if d["id"] == digest_id:
            ids = set(d["member_ids"])
            return [f for f in _findings(store_path) if f["id"] in ids]
    return []


def planner_block(run_id="default", store_path=None):
    """One compact block for the planner: verified + recent hot findings, then cold digests (not raw)."""
    ov = overview(run_id, store_path)
    L = [f"situational: {ov['counts']}"]
    for f in ov["hot"][-12:]:
        L.append(f"  [{f['status'][:4]}/{f['sev'][:4]}] {f['ct']}: {f['summary']}")
    for d in ov["digests"][:8]:
        L.append(f"  (digest {d['id']}) {d['summary']}")
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    print(planner_block(sys.argv[1] if len(sys.argv) > 1 else "default"))
