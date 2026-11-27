"""frontier.py -- open exploration FRONTIER: fact-synthesized intents + hint-steered re-plan (ARTEX-port #5).

Aegis's Planner ranks a (now richer) techniques DB -- a menu. On hard/novel targets the winning move is
usually a SYNTHESIS of observed facts that is in no menu ("chain this leaked path with that param"). This
adds an append-only frontier of open INTENTS (free-form exploration directions, not fixed types), anchored
on confirmed facts/findings, plus a HINT channel the planner reads at the top of the next round, plus three
success-critical disciplines:

  * HARD FLOOR: if the goal is unmet and no intent is open/running, the round MUST emit >=1 intent
    (never idle with the goal unmet -- the #1 autonomous-agent failure).
  * DEPTH > COVERAGE: after a high-value entry, drive THAT route deep before spreading.
  * DON'T CONVERGE EARLY: prefer a mechanism-distinct uncovered surface over synonyms (2-3 live routes).

State is a JSONL log keyed per run; it pairs with digest.py (#7) for long-run memory compression. The loop/
planner call open_intents() for directions and consume_hints() each round. Gate AEGIS_FRONTIER=0.
"""
import os, json, time, uuid, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))


def _path(run_id):
    rid = hashlib.sha1((run_id or "default").encode()).hexdigest()[:12]
    return os.path.join(HERE, f"frontier_{rid}.jsonl")


def _append(run_id, rec):
    try:
        with open(_path(run_id), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


def _read(run_id):
    out = []
    try:
        for line in open(_path(run_id), encoding="utf-8", errors="ignore"):
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return out


def _enabled():
    return str(os.environ.get("AEGIS_FRONTIER", "1")).lower() not in ("0", "false", "no", "off")


# ---- intents (open exploration directions) ----
def add_intent(run_id, summary, parent_facts=None, angle="", surface="", vuln_class="", origin="planner"):
    """Add an open exploration direction. parent_facts = ids of the CONFIRMED facts/findings it builds on
    (an intent should synthesize real observations, not restate the goal)."""
    iid = uuid.uuid4().hex[:10]
    _append(run_id, {"t": "intent", "id": iid, "summary": summary[:300], "state": "open",
                     "parents": parent_facts or [], "angle": angle, "surface": surface,
                     "vuln_class": vuln_class, "origin": origin, "ts": time.time()})
    return iid


def set_state(run_id, iid, state):
    _append(run_id, {"t": "state", "id": iid, "state": state, "ts": time.time()})


def _latest_state(recs):
    st = {}
    for r in recs:
        if r.get("t") == "intent":
            st[r["id"]] = dict(r)
        elif r.get("t") == "state" and r.get("id") in st:
            st[r["id"]]["state"] = r["state"]
    return st


def open_intents(run_id):
    st = _latest_state(_read(run_id))
    return [v for v in st.values() if v.get("state") in ("open", "running")]


def counts(run_id):
    st = _latest_state(_read(run_id))
    c = {}
    for v in st.values():
        c[v.get("state", "open")] = c.get(v.get("state", "open"), 0) + 1
    return c


# ---- hints (strategic steering the planner reads NEXT round) ----
def add_hint(run_id, text, origin="board"):
    _append(run_id, {"t": "hint", "id": uuid.uuid4().hex[:8], "text": text[:280],
                     "origin": origin, "consumed": False, "ts": time.time()})


def consume_hints(run_id):
    """Return unconsumed hints and mark them consumed (planner reads them at the top of the round)."""
    recs = _read(run_id)
    consumed = {r["id"] for r in recs if r.get("t") == "hint-consumed"}
    hints = [r for r in recs if r.get("t") == "hint" and r["id"] not in consumed]
    for h in hints:
        _append(run_id, {"t": "hint-consumed", "id": h["id"], "ts": time.time()})
    return [{"text": h["text"], "origin": h["origin"]} for h in hints]


# ---- disciplines ----
def hard_floor(run_id, goal_met: bool, running: int):
    """True => the planner MUST emit >=1 intent this round (goal unmet, nothing open/running)."""
    if goal_met:
        return False
    return (len(open_intents(run_id)) == 0 and running == 0)


def planner_block(run_id):
    """A compact situational block for the planner prompt: open directions + fresh hints + the floor rule."""
    oi = open_intents(run_id)
    hints = consume_hints(run_id)
    lines = []
    if hints:
        lines.append("HINTS (steer this round): " + " | ".join(f"[{h['origin']}] {h['text']}" for h in hints[:5]))
    if oi:
        lines.append("OPEN DIRECTIONS (" + str(len(oi)) + "): "
                     + " | ".join(f"{i.get('angle') or i.get('vuln_class') or '?'}:{i['summary'][:60]}" for i in oi[:6]))
    else:
        lines.append("NO open direction -- if the goal is unmet you MUST emit at least one new, "
                     "fact-anchored direction this round (hard floor; do not idle).")
    lines.append("Discipline: depth over coverage after a high-value entry; keep 2-3 mechanism-DISTINCT "
                 "routes, don't converge on synonyms; dispatch serial chains step-by-step.")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    rid = sys.argv[1] if len(sys.argv) > 1 else "demo"
    add_intent(rid, "chain the leaked /wp-json user id into the password-reset flow", angle="authz")
    add_hint(rid, "focus elementor-pro 3.35.1 -- check its known CVEs first", origin="board")
    print(planner_block(rid))
    print("counts:", counts(rid))
