#!/usr/bin/env python3
"""hunt_monitor.py -- LIVE execution monitor for a running Aegis hunt.

Shows what the loop is doing RIGHT NOW -- current attempt/leg/surface, run state, verified findings (live),
the latest novel-code attempt, and the egress IP -- by reading the RunMonitor heartbeat + the findings
ledger + coder_events. Not the board CHAT (that's board/live_board.ps1); this is the EXECUTION view.

  python operator/hunt_monitor.py            # live, refreshes every 2s
  python operator/hunt_monitor.py --once     # one snapshot
  AEGIS_HEARTBEAT=/path  AEGIS_MON_LEDGER=/path   # override locations
"""
import os, sys, json, time

HERE = os.path.dirname(os.path.abspath(__file__))
HB = os.environ.get("AEGIS_HEARTBEAT") or os.path.join(HERE, "run_heartbeat.json")
LEDGER = os.environ.get("AEGIS_MON_LEDGER") or os.path.join(HERE, "hunt_findings.jsonl")
CODER = os.path.join(HERE, "coder_events.jsonl")
_C = {"g": "\033[32m", "y": "\033[33m", "r": "\033[31m", "c": "\033[36m", "b": "\033[1m", "d": "\033[2m", "x": "\033[0m"}


def _j(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return {}


def _findings():
    rows = []
    try:
        for line in open(LEDGER, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("type") == "record":
                f = o.get("finding", {})
                ts = o.get("ts", 0)
                rows.append((ts if isinstance(ts, (int, float)) else 0, f.get("claim_type", "?"),
                             (f.get("summary", "") or "")[:62], f.get("status", "?"), f.get("severity", "?")))
    except Exception:
        pass
    return rows


def _last_coder():
    last = None
    try:
        for line in open(CODER, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)
                except Exception:
                    pass
    except Exception:
        pass
    return last


def render():
    hb = _j(HB)
    hb_age = (time.time() - os.path.getmtime(HB)) if os.path.exists(HB) else None
    L = []
    L.append(_C["b"] + "=" * 76 + _C["x"])
    L.append(f"{_C['b']}{_C['c']}  AEGIS HUNT- EXECUTION MONITOR{_C['x']}    {time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(_C["b"] + "=" * 76 + _C["x"])
    if hb and hb_age is not None and hb_age < 120:
        state = hb.get("state", "?")
        sc = _C["g"] if state == "running" else _C["y"]
        L.append(f"  run {sc}{state}{_C['x']}  stage={hb.get('stage','?')}  pid={hb.get('pid')}  "
                 f"hb_age={hb_age:.0f}s  id={str(hb.get('run_id',''))[:34]}")
        L.append(f"  attempt {_C['b']}{hb.get('attempt','?')}{_C['x']}   hung={hb.get('attempts_hung',0)}   "
                 f"last_event={hb.get('last_event','?')} @ {hb.get('last_event_at','?')}")
        L.append(f"  {_C['y']}NOW >{_C['x']} leg={_C['b']}{hb.get('current_leg','?')}{_C['x']}   "
                 f"surface={hb.get('current_surface','') or '-'}   cov={hb.get('coverage','')}")
        if hb.get("last_error"):
            L.append(f"  {_C['r']}last_error:{_C['x']} {str(hb['last_error'])[:68]}")
    else:
        L.append(f"  {_C['d']}(no live heartbeat- no hunt running, or it finished; hb_age="
                 f"{('%.0fs' % hb_age) if hb_age is not None else 'n/a'}){_C['x']}")
    rows = _findings()
    verified = [r for r in rows if r[3] == "verified"]
    sev = {}
    for r in verified:
        sev[r[4]] = sev.get(r[4], 0) + 1
    L.append("-" * 76)
    L.append(f"  findings ledger: {len(rows)}   {_C['g']}VERIFIED: {len(verified)}{_C['x']}  "
             + " ".join(f"{k}={v}" for k, v in sorted(sev.items())))
    for ts, ct, s, st, sv in sorted(rows, key=lambda r: r[0])[-6:]:
        col = _C["g"] if st == "verified" else _C["d"]
        L.append(f"   {col}[{st[:4]:4}/{sv[:4]:4}] {ct:26.26} {s}{_C['x']}")
    lc = _last_coder()
    if lc:
        L.append("-" * 76)
        L.append(f"  novel-code: step={lc.get('step')} dir={lc.get('direction')} "
                 f"status={lc.get('status') or lc.get('dead_reason') or '?'} "
                 f"exec={lc.get('executed')} angle={str(lc.get('angle'))[:30]}")
    L.append(_C["b"] + "=" * 76 + _C["x"])
    return "\n".join(L)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows cp1252 console safety
    except Exception:
        pass
    once = "--once" in sys.argv
    try:
        while True:
            sys.stdout.write(("\033[2J\033[H" if not once else "") + render() + "\n")
            sys.stdout.flush()
            if once:
                break
            time.sleep(float(os.environ.get("AEGIS_MON_REFRESH", "2")))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
