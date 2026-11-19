#!/usr/bin/env python3
"""run_log.py -- consolidate ALL of a campaign's scattered telemetry into ONE consultable run-log timeline,
for framework improvement + "what's not working" diagnosis.

Today a run's story is spread across: campaigns/<c>/progress.json (phase/terminal/coverage/reachability),
campaigns/<c>/findings.jsonl (candidate/verified/rejected + oracle receipts, hash-chained), campaigns/<c>/
interventions.jsonl (mishaps), operator/coder_events.jsonl (code write/exec/dead), and the audit logs
(distro_run_audit / redteam_audit / foothold_audit / c2_audit). This merges the ts-bearing events into a
single time-ordered timeline + a summary, and writes RUN_LOG_<campaign>.md.

Usage:  python operator/run_log.py <campaign> [--since <epoch>] [--out FILE]
"""
import os, sys, json, glob, time, argparse

HERE = os.path.dirname(os.path.abspath(__file__))


def _read_jsonl(path, since=0):
    out = []
    if not os.path.exists(path):
        return out
    for ln in open(path, encoding="utf-8", errors="replace"):
        ln = ln.strip()
        if not ln:
            continue
        try:
            d = json.loads(ln)
        except Exception:
            continue
        ts = d.get("ts") or d.get("time") or 0
        if isinstance(ts, str):
            try: ts = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
            except Exception: ts = 0
        if ts and ts < since:
            continue
        out.append((ts, d))
    return out


import re as _re
# stdout failure signatures (leg errors, supervised kills, infra faults) -> WHAT WENT WRONG
_FAIL_PATS = [
    ("traceback", r"traceback \(most recent call last\)"), ("exception", r"\b\w*error\b:|\bexception\b"),
    ("supervised_kill", r"\[supervised (output_silence|hard_timeout|no_progress|aborted[_ ]target[_ ]down)"),
    ("run_error", r"run error:"), ("db_error", r"\[db error"), ("unreachable", r"HTTP 000|connection refused|max retries"),
    ("no_code", r"bench produced no code|\[raw reasoning"), ("login_fail", r"login .*failed|\[abort\].*login|401"),
    ("cf_timeout", r"unavailable, skipping|read operation timed out"), ("leg_error", r"status=error|reason=(?!exit)\w+"),
]


def build(campaign, since=0, log_path=None):
    cdir = os.path.join(HERE, "campaigns", campaign)
    # AUTO-SCOPE: coder_events/audits are GLOBAL files -> derive the campaign window from the earliest
    # finding ts so stale prior-run events don't pollute this campaign's log. Explicit --since overrides.
    if not since:
        fts = [ts for ts, _ in _read_jsonl(os.path.join(cdir, "findings.jsonl"), 0) if ts]
        if fts:
            since = min(fts) - 30
    ev = []  # (ts, kind, detail, is_fail, where)
    cur_phase = "?"
    for ts, d in _read_jsonl(os.path.join(cdir, "findings.jsonl"), since):
        if d.get("type") == "record":
            f = d.get("finding", {})
            ev.append((ts, "PROPOSE", f"{f.get('claim_type')} [{f.get('severity')}] {str(f.get('summary'))[:100]}", False, ""))
        elif d.get("type") == "transition":
            rec = d.get("oracle_receipt") or {}
            st = str(d.get("status", "?")).lower()
            fail = st in ("rejected", "errored", "inconclusive")
            ev.append((ts, "VERDICT", f"{st.upper()} {d.get('finding_id','')[:10]} oracle={d.get('oracle_id','')} "
                                      f"{json.dumps(rec)[:90] if rec else ''}", fail, ""))
    for ts, d in _read_jsonl(os.path.join(HERE, "coder_events.jsonl"), since):
        fail = d.get("status") == "dead_try" or (d.get("code_valid") is False)
        ev.append((ts, "CODER", f"{d.get('source','')} s{d.get('step')}/{d.get('direction')} valid={d.get('code_valid')} "
                                f"exec={d.get('executed')} status={d.get('status')} {d.get('dead_reason') or d.get('reason') or ''}",
                   fail, f"s{d.get('step')}/{d.get('direction')}"))
    for ts, d in _read_jsonl(os.path.join(cdir, "interventions.jsonl"), since):
        ev.append((ts, "MISHAP", f"{d.get('signature')} -> {d.get('action')} = {d.get('outcome')}", True, d.get("step_id", "")))
    for name in ("distro_run_audit", "redteam_audit", "foothold_audit", "c2_audit"):
        for ts, d in _read_jsonl(os.path.join(HERE, name + ".jsonl"), since):
            fail = (d.get("ok") is False) or (d.get("rc") not in (0, None))
            ev.append((ts, name.split("_")[0].upper(), json.dumps({k: d[k] for k in list(d)[:5]})[:100], fail, ""))
    # stdout log: leg-level failures the jsonl streams don't carry (tracebacks, supervised kills, cf timeouts)
    if log_path and os.path.exists(log_path):
        b = open(log_path, "rb").read()
        t = b.decode("utf-16-le", "ignore") if b.count(bytes([0])) > len(b) // 4 else b.decode("utf-8", "ignore")
        for line in t.splitlines():
            lo = line.lower()
            m = _re.search(r"phase (\w+) ->", lo)
            if m: cur_phase = m.group(1)
            for fk, pat in _FAIL_PATS:
                if _re.search(pat, lo):
                    ev.append((0, "FAIL:" + fk, line.strip().encode("ascii", "replace").decode()[:140], True, cur_phase))
                    break
    ev.sort(key=lambda x: x[0] or 0)
    return cdir, ev


def render(campaign, since=0, log_path=None):
    from collections import Counter
    cdir, ev = build(campaign, since, log_path)
    try:
        p = json.load(open(os.path.join(cdir, "progress.json"), encoding="utf-8"))
    except Exception:
        p = {}
    L = [json.loads(l) for l in open(os.path.join(cdir, "findings.jsonl"), encoding="utf-8") if l.strip()] \
        if os.path.exists(os.path.join(cdir, "findings.jsonl")) else []
    trans = Counter(d.get("status") for d in L if d.get("type") == "transition")
    cls = Counter(d["finding"].get("claim_type") for d in L if d.get("type") == "record" and isinstance(d.get("finding"), dict))
    out = [f"# RUN LOG — {campaign}", "",
           f"- terminal: **{p.get('terminal_reason')}**  phase={p.get('phase')} mode={p.get('mode')}",
           f"- reachability: {p.get('reachability')}",
           f"- coverage_omissions: {p.get('coverage_omissions')}",
           f"- remediation: {p.get('remediation')}",
           f"- verdicts: {dict(trans)}",
           f"- hypothesis classes tried: {dict(cls.most_common(15))}",
           f"- events in timeline: {len(ev)}", ""]
    # FAILURES first -- "what went wrong, where" (the diagnosis the board/dev needs)
    fails = [(ts, k, det, where) for (ts, k, det, is_fail, where) in ev if is_fail]
    ftypes = Counter(k for _, k, _, _ in fails)
    out += ["## FAILURES — what went wrong, where (" + str(len(fails)) + ")", "",
            f"by type: {dict(ftypes)}", ""]
    for ts, k, det, where in fails[:60]:
        hh = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "--:--:--"
        out.append(f"`{hh}` **{k}** {('@'+where+' ') if where else ''}{det}")
    out += ["", "## TIMELINE (PROPOSE=hypothesis · CODER=code write/exec · VERDICT=oracle · MISHAP · FAIL:* · audits)", ""]
    for ts, kind, det, is_fail, where in ev:
        hh = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "--:--:--"
        out.append(f"`{hh}` {'⚠ ' if is_fail else ''}**{kind}** {det}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign")
    ap.add_argument("--since", type=float, default=0)
    ap.add_argument("--out", default=None)
    ap.add_argument("--log", default=None, help="stdout log to mine for leg-level failures (tracebacks, supervised kills)")
    a = ap.parse_args()
    md = render(a.campaign, a.since, a.log)
    out = a.out or os.path.join(HERE, "..", f"RUN_LOG_{a.campaign}.md")
    open(out, "w", encoding="utf-8").write(md)
    print(f"run-log written: {out} ({md.count(chr(10))} lines)")
    print(md[:1500])


if __name__ == "__main__":
    main()
