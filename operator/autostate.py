#!/usr/bin/env python3
"""autostate.py -- AutoLoop state, budget ledger, and append-only learning (board build-order step 4).

Two append-only siblings to findings.jsonl, written best-effort (never raise), plus a resumable state file:
  - interventions.jsonl : every mishap intervention {ts, step_id, signature, action, cmd, outcome, attempt}
      -> never_repeated() blocks re-trying a (step_id, signature, action) that already FAILED.
  - progress.json       : {phase, legs_done, budget_consumed, last_finding_line, ...} -> resume mid-task.
  - Budget              : a global ledger (wallclock, model_spend_usd, legs, tool_calls, repairs, pivots)
                          with per-kind caps; reserve/consume + exhausted().
"""
import os, sys, json, time

TERMINALS = ("COMPLETE", "BUDGET_EXHAUSTED", "STUCK", "OUT_OF_SCOPE", "ABORTED")


def _camp_dir(campaign, root=None):
    root = root or os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(root, "campaigns", campaign)
    os.makedirs(d, exist_ok=True)
    return d


# ---------------- interventions ledger (never-repeat learning) ----------------
def record_intervention(campaign, rec, root=None):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **rec}
    try:
        p = os.path.join(_camp_dir(campaign, root), "interventions.jsonl")
        line = (json.dumps(rec) + "\n").encode("utf-8")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line)          # single O_APPEND write -> no interleave across concurrent runs (Pass 5b #6)
        finally:
            os.close(fd)
    except Exception:
        pass
    return rec


def read_interventions(campaign, root=None):
    out = []
    try:
        for ln in open(os.path.join(_camp_dir(campaign, root), "interventions.jsonl"), encoding="utf-8"):
            ln = ln.strip()
            if ln:
                try:
                    out.append(json.loads(ln))
                except Exception:
                    pass
    except Exception:
        pass
    return out


def never_repeated(campaign, step_id, signature, action, root=None):
    """False if a prior intervention with this (step_id, signature, action) already FAILED -- i.e. this
    exact fix was already tried and did not work, so the caller must move to the next rung ('I tried that')."""
    for r in read_interventions(campaign, root):
        if (r.get("step_id") == step_id and r.get("signature") == signature
                and r.get("action") == action and r.get("outcome") == "failed"):
            return False
    return True


def last_incidents(campaign, n=5, root=None):
    """The last n interventions -- accompany every deep-seat / Support call so it can't repeat a failed fix."""
    return read_interventions(campaign, root)[-n:]


# ---------------- resumable progress ----------------
def save_progress(campaign, state, root=None):
    try:
        p = os.path.join(_camp_dir(campaign, root), "progress.json"); tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:   # temp + atomic replace: the resume file is never
            json.dump(state, fh, indent=2)             # left half-written by a crash (Pass 5b #13)
        os.replace(tmp, p)
    except Exception:
        pass


def load_progress(campaign, root=None):
    try:
        return json.load(open(os.path.join(_camp_dir(campaign, root), "progress.json"), encoding="utf-8"))
    except Exception:
        return None


# ---------------- global budget ledger ----------------
class Budget:
    """Global run budget across all resource kinds. Per-leg budget stays separate (passed to step_runner)."""
    KINDS = ("wallclock_s", "model_spend_usd", "legs", "tool_calls", "repairs", "pivots")

    def __init__(self, wallclock_s=3600, model_spend_usd=5.0, legs=12, tool_calls=200, repairs=8, pivots=4):
        self.limits = {"wallclock_s": wallclock_s, "model_spend_usd": model_spend_usd, "legs": legs,
                       "tool_calls": tool_calls, "repairs": repairs, "pivots": pivots}
        self.used = {k: 0 for k in self.KINDS}
        self._t0 = time.time()

    def _refresh_wall(self):
        self.used["wallclock_s"] = round(time.time() - self._t0, 1)

    def can(self, kind, amount=1):
        if kind == "wallclock_s":
            self._refresh_wall()
        return self.used.get(kind, 0) + amount <= self.limits.get(kind, float("inf"))

    def consume(self, kind, amount=1):
        self.used[kind] = self.used.get(kind, 0) + amount
        return self.used[kind]

    def exhausted(self):
        """True if any hard resource is spent (wallclock or legs -- the two that end a run)."""
        self._refresh_wall()
        return (self.used["wallclock_s"] >= self.limits["wallclock_s"]
                or self.used["legs"] >= self.limits["legs"])

    def snapshot(self):
        self._refresh_wall()
        return {"limits": dict(self.limits), "used": dict(self.used)}


def count_findings(store_path):
    """G7 fix: authoritative campaign accounting from the DURABLE store (not step_runner's leg count).
    Aggregates by finding_id across the append-only ledger's mixed shapes -- a finding counts as CONFIRMED
    if ANY of its lines has verdict/status 'confirmed'/'verified' or a confirmed flag. Returns unique-per-
    finding {total, confirmed, candidate, rejected, confirmed_ids}.

    G20: the oracle ledger (shared/verified_findings) writes the passed status as 'verified', but this
    accounting only recognized 'confirmed' -- so a run with N verified findings reported confirmed=0 and
    the REMEDIATE stage self-skipped as 'no confirmed findings'. Treat 'verified' == 'confirmed' here."""
    by_id = {}; order = 0
    try:
        for ln in open(store_path, encoding="utf-8"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
            except Exception:
                continue
            f = d.get("finding") if isinstance(d.get("finding"), dict) else d
            fid = f.get("finding_id") or d.get("finding_id")
            if not fid:
                order += 1; fid = f"_anon{order}"
            rec = by_id.setdefault(fid, {"status": None, "confirmed": False})
            verdict = str(d.get("verdict") or f.get("verdict") or "").lower()
            status = str(f.get("status") or d.get("status") or "").lower()
            if verdict in ("confirmed", "verified") or status in ("confirmed", "verified") \
                    or f.get("confirmed") or d.get("confirmed"):
                rec["confirmed"] = True
            if status:
                rec["status"] = status          # last status wins (candidate -> rejected/inconclusive/...)
    except FileNotFoundError:
        return {"total": 0, "confirmed": 0, "candidate": 0, "rejected": 0, "inconclusive": 0,
                "errored": 0, "confirmed_ids": []}
    except Exception:
        pass
    confirmed_ids = [k for k, r in by_id.items() if r["confirmed"]]
    def _n(st):
        return sum(1 for r in by_id.values() if not r["confirmed"] and r["status"] == st)
    return {"total": len(by_id), "confirmed": len(confirmed_ids),
            "candidate": _n("candidate"), "rejected": _n("rejected"),
            # G17: 'inconclusive' (e.g. the probe couldn't reach the target -> not tested) and 'error' must
            # be surfaced, NOT hidden -- a run that couldn't complete its tests is not a clean "0 confirmed".
            "inconclusive": _n("inconclusive"), "errored": _n("error") + _n("errored"),
            "confirmed_ids": confirmed_ids}


def new_autostate(campaign, phase="BRINGUP"):
    return {"campaign": campaign, "mode": "ACTIVE", "terminal_reason": None, "phase": phase,
            "phases_done": [], "confirmed_n": 0, "stall_ticks": 0, "incidents": [], "gate": None}


if __name__ == "__main__":
    import tempfile
    root = tempfile.mkdtemp()
    c = "test-camp"
    record_intervention(c, {"step_id": "operator", "signature": "file_lock", "action": "skip",
                            "outcome": "failed", "attempt": 1}, root=root)
    assert never_repeated(c, "operator", "file_lock", "skip", root=root) is False, "should block repeat"
    assert never_repeated(c, "operator", "permission", "retry_kali", root=root) is True, "unseen -> allowed"
    print("interventions never-repeat: OK")
    save_progress(c, {"phase": "DISCOVER", "legs_done": 2}, root=root)
    assert load_progress(c, root=root)["legs_done"] == 2
    print("progress resume: OK")
    b = Budget(wallclock_s=3600, legs=3)
    b.consume("legs", 3)
    assert b.exhausted() is True, "legs cap -> exhausted"
    assert b.can("tool_calls", 1) is True
    print("budget ledger: OK ->", b.snapshot()["used"])
    print("ALL autostate tests PASS")
