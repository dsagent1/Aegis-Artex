#!/usr/bin/env python3
"""
recovery.py -- unified error-recovery / self-healing for long autonomous hunts (discovery gap #4).

Today recovery is scattered and shallow (_is_transient 3-retry in aegis_operator, _dead_try_reason in
code_driver, run_monitor/oom-triage for hangs). This centralizes it: a single failure CLASSIFIER +
per-class recovery LADDER (escalating by attempt) + a light CHECKPOINT/restore, so a branching run adapts
around rate-limits / auth-expiry / transient-net / tool-OOM / missing-tool / target-down instead of
stalling -- which is what sustains the long runs deep hypotheses need.

This is sustaining plumbing (the board's read: robustness, not a direct novelty driver), kept pure so the
policy is testable offline. Callers ask `decide(...)` what to do next and act on the returned action.
Opt-in wiring ($AEGIS_RECOVERY) is left to the loop; the policy itself is always import-safe. Stdlib only.
"""
from __future__ import annotations

import json
import os
import random
import re
import time

# error types
RATE_LIMIT = "rate_limit"
AUTH_EXPIRY = "auth_expiry"
TRANSIENT_NET = "transient_net"
TOOL_OOM = "tool_oom"
TOOL_MISSING = "tool_missing"
TARGET_DOWN = "target_down"
PARSE_ERROR = "parse_error"
DESTRUCTIVE_BLOCKED = "destructive_blocked"
UNKNOWN = "unknown"

# recovery actions
RETRY = "retry"                  # try the same thing again (transient)
BACKOFF = "backoff"             # wait `delay` then retry (rate-limit / target flap)
RELOGIN_RESUME = "relogin_resume"   # refresh the session/token, then resume the leg
LIGHTER_PARAMS = "lighter_params"   # re-run with reduced footprint (OOM)
ALT_TOOL = "alt_tool"          # switch to an alternative tool for the same goal
SKIP = "skip"                  # give up on THIS leg, keep hunting
ABORT = "abort"                # the whole run can't proceed (target gone)

# classification patterns (checked in order; first match wins). status codes handled separately.
_PATTERNS = [
    (RATE_LIMIT, r"rate.?limit|too many requests|\b429\b|retry-after|quota exceeded|throttl"),
    (AUTH_EXPIRY, r"token expired|session expired|csrf|invalid token|not authenticated|login required|\b401\b|\b403\b"),
    (TOOL_OOM, r"out of memory|oom-|oomkilled|cannot allocate|memoryerror|killed process|javascript heap out of memory"),
    (TOOL_MISSING, r"command not found|not installed|no such file|err_module_not_found|cannot find module|executable .* not found"),
    (TARGET_DOWN, r"connection refused|could not connect|name or service not known|no route to host|failed to establish"),
    (TRANSIENT_NET, r"timeout|timed out|connection reset|econnreset|temporarily unavailable|\b50[234]\b|read timed out"),
    (DESTRUCTIVE_BLOCKED, r"non-destructive|destructive.*blocked|blocked by .*doctrine|erase/drop/delete"),
    (PARSE_ERROR, r"expecting value|unexpected token|json ?decode|failed to parse|malformed"),
]


def classify(error_text: str = "", status=None) -> str:
    """Map an error string (+ optional HTTP status) to an ErrorType. Deterministic, pure."""
    t = (error_text or "").lower()
    try:
        st = int(status) if status is not None else None
    except (TypeError, ValueError):
        st = None
    if st == 429:
        return RATE_LIMIT
    if st in (401, 403):
        return AUTH_EXPIRY
    if st in (502, 503, 504):
        return TRANSIENT_NET
    for etype, pat in _PATTERNS:
        if re.search(pat, t):
            return etype
    return UNKNOWN


# per-type recovery LADDER: action at attempt 1, 2, 3+ (last entry repeats/terminal)
_LADDER = {
    RATE_LIMIT:          [BACKOFF, BACKOFF, SKIP],
    AUTH_EXPIRY:         [RELOGIN_RESUME, RELOGIN_RESUME, SKIP],
    TRANSIENT_NET:       [RETRY, BACKOFF, SKIP],
    TOOL_OOM:            [LIGHTER_PARAMS, ALT_TOOL, SKIP],
    TOOL_MISSING:        [ALT_TOOL, SKIP],
    TARGET_DOWN:         [BACKOFF, BACKOFF, ABORT],   # target truly gone -> abort the run
    PARSE_ERROR:         [RETRY, SKIP],
    DESTRUCTIVE_BLOCKED: [SKIP],                       # never retry a blocked destructive action
    UNKNOWN:             [RETRY, SKIP],
}


def backoff_delay(attempt: int, base: float = 2.0, cap: float = 60.0, retry_after=None) -> float:
    """Exponential backoff with jitter; honors a server Retry-After when provided."""
    if retry_after is not None:
        try:
            return max(0.0, float(retry_after))
        except (TypeError, ValueError):
            pass
    return round(min(cap, base * (2 ** max(0, attempt - 1))) + random.uniform(0, base), 2)


class RecoveryPolicy:
    """Tracks per-failure-signature attempt counts and returns the escalating recovery decision."""
    def __init__(self, max_attempts: int = 3):
        self.max_attempts = max_attempts
        self.attempts: dict = {}   # signature -> count

    def decide(self, error_text: str = "", status=None, signature: str = None, retry_after=None) -> dict:
        etype = classify(error_text, status)
        sig = signature or etype
        n = self.attempts.get(sig, 0) + 1
        self.attempts[sig] = n
        ladder = _LADDER.get(etype, _LADDER[UNKNOWN])
        action = ladder[min(n, len(ladder)) - 1]
        # a run-wide attempt cap forces termination of the leg even if the ladder would keep going
        if n > self.max_attempts and action not in (ABORT,):
            action = SKIP
        delay = backoff_delay(n, retry_after=retry_after) if action == BACKOFF else 0.0
        return {"type": etype, "action": action, "attempt": n, "delay": delay,
                "reason": f"{etype} attempt {n} -> {action}"}

    def reset(self, signature: str = None):
        if signature is None:
            self.attempts.clear()
        else:
            self.attempts.pop(signature, None)


# ---- light checkpoint/restore so a run can snapshot before a risky leg and resume ----
def save_checkpoint(path: str, state: dict) -> bool:
    try:
        tmp = path + ".tmp"
        json.dump({"state": state, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                  open(tmp, "w", encoding="utf-8"))
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def load_checkpoint(path: str):
    try:
        return json.load(open(path, encoding="utf-8")).get("state")
    except Exception:
        return None


def active() -> bool:
    return str(os.environ.get("AEGIS_RECOVERY", "")).lower() in ("1", "true", "yes", "on")
