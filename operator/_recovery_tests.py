#!/usr/bin/env python3
"""Offline tests for recovery.py (failure classifier + recovery ladder + checkpoint). No network.
Run: python operator/_recovery_tests.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import recovery as R  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

# --- classify (text) ---
ok("rate-limit text", R.classify("HTTP 429 Too Many Requests, retry-after 30") == R.RATE_LIMIT)
ok("auth-expiry text", R.classify("session expired, csrf token invalid") == R.AUTH_EXPIRY)
ok("oom text", R.classify("Killed: process ran out of memory") == R.TOOL_OOM)
ok("tool-missing text", R.classify("sqlmap: command not found") == R.TOOL_MISSING)
ok("target-down text", R.classify("curl: (7) connection refused") == R.TARGET_DOWN)
ok("transient text", R.classify("read timed out after 20s") == R.TRANSIENT_NET)
ok("destructive-blocked text", R.classify("blocked by non-destructive doctrine") == R.DESTRUCTIVE_BLOCKED)
ok("unknown text", R.classify("something weird happened") == R.UNKNOWN)

# --- classify (status codes) ---
ok("429 status -> rate_limit", R.classify("", status=429) == R.RATE_LIMIT)
ok("401 status -> auth_expiry", R.classify("", status=401) == R.AUTH_EXPIRY)
ok("503 status -> transient", R.classify("", status=503) == R.TRANSIENT_NET)

# --- recovery ladder escalates by attempt ---
p = R.RecoveryPolicy(max_attempts=3)
d1 = p.decide(status=429, retry_after=12)
ok("rate-limit attempt1 -> BACKOFF honoring retry-after", d1["action"] == R.BACKOFF and d1["delay"] == 12.0)
ok("rate-limit attempt2 -> BACKOFF", p.decide(status=429)["action"] == R.BACKOFF)
ok("rate-limit attempt3 -> SKIP (ladder terminal)", p.decide(status=429)["action"] == R.SKIP)

p2 = R.RecoveryPolicy()
ok("auth-expiry -> RELOGIN_RESUME first", p2.decide(status=401)["action"] == R.RELOGIN_RESUME)

p3 = R.RecoveryPolicy()
ok("OOM attempt1 -> LIGHTER_PARAMS", p3.decide("out of memory")["action"] == R.LIGHTER_PARAMS)
ok("OOM attempt2 -> ALT_TOOL", p3.decide("out of memory")["action"] == R.ALT_TOOL)
ok("OOM attempt3 -> SKIP", p3.decide("out of memory")["action"] == R.SKIP)

p4 = R.RecoveryPolicy()
ok("destructive-blocked -> SKIP (never retried)", p4.decide("blocked by non-destructive doctrine")["action"] == R.SKIP)

p5 = R.RecoveryPolicy()
ok("target-down escalates to ABORT", [p5.decide(status=None, error_text="connection refused")["action"] for _ in range(3)][-1] == R.ABORT)

# --- per-signature tracking is independent ---
p6 = R.RecoveryPolicy()
p6.decide(status=429, signature="sig-a"); p6.decide(status=429, signature="sig-a")
ok("distinct signatures track independently", p6.decide(status=429, signature="sig-b")["attempt"] == 1)
p6.reset("sig-a")
ok("reset clears a signature", p6.decide(status=429, signature="sig-a")["attempt"] == 1)

# --- backoff grows + is capped ---
ok("backoff grows with attempt", R.backoff_delay(3) > R.backoff_delay(1))
ok("backoff capped", R.backoff_delay(20, cap=60) <= 60 + 2)

# --- checkpoint roundtrip ---
d = tempfile.mkdtemp(); cp = os.path.join(d, "ckpt.json")
ok("save_checkpoint ok", R.save_checkpoint(cp, {"queue": [1, 2], "tried": ["x"]}) is True)
ok("load_checkpoint restores state", R.load_checkpoint(cp) == {"queue": [1, 2], "tried": ["x"]})
ok("load missing checkpoint -> None", R.load_checkpoint(os.path.join(d, "nope.json")) is None)

# --- opt-in flag ---
os.environ.pop("AEGIS_RECOVERY", None)
ok("inert by default", R.active() is False)
os.environ["AEGIS_RECOVERY"] = "1"
ok("active when enabled", R.active() is True)
os.environ.pop("AEGIS_RECOVERY", None)

n = 26
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
