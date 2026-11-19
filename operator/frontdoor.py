#!/usr/bin/env python3
"""
frontdoor.py -- D8 wiring: the FRONT-DOOR vector that makes BruteForceFeasibility / UserEnumeration /
PinPolicy part of the discovery/zero-day loop (not just standalone oracle classes).

Registered into vectors.LEGS as action "front_door" (same pattern as the discovery module), and seeded by
planner.frontdoor_seeds against the login/auth surface. Turns auth control-PRESENCE into attack-FEASIBILITY.

Board doctrine on safety (they were explicit):
  DEFAULT (passive-ish, no account risk): PinPolicy (no traffic) + UserEnumeration status/body arm (ONE
    login attempt per identity -> can't lock anyone).
  OPT-IN (AEGIS_ACTIVE_AUTH=1): the rate/lockout BURST (bounded, NONEXISTENT identity so no real account
    locks) which then feeds BruteForceFeasibility, and the timing-enumeration arm (a few valid-name samples,
    kept well under any lockout threshold).
Without the active sample BruteForceFeasibility stays inconclusive (a derivation needs the rate/lockout
facts) -- never over-claims. Non-destructive throughout; N hard-capped.

Result shape matches the other vectors: {status, body, front_door: {...}, front_door_verified: bool}.
"""
from __future__ import annotations
import json as _json
import os
import time
import uuid

_ACTIVE = str(os.environ.get("AEGIS_ACTIVE_AUTH", "0")).lower() in ("1", "true", "yes", "on")
_CHARSET_SIZE = {"digits": 10, "alnum": 36, "alnum_case": 62}


def _sess():
    import requests as _rq
    try:
        _rq.packages.urllib3.disable_warnings()
    except Exception:
        pass
    s = _rq.Session(); s.verify = False
    return s


def _login(s, url, name, pin, name_field, pin_field, extra):
    """One login POST; return (status, body_text, latency_ms) -- latency None on transport error."""
    body = {name_field: name, pin_field: pin}
    body.update(extra or {})
    t0 = time.time()
    try:
        r = s.post(url, json=body, timeout=15, verify=False)
        return r.status_code, (r.text or "")[:600], (time.time() - t0) * 1000.0
    except Exception:
        return -1, "", None


def front_door(move, ctx):
    """D8 front-door battery: PinPolicy + UserEnumeration (+ rate/BruteForceFeasibility when active)."""
    from verified_findings import (BruteForceFeasibilityOracle, UserEnumerationOracle, PinPolicyOracle,
                                   RateLimitOracle)
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    path = move.get("surface") or move.get("path") or "/api/auth/login"
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    name_field = move.get("name_field", "name"); pin_field = move.get("pin_field", "pin")
    extra = move.get("extra_body") or {}
    charset = move.get("charset", "digits")
    pin_len = int(move.get("pin_length", os.environ.get("AEGIS_PIN_LENGTH", "6")))
    keyspace = _CHARSET_SIZE.get(charset, 10) ** pin_len
    valid_name = move.get("valid_name") or os.environ.get("AEGIS_VALID_NAME")  # a KNOWN real name to compare
    bad_pin = "9" * pin_len
    out = {"surface": path, "results": {}}
    verified_any = False
    s = _sess()

    # 1) PIN policy -- no traffic
    pv, pr = PinPolicyOracle(length=pin_len, charset=charset, surface=path).check()
    out["results"]["pin_policy"] = {"verdict": pv, **pr}; verified_any |= (pv == "verified")

    # 2) User enumeration -- status/body arm (default): ONE attempt per identity (no lockout risk)
    if valid_name:
        ghost = "zzz-nobody-" + uuid.uuid4().hex[:8]
        vstat, vbody, vlat = _login(s, url, valid_name, bad_pin, name_field, pin_field, extra)
        istat, ibody, ilat = _login(s, url, ghost, bad_pin, name_field, pin_field, extra)
        vl = [vlat] if vlat is not None else []; il = [ilat] if ilat is not None else []
        if _ACTIVE:                                    # timing arm: a few MORE samples (kept < lockout)
            for _ in range(int(move.get("timing_samples", 5))):
                _, _, a = _login(s, url, valid_name, bad_pin, name_field, pin_field, extra)
                _, _, b = _login(s, url, "zzz-" + uuid.uuid4().hex[:8], bad_pin, name_field, pin_field, extra)
                if a is not None: vl.append(a)
                if b is not None: il.append(b)
        uv, ur = UserEnumerationOracle(valid_statuses=[vstat], invalid_statuses=[istat],
                                       valid_body=vbody, invalid_body=ibody,
                                       valid_latencies=vl, invalid_latencies=il, surface=path).check()
        out["results"]["user_enumeration"] = {"verdict": uv, **ur}; verified_any |= (uv == "verified")
    else:
        out["results"]["user_enumeration"] = {"verdict": "inconclusive",
                                              "note": "no valid_name to compare (set move.valid_name / AEGIS_VALID_NAME)"}

    # 3) Rate/lockout burst + BruteForceFeasibility -- OPT-IN (bounded). FP-fix: a NONEXISTENT identity can
    # only ever reveal the per-IP limiter (never the per-ACCOUNT lockout), and n must EXCEED that limit or the
    # 429 is never observed -> the old ghost+n=20 falsely reported "no throttle -> feasible". So: prefer a
    # THROWAWAY REAL account (move.bruteforce_name) to exercise account-lockout; n defaults above the IP
    # limit; ABORT on the first throttle; and a no-throttle result from a ghost is INCONCLUSIVE, not feasible.
    if _ACTIVE:
        n = min(int(move.get("n", 25)), int(os.environ.get("AEGIS_RATE_MAX", "30")))   # must exceed the IP limit
        real_acct = move.get("bruteforce_name")            # a dedicated disposable REAL account, if supplied
        acct = real_acct or ("zzz-brute-" + uuid.uuid4().hex[:8])
        statuses, lockout_at = [], None
        for i in range(n):
            st, _, _ = _login(s, url, acct, bad_pin, name_field, pin_field, extra)
            statuses.append(st)
            if lockout_at is None and st in (429, 423):
                lockout_at = i + 1
                break                                      # stop the moment a throttle/lockout appears
        rv, rr = RateLimitOracle(statuses, endpoint=path,
                                 min_attempts=int(move.get("min_attempts", 10))).check()
        throttled = rr.get("throttle_seen", False) or (lockout_at is not None)
        if (not throttled) and (not real_acct):
            # ghost identity + no 429 seen: per-ACCOUNT lockout was NEVER exercised -> can't conclude feasible.
            out["results"]["rate_limit"] = {"verdict": "inconclusive", **rr,
                "note": ("ghost identity: only the per-IP limiter is testable and no 429 in %d tries; per-ACCOUNT "
                         "lockout UNTESTED -> supply move.bruteforce_name (a throwaway real account)" % n)}
            out["results"]["brute_force"] = {"verdict": "inconclusive", "keyspace": keyspace,
                "note": "rate/lockout not fully sampled (ghost identity) -> feasibility undetermined"}
        else:
            out["results"]["rate_limit"] = {"verdict": rv, **rr}; verified_any |= (rv == "verified")
            bv, br = BruteForceFeasibilityOracle(keyspace=keyspace, throttled=throttled, lockout_threshold=lockout_at,
                                                 req_per_sec=move.get("req_per_sec"), surface=path).check()
            out["results"]["brute_force"] = {"verdict": bv, **br}; verified_any |= (bv == "verified")
    else:
        out["results"]["brute_force"] = {"verdict": "inconclusive",
                                        "note": "set AEGIS_ACTIVE_AUTH=1 to sample rate/lockout and derive feasibility"}

    return {"status": 200, "body": _json.dumps(out)[:2000], "front_door": out,
            "front_door_verified": verified_any}


LEGS = {"front_door": front_door}
