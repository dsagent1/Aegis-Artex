#!/usr/bin/env python3
"""#4 -- deceptive-target robustness (ATOBench-style negative-control gating).

A DECEPTIVE / honeypot target emits a "success" signal (200, reflected payload, a canned vuln banner, a
slow response) for EVERY input. A weak oracle that only reads that signal is fooled into a false 'verified'.
This module is the native defense the oracle layer calls BEFORE it trusts a deceivable oracle:

    guard_oracle(oracle_id, probe=send_attack, control=send_benign) -> OracleGuard

It runs the real probe AND a NEGATIVE CONTROL (the same request shape with a benign/nonsense payload that
must NOT trigger the vuln), then classifies via shared.verified_findings.deception_verdict:

    clean       positive fired, benign control did NOT  -> a real differential signal (trust it)
    deceptive   positive fired AND the benign control fired too -> target says success to anything (reject)
    negative    positive did not fire -> no finding
    untested    a deceivable oracle fired but no control was supplied -> suspect (do not reach verified)

GROUND-TRUTH oracles (canary echo / OOB callback / DB witness / raw-SQL / SSTI -- the _HIGH_CONF_ORACLE
prefixes) are deception-resistant by construction: they require a specific side-channel WITNESS (a unique
token echoed out-of-band, a DB row actually written) that an always-success target cannot fabricate without
truly being vulnerable. They are exempt from the control requirement (deception_verdict returns 'clean').

The caller records the verdict into the finding's oracle_receipt as receipt["deception"]; the hash-chain
fold (shared/verified_findings.findings) reads it and, for a weak-oracle 'deceptive'/'untested' hit,
forces disagreement=True so grade_confidence collapses -- advisory, the oracle stays ground truth.

Self-contained: the mock targets below are in-process callables (no network), so the self-test
(shared/_deception_tests.py) runs anywhere, including this box.
"""
from __future__ import annotations
import os
import sys
import random
import hashlib
from dataclasses import dataclass, field
from typing import Callable, Optional, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.verified_findings import (  # noqa: E402
    deception_verdict, oracle_is_deceivable, high_confidence_oracle,
)


# ---------------------------------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------------------------------
@dataclass
class OracleGuard:
    oracle_id: str
    verdict: str                      # clean | deceptive | negative | untested
    positive: bool
    control_positive: Optional[bool]
    high_conf: bool
    note: str = ""

    @property
    def trustworthy(self) -> bool:
        """A finding should only reach 'verified' off this oracle when the guard is clean."""
        return self.verdict == "clean"

    def as_receipt(self) -> dict:
        """What the caller merges into oracle_receipt so the fold can read the verdict."""
        return {"deception": self.verdict, "control_ran": self.control_positive is not None,
                "control_fired": bool(self.control_positive)}


def _as_bool(signal: Any) -> bool:
    """Normalize a probe's return (bool, or a dict/str signal) to 'did the success signal fire?'."""
    if isinstance(signal, bool):
        return signal
    if isinstance(signal, dict):
        return bool(signal.get("hit") or signal.get("success") or signal.get("fired"))
    if signal is None:
        return False
    return bool(signal)


def guard_oracle(oracle_id: str,
                 probe: Callable[[], Any],
                 control: Optional[Callable[[], Any]] = None) -> OracleGuard:
    """Run the attack probe and (for a deceivable oracle) its benign negative control, then classify.

    probe()    -> truthy iff the oracle's success signal fired for the real attack payload.
    control()  -> truthy iff the SAME signal fired for a benign/nonsense payload (should be falsey on an
                  honest target). Omit for a ground-truth oracle (exempt) or when you cannot build one
                  (the verdict is then 'untested' -> the finding stays below 'verified')."""
    hi = high_confidence_oracle([oracle_id])
    pos = _as_bool(probe())
    ctrl_pos: Optional[bool] = None
    if pos and not hi and control is not None:
        ctrl_pos = _as_bool(control())
    verdict = deception_verdict(pos, ctrl_pos, high_conf=hi)
    note = {
        "clean": "differential signal (or ground-truth oracle) -- trustworthy",
        "deceptive": "benign control ALSO fired -- target returns success for anything; rejected",
        "untested": "deceivable oracle fired with no negative control -- suspect, held below verified",
        "negative": "attack signal did not fire -- no finding",
    }[verdict]
    return OracleGuard(oracle_id=oracle_id, verdict=verdict, positive=pos,
                       control_positive=ctrl_pos, high_conf=hi, note=note)


# ---------------------------------------------------------------------------------------------------
# In-process mock targets for the self-test (no network). Each is send(payload)->response dict.
# A "response" carries: status, body, elapsed_ms, and (for ground-truth) an out-of-band witness set.
# ---------------------------------------------------------------------------------------------------
_BENIGN = "qwErty-benign-0000"           # a nonsense control payload: no honest target reacts to it
_OOB: set = set()                        # simulated out-of-band channel (canary tokens that came back)


def _canary(payload: str) -> str:
    return "cnry_" + hashlib.sha1(payload.encode()).hexdigest()[:10]


def honest_safe(payload: str) -> dict:
    """An honest, NON-vulnerable target: benign 200, never reflects, never echoes a canary OOB."""
    return {"status": 200, "body": "ok", "elapsed_ms": 20, "reflected": False}


def honest_vulnerable(payload: str) -> dict:
    """An honest, GENUINELY vulnerable target: it reflects a real injection payload (and only that),
    and a real SSRF/canary payload actually calls back out-of-band. A benign control does neither."""
    is_attack = ("<script>" in payload) or ("' OR " in payload) or ("http://oob/" in payload)
    reflected = "<script>" in payload
    if "http://oob/" in payload:         # genuine SSRF: the server really fetches the canary URL
        _OOB.add(_canary(payload))
    return {"status": 200 if is_attack else 200, "body": (payload if reflected else "ok"),
            "elapsed_ms": 900 if ("sleep" in payload) else 20, "reflected": reflected}


def deceptive_always_success(payload: str) -> dict:
    """Honeypot #1: returns 200 for EVERYTHING (classic always-up honeypot)."""
    return {"status": 200, "body": "ok", "elapsed_ms": 20, "reflected": False}


def deceptive_reflect_everything(payload: str) -> dict:
    """Honeypot #2: echoes ANY input back verbatim -> fools a naive reflection/XSS body oracle."""
    return {"status": 200, "body": payload, "elapsed_ms": 20, "reflected": True}


def deceptive_canned_banner(payload: str) -> dict:
    """Honeypot #3: serves a canned 'vulnerable' banner regardless of input (fake-vuln decoy)."""
    return {"status": 200, "body": "SQL syntax error near '' -- you are vulnerable!",
            "elapsed_ms": 20, "reflected": False}


def deceptive_timing_noise(payload: str) -> dict:
    """Honeypot #4: random latency on every request -> fools a naive time-based blind oracle."""
    return {"status": 200, "body": "ok", "elapsed_ms": random.choice([20, 900, 1500]), "reflected": False}


# --- example oracle signal readers (what a probe() closure checks on a response) --------------------
def sig_reflection(resp: dict, payload: str) -> bool:
    return bool(resp.get("reflected")) and payload in str(resp.get("body", ""))

def sig_error_banner(resp: dict) -> bool:
    return "SQL syntax error" in str(resp.get("body", ""))

def sig_timing(resp: dict, threshold_ms: int = 800) -> bool:
    return int(resp.get("elapsed_ms", 0)) >= threshold_ms

def sig_canary_oob(payload: str) -> bool:
    """GROUND-TRUTH: did the unique canary for THIS payload actually come back out-of-band?"""
    return _canary(payload) in _OOB


if __name__ == "__main__":
    # quick manual smoke
    from shared import _deception_tests  # type: ignore
    _deception_tests.main()
