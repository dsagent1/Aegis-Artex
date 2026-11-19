#!/usr/bin/env python3
"""Offline tests for build-target 4's JWT forgery: jwt_forge crafters + JwtForgeryOracle verdicts.
No network. Run: python operator/_jwt_forge_tests.py"""
import hashlib
import hmac
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "shared"))

import jwt_forge as J              # noqa: E402
from verified_findings import JwtForgeryOracle  # noqa: E402

fails = 0


def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")


CLAIMS = {"sub": "1", "email": "admin@juice-sh.op", "role": "admin"}
PUBKEY = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJK...FAKE...AB\n-----END PUBLIC KEY-----\n"

# --- alg:none ---
t = J.forge_alg_none(CLAIMS)
h, p, sig = J.decode_segments(t)
ok("alg:none header alg=none", h.get("alg") == "none")
ok("alg:none payload preserved", p == CLAIMS)
ok("alg:none empty signature", sig == "" and t.endswith("."))

# --- RS256 -> HS256 ---
t2 = J.forge_rs256_to_hs256(CLAIMS, PUBKEY)
h2, p2, sig2 = J.decode_segments(t2)
ok("hs256 header alg=HS256", h2.get("alg") == "HS256")
ok("hs256 payload preserved", p2 == CLAIMS)
signing_input = ".".join(t2.split(".")[:2]).encode()
expect = J._b64url(hmac.new(PUBKEY.encode(), signing_input, hashlib.sha256).digest())
ok("hs256 signature verifies with pubkey-as-secret", sig2 == expect)

# --- craft_forgeries ---
ok("craft: alg:none only without pubkey", [v for v, _ in J.craft_forgeries(CLAIMS)] == ["alg:none"])
ok("craft: both with pubkey", [v for v, _ in J.craft_forgeries(CLAIMS, PUBKEY)] == ["alg:none", "rs256->hs256"])

# --- JwtForgeryOracle verdicts ---
v, _ = JwtForgeryOracle(forged_authed=True, control_denied=True, identity_match=True,
                        vector="alg:none", surface="/whoami").check()
ok("oracle VERIFIED (forged+control-denied+identity)", v == "verified")
v, _ = JwtForgeryOracle(forged_authed=True, control_denied=False, identity_match=True).check()
ok("oracle inconclusive (identity reflected but endpoint unauth)", v == "inconclusive")
# live juice-shop shape: bad token -> 200-empty (control not denied), no forged identity -> REJECTED
v, _ = JwtForgeryOracle(forged_authed=True, control_denied=False, identity_match=False).check()
ok("oracle REJECTED (200-empty, no forged identity == live juice-shop)", v == "rejected")
v, _ = JwtForgeryOracle(forged_authed=True, control_denied=True, identity_match=False).check()
ok("oracle REJECTED (forgery failed to impersonate)", v == "rejected")
v, _ = JwtForgeryOracle(forged_authed=False, control_denied=True, identity_match=False).check()
ok("oracle REJECTED (signature verification works)", v == "rejected")

n = 15
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
