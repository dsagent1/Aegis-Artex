#!/usr/bin/env python3
"""
scope.py -- technical authorization gate for the engine (TRUST lever).

Every network-facing leg the operator fires (web / recon / nuclei / any move that carries its own
`target`/`host`/`url`) is checked against an explicit, operator-signed SCOPE FILE *before the request
leaves the box*. This is enforced at the execute layer (iterative_hunt_live.make_execute ->
vectors.dispatch), not by regex on a move dict or by a prompt instruction the model could talk itself
out of. Contained-by-default: loopback + RFC1918 are the built-in containment and always allowed; any
PUBLIC host must be listed explicitly AND the file must set "allow_public": true. Wildcards are refused.
Stdlib-only, offline, deterministic.

Scope file (JSON), path from $AEGIS_SCOPE_FILE (or passed explicitly):
    {
      "authorized": ["127.0.0.1", "localhost", "10.0.0.0/8", "mirror.internal"],
      "allow_public": false,          # must be true for any non-contained (public) entry to be honored
      "sha256": "<hex>"               # OPTIONAL integrity hash of the authorized list (tamper-evidence)
    }

Modes (env):
    AEGIS_SCOPE_FILE=<path>   -> load & enforce that scope.
    AEGIS_SCOPE_ENFORCE=1     -> fail CLOSED: if no scope file is present, refuse every network leg.
    (neither set)             -> gate is inert (legacy behaviour); existing runs/tests are unaffected.

Public API:
    load_scope(path=None)                 -> dict | None      (raises ScopeError on tamper/parse error)
    in_scope(target, scope)               -> (bool, reason)
    check_move(move, base, scope=None)    -> (bool, reason)   # block-contract, mirrors guard()
    enforce(target, scope=None)           -> None             # raises ScopeError (hard, fail-closed)
    hash_scope(scope) / write_scope(...)                       # authoring helpers
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from urllib.parse import urlsplit

ENV_FILE = "AEGIS_SCOPE_FILE"
ENV_ENFORCE = "AEGIS_SCOPE_ENFORCE"
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope, or the scope file is missing/tampered."""


def _enforce_mode() -> bool:
    return str(os.environ.get(ENV_ENFORCE, "")).lower() in ("1", "true", "yes", "on")


def host_of(target: str) -> str:
    """Extract the bare host from a URL, host:port, or bare host. Lowercased, no scheme/port/brackets."""
    if not target:
        return ""
    t = str(target).strip()
    if "//" not in t:
        t = "//" + t                       # let urlsplit treat "host:port/path" as authority
    netloc = urlsplit(t).netloc or ""
    if "@" in netloc:                      # strip userinfo
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):             # bracketed IPv6 [::1]:8443
        return netloc[1:].split("]", 1)[0].lower()
    return netloc.split(":", 1)[0].lower()


def _as_ip(host: str):
    if host in _LOCAL_NAMES:
        return ipaddress.ip_address("127.0.0.1")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_contained(host: str) -> bool:
    """Loopback / RFC1918 -- the built-in lab containment, allowed by default. Link-local is
    DELIBERATELY excluded: 169.254.169.254 (and fe80::/10) is the cloud-metadata SSRF/exfil surface,
    not lab containment, so it must be authorized explicitly (an entry in the scope file) rather than
    pass by default -- even though ipaddress marks it is_private."""
    ip = _as_ip(host)
    if ip is None:
        return False
    if ip.is_link_local:
        return False
    return bool(ip.is_loopback or ip.is_private)


def hash_scope(scope: dict) -> str:
    """Canonical sha256 over the authorized list (order-independent) -- what "sha256" pins."""
    items = sorted(str(x).strip().lower() for x in (scope.get("authorized") or []))
    return hashlib.sha256(json.dumps(items, separators=(",", ":")).encode()).hexdigest()


def load_scope(path: str = None) -> dict | None:
    """Load & validate the scope file. Returns None when no file is configured (path or env)."""
    path = path or os.environ.get(ENV_FILE)
    if not path:
        return None
    if not os.path.exists(path):
        raise ScopeError(f"scope file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            scope = json.load(fh)
    except (OSError, ValueError) as e:
        raise ScopeError(f"scope file unreadable: {e}") from e
    if not isinstance(scope, dict) or not isinstance(scope.get("authorized"), list):
        raise ScopeError("scope file must be an object with an 'authorized' list")
    want = scope.get("sha256")
    if want and want.lower() != hash_scope(scope):        # tamper-evidence
        raise ScopeError("scope file integrity check failed (sha256 mismatch) -- refusing")
    return scope


def in_scope(target: str, scope: dict) -> tuple[bool, str]:
    """Is `target` authorized by `scope`? Contained-by-default; explicit entries by host or CIDR;
    public entries require allow_public; wildcards refused."""
    host = host_of(target)
    if not host:
        return False, "no host in target"
    scope = scope or {}
    ip = _as_ip(host)
    allow_public = bool(scope.get("allow_public"))

    for raw in (scope.get("authorized") or []):
        entry = str(raw).strip().lower()
        if not entry or "*" in entry:                     # wildcards are never honored
            continue
        # CIDR / IP-range entry
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if ip is not None and ip in net:
                if _is_contained(host) or allow_public:
                    return True, f"explicit range {entry}"
                return False, f"public host {host} matches {entry} but allow_public is false"
            continue
        except ValueError:
            pass
        # hostname / exact-IP entry
        if entry == host:
            if _is_contained(host) or allow_public:
                return True, f"explicit host {entry}"
            return False, f"public host {host} listed but allow_public is false"

    if _is_contained(host):
        return True, "contained (loopback/rfc1918/link-local)"
    return False, f"out of scope: {host} (not contained and not in authorized list)"


def check_move(move: dict, base: str, scope: dict = None) -> tuple[bool, str]:
    """Block-contract gate (mirrors guard()): returns (ok, reason). Resolves EVERY host a leg could
    reach -- the run base plus any move-supplied target/host/url -- and requires all to be in scope.
    Inert when no scope file is configured and enforce-mode is off (legacy behaviour)."""
    if scope is None:
        scope = load_scope()
    if scope is None:
        if _enforce_mode():
            return False, "scope enforcement on but no scope file configured (fail-closed)"
        return True, ""                                   # gate inert
    targets = [base] + [move.get(k) for k in ("target", "host", "url", "endpoint")]
    for t in targets:
        if not t:
            continue
        if host_of(t) in ("", None):
            continue
        ok, why = in_scope(t, scope)
        if not ok:
            return False, f"scope-gate: {why}"
    return True, ""


def enforce(target: str, scope: dict = None) -> None:
    """Hard gate (fail-closed): raise ScopeError unless `target` is authorized. Used at run start on
    the base host so an out-of-scope run never begins."""
    if scope is None:
        scope = load_scope()
    if scope is None:
        if _enforce_mode():
            raise ScopeError("scope enforcement on but no scope file configured (fail-closed)")
        return                                            # gate inert
    ok, why = in_scope(target, scope)
    if not ok:
        raise ScopeError(f"target not authorized by scope file: {why}")


def write_scope(path: str, authorized: list, allow_public: bool = False, sign: bool = True) -> dict:
    """Author a scope file (adds the integrity hash by default)."""
    scope = {"authorized": list(authorized), "allow_public": bool(allow_public)}
    if sign:
        scope["sha256"] = hash_scope(scope)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(scope, fh, indent=2)
    return scope


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Scope-file authorization gate (TRUST).")
    sub = ap.add_subparsers(dest="cmd")
    w = sub.add_parser("write", help="author a signed scope file")
    w.add_argument("path")
    w.add_argument("hosts", nargs="+", help="authorized hosts / CIDRs")
    w.add_argument("--allow-public", action="store_true")
    c = sub.add_parser("check", help="check a target against a scope file")
    c.add_argument("path")
    c.add_argument("target")
    a = ap.parse_args()
    if a.cmd == "write":
        print(json.dumps(write_scope(a.path, a.hosts, a.allow_public), indent=2))
    elif a.cmd == "check":
        ok, why = in_scope(a.target, load_scope(a.path))
        print(json.dumps({"target": a.target, "in_scope": ok, "reason": why}, indent=2))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
