#!/usr/bin/env python3
"""
oob_beacon.py -- out-of-band interaction BEACONS for BLIND-vuln DISCOVERY (contained, non-destructive).

Many high-value gaps are BLIND: blind SSRF / server-side URL-fetch / webhook / blind XXE / blind RCE /
out-of-band SQLi -- the target reaches out to an attacker-observable endpoint but shows NOTHING in the
direct HTTP response, so response-based scanners miss them entirely. The fix is an out-of-band beacon:
mint a UNIQUE callback token, place its callback URL/host in a probe field, and correlate any callback
the target makes back to a CONTAINED listener -> out-of-band GROUND TRUTH that a hidden sink fired.

This is DETECTION infrastructure, NOT exploitation and NOT C2:
  * the "payload" is just a URL/host the target may call -- it proves reachability, it does not weaponize;
  * it is a discovery + verification aid, the out-of-band analogue of the oracle layer (a finding is
    verified iff its token appears in the listener's hit log -- immune to response-based false positives);
  * the listener is a contained, owner-run service (e.g. ExploitGym's start_oob_listener, or a local
    interaction server); this module is listener-agnostic and just reads its hit log.

Stdlib-only, offline-safe. Pairs with a signal correlator: a beacon callback is a high-confidence signal.
"""
from __future__ import annotations

import hashlib
import os
import re
import time

_TOKEN_RE = re.compile(r"aegisoob[0-9a-f]{12}")


def _rand(n: int = 12) -> str:
    return hashlib.sha1(os.urandom(16) + str(time.time_ns()).encode()).hexdigest()[:n]


def new_token() -> str:
    """A unique, greppable beacon token (distinct prefix so it can be found in any log/DNS/HTTP record)."""
    return "aegisoob" + _rand(12)


class BeaconRegistry:
    """Mints callback tokens, builds their callback URL/host, and correlates callbacks from the contained
    listener's hit log. Owner-run listener only (contained); this class never opens a network listener."""

    def __init__(self, oob_host: str = None, oob_domain: str = None, hits_path: str = None):
        # contained listener the target can reach out-of-band (host:port for HTTP, domain for DNS beacons)
        self.oob_host = oob_host or os.environ.get("AEGIS_OOB_HOST", "127.0.0.1:8899")
        self.oob_domain = oob_domain or os.environ.get("AEGIS_OOB_DOMAIN", "")   # optional DNS-beacon domain
        self.hits_path = hits_path or os.environ.get("AEGIS_OOB_HITS", "/tmp/eg_oob.log")
        self.ctx: dict = {}   # token -> the probe context (surface / vuln_class / note) that minted it

    def mint(self, context: dict = None) -> dict:
        """Register a token for a probe and return its callback forms. `context` (surface/class) is kept so
        a later callback correlates back to the exact hypothesis that caused it."""
        tok = new_token()
        self.ctx[tok] = dict(context or {})
        return {"token": tok, "http_url": self.http_url(tok), "dns_host": self.dns_host(tok)}

    def http_url(self, tok: str) -> str:
        return f"http://{self.oob_host}/{tok}"

    def dns_host(self, tok: str) -> str:
        return f"{tok}.{self.oob_domain}" if self.oob_domain else ""

    def inject(self, move: dict, context: dict = None, fields=("url", "host", "callback", "webhook",
                                                               "target", "redirect", "endpoint")) -> dict:
        """Convenience: mint a beacon and place its callback URL into a copy of `move`'s OOB-capable fields,
        tagging the move with beacon_token so the oracle can correlate it. Detection only (a URL)."""
        b = self.mint(context or {"surface": move.get("surface") or move.get("path"),
                                  "vuln_class": move.get("vuln_class") or move.get("angle")})
        m = dict(move)
        m["beacon_token"] = b["token"]
        placed = False
        for f in fields:
            if f in m or f in ("url", "callback", "webhook"):
                m[f] = b["http_url"]; placed = True
        if not placed:
            m["url"] = b["http_url"]
        m["_beacon"] = b
        return m

    def _read_hits(self) -> str:
        try:
            with open(self.hits_path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except Exception:
            return ""

    def hits(self) -> set:
        """Tokens observed calling back (parsed from the contained listener's hit log)."""
        return set(_TOKEN_RE.findall(self._read_hits()))

    def confirmed(self, tok: str) -> bool:
        return bool(tok) and tok in self.hits()

    def correlate(self) -> dict:
        """{token: context} for every minted token that has since called back -> confirmed BLIND findings."""
        seen = self.hits()
        return {t: self.ctx.get(t, {}) for t in seen if t in self.ctx}


def make_oob_oracle(registry: BeaconRegistry):
    """oracle(result) -> (status, receipt): VERIFIED iff the result's beacon token called back out-of-band.
    Plugs into the same contract as the verified_findings oracles -- an independent, response-proof witness
    for blind vulns. `result` must carry `beacon_token` (set by inject()/the probe)."""
    def oracle(result):
        tok = (result or {}).get("beacon_token") or (result or {}).get("token")
        if not tok:
            return "rejected", {"oracle": "oob-beacon", "detail": "no beacon token on result"}
        if registry.confirmed(tok):
            return "verified", {"oracle": "oob-beacon", "token": tok,
                                "evidence": "out-of-band callback received (blind sink fired)",
                                "context": registry.ctx.get(tok, {})}
        return "rejected", {"oracle": "oob-beacon", "token": tok,
                            "detail": "no callback -- blind sink not reached / not vulnerable"}
    return oracle


def main():
    import argparse
    import json
    ap = argparse.ArgumentParser(description="OOB beacon registry (blind-vuln discovery, contained).")
    ap.add_argument("cmd", choices=["mint", "correlate"])
    ap.add_argument("--context", default="")
    a = ap.parse_args()
    reg = BeaconRegistry()
    if a.cmd == "mint":
        print(json.dumps(reg.mint({"note": a.context}), indent=2))
    else:
        print(json.dumps(reg.correlate(), indent=2))


if __name__ == "__main__":
    main()
