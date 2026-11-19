#!/usr/bin/env python3
"""
signal_correlator.py -- fuse WEAK, sub-threshold signals from every hunt leg into concrete HYPOTHESIS
MOVES fed back into the loop. Discovery gap #2 from the board: we verify well AFTER the fact, but had no
PRE-verification engine that assembles composite signals -- where novel chains on hardened targets hide,
because no single oracle flags them.

A signal is a normalized weak observation from any leg: an out-of-band beacon callback, a timing/size/role
response differential, a 5xx / stack-trace on crafted input, a fuzzer near-miss, or a coverage gap from the
TargetProfile. The correlator groups signals by SURFACE, fuses their strengths per candidate vuln-CLASS
(with a co-occurrence boost when >=2 independent signals point the same way), and emits candidate moves in
the board's hypothesis shape -- tagged `_origin="correlator"` for provenance and carrying a confidence +
the evidence that justified them. The oracle layer still decides truth; this only proposes what to test.

Pure + stdlib + offline-safe. Consumes the signals that oob_beacon (callbacks) and target_profile
(coverage/saturation) now produce.
"""
from __future__ import annotations

import os

EMIT_MIN = float(os.environ.get("AEGIS_CORR_EMIT_MIN", "0.6"))     # fused confidence needed to emit a move
COOCCUR_BOOST = float(os.environ.get("AEGIS_CORR_COOCCUR", "0.2"))  # added when >=2 signals agree on a class

# signal kind -> (default vuln_class, base strength, human evidence phrase)
KIND_MAP = {
    "beacon_callback": ("ssrf", 0.90, "out-of-band callback (blind sink fired)"),
    "timing_delta":    ("injection", 0.45, "time-based response differential"),
    "error_5xx":       ("injection", 0.40, "server error on crafted input"),
    "stack_trace":     ("injection", 0.50, "stack-trace/error leak on crafted input"),
    "role_diff":       ("authz", 0.70, "cross-role response differential"),
    "size_delta":      ("idor", 0.40, "response-size differential on id change"),
    "fuzzer_nearmiss": ("fuzz", 0.50, "fuzzer anomaly (unconfirmed)"),
    "coverage_gap":    ("recon", 0.30, "under-probed surface"),
}
_ORACLE = {
    "ssrf": "an out-of-band callback carrying the beacon token",
    "injection": "an error/timing differential that proves injection (not the baseline)",
    "authz": "a lower role reaches a surface a baseline role is denied on the same request",
    "idor": "an object owned by another principal is returned",
    "fuzz": "the crashing input reproduces the fault deterministically",
    "recon": "the surface/endpoint is enumerated and reachable",
}


class SignalBus:
    """Collects normalized weak signals from the legs."""
    def __init__(self):
        self.signals = []

    def add(self, kind, surface, cls=None, strength=None, evidence="", source="", token=None):
        base_cls, base_str, phrase = KIND_MAP.get(kind, (None, 0.3, kind))
        self.signals.append({
            "kind": kind, "surface": (surface or "").strip() or "?",
            "cls": (cls or base_cls or "").lower(),
            "strength": float(strength if strength is not None else base_str),
            "evidence": evidence or phrase, "source": source, "token": token,
        })
        return self


def _fuse(signals):
    """Group signals by (surface, class); sum strengths, +boost when >=2 signals agree. -> list of fused."""
    groups = {}
    for s in signals:
        if not s.get("cls"):
            continue
        key = (s["surface"], s["cls"])
        g = groups.setdefault(key, {"surface": s["surface"], "cls": s["cls"], "strength": 0.0,
                                    "kinds": [], "evidence": [], "tokens": []})
        g["strength"] += s["strength"]
        g["kinds"].append(s["kind"])
        g["evidence"].append(s["evidence"])
        if s.get("token"):
            g["tokens"].append(s["token"])
    for g in groups.values():
        if len(set(g["kinds"])) >= 2:          # independent signals agreeing -> composite boost
            g["strength"] += COOCCUR_BOOST
        g["conf"] = min(1.0, round(g["strength"], 3))
    return list(groups.values())


def correlate(bus, emit_min: float = None) -> list:
    """Fuse the bus's signals -> deduped hypothesis MOVES (board shape) above the confidence threshold,
    best-first. The oracle layer still verifies; this only proposes what to test next."""
    thr = EMIT_MIN if emit_min is None else emit_min
    moves = []
    for g in sorted(_fuse(bus.signals if isinstance(bus, SignalBus) else bus), key=lambda x: -x["conf"]):
        if g["conf"] < thr:
            continue
        cls = g["cls"]
        mv = {
            "angle": cls, "vuln_class": cls, "surface": g["surface"],
            "mechanism": "correlated from " + ", ".join(sorted(set(g["kinds"]))),
            "expected_oracle": _ORACLE.get(cls, "an observable delta vs the baseline"),
            "_origin": "correlator", "_corr_conf": g["conf"],
            "_corr_evidence": g["evidence"],
        }
        if g["tokens"]:
            mv["beacon_token"] = g["tokens"][0]
        moves.append(mv)
    return moves


# ---- convenience ingesters (turn other modules' outputs into signals) ----
def ingest_beacons(bus, registry):
    """A confirmed OOB callback is a high-confidence signal (the blind sink fired)."""
    try:
        for tok, ctx in (registry.correlate() or {}).items():
            bus.add("beacon_callback", ctx.get("surface") or "?",
                    cls=(ctx.get("vuln_class") or "ssrf"), evidence="beacon %s called back" % tok[:14],
                    source="oob_beacon", token=tok)
    except Exception:
        pass
    return bus


def ingest_coverage(bus, profile):
    """Under-probed surfaces from the TargetProfile become low-strength 'explore here' signals."""
    try:
        for surf in (profile.under_probed() or []):
            bus.add("coverage_gap", surf, source="target_profile")
    except Exception:
        pass
    return bus
