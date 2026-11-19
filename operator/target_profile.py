#!/usr/bin/env python3
"""
target_profile.py -- a PERSISTENT, updating model of a target that accumulates across every hunt leg, so
the loop stops re-hammering already-exhausted obvious classes (the ~31% saturation collapse) and steers
toward under-probed, target-specific surfaces. This is the #1 discovery gap from the board analysis: today
the planner builds a ONE-TIME manifest and nothing carries saturation/coverage state forward.

The profile records, per target: which (surface x vuln_class) pairs have been TRIED and how often they
CONFIRMED, plus global per-class tallies and confirmed sinks. From that it derives:
  * SATURATION: a class tried heavily with ~0 payoff -> a NEGATIVE bandit bias (down-weight it);
  * UNDER-PROBED surfaces: seen but barely tried -> a board hint to prefer them;
  * a brainstorm hint the board can act on.

OPT-IN + INERT BY DEFAULT: set $AEGIS_TARGET_PROFILE=<path> to enable. Unset -> active_bias()/active_hint()
are no-ops and the bandit/board behave exactly as before. The bias rides only in the bandit's SELECT-time
sort (transient, never written to the bandit's learned reward state -- same non-poisoning discipline as the
priority switch). Stdlib-only, offline-safe.
"""
from __future__ import annotations

import json
import os
import time

SAT_MIN = int(os.environ.get("AEGIS_TP_SAT_MIN", "8"))          # min tries before a class can be "saturated"
SAT_RATE = float(os.environ.get("AEGIS_TP_SAT_RATE", "0.05"))   # confirm-rate below this = saturated
SAT_PENALTY = float(os.environ.get("AEGIS_TP_SAT_PENALTY", "0.6"))   # bandit down-weight for a saturated class


def _class_of(move: dict) -> str:
    return str((move or {}).get("vuln_class") or (move or {}).get("angle")
               or (move or {}).get("class") or (move or {}).get("technique") or "").split("/")[0].strip().lower()


def _surf_of(move: dict) -> str:
    return str((move or {}).get("surface") or (move or {}).get("path") or "").strip()


def _sig(a: dict) -> str:
    mv = a.get("move") or {}
    return "|".join([_surf_of(mv), _class_of(mv), str(a.get("verdict")),
                     str(a.get("gain")), json.dumps(a.get("delta"), sort_keys=True)[:60] if a.get("delta") is not None else ""])


class TargetProfile:
    def __init__(self, path: str = None, target: str = ""):
        self.path = path
        self.target = target
        self.surfaces: dict = {}     # surface -> {"tried","confirms","classes":{cls:{"tried","confirms"}}}
        self.classes: dict = {}      # cls -> {"tried","confirms"}
        self.sinks: list = []
        self._seen: set = set()      # attempt signatures already folded (idempotent observe)
        self._load()

    # ---- persistence ----
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            d = json.load(open(self.path, encoding="utf-8"))
            self.target = d.get("target", self.target)
            self.surfaces = d.get("surfaces", {}) or {}
            self.classes = d.get("classes", {}) or {}
            self.sinks = d.get("sinks", []) or []
            self._seen = set(d.get("_seen", []) or [])
        except Exception:
            pass

    def save(self):
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            json.dump({"target": self.target, "surfaces": self.surfaces, "classes": self.classes,
                       "sinks": self.sinks, "_seen": sorted(self._seen)[-5000:],
                       "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                      open(tmp, "w", encoding="utf-8"), indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    # ---- update ----
    def _bump(self, cls: str, surf: str, confirmed: bool):
        if cls:
            c = self.classes.setdefault(cls, {"tried": 0, "confirms": 0})
            c["tried"] += 1; c["confirms"] += int(confirmed)
        if surf:
            s = self.surfaces.setdefault(surf, {"tried": 0, "confirms": 0, "classes": {}})
            s["tried"] += 1; s["confirms"] += int(confirmed)
            if cls:
                sc = s["classes"].setdefault(cls, {"tried": 0, "confirms": 0})
                sc["tried"] += 1; sc["confirms"] += int(confirmed)

    def observe(self, move: dict, verdict: str):
        self._bump(_class_of(move), _surf_of(move), verdict == "verified")

    def observe_context(self, context: dict) -> int:
        """Idempotently fold the loop's attempt/confirm history (same shape t0_bandit reads) into the model."""
        n = 0
        for c in (context or {}).get("confirmed") or []:
            a = {"move": c.get("move") or {}, "verdict": "verified", "gain": 1, "delta": None}
            sg = _sig(a)
            if sg not in self._seen:
                self._seen.add(sg); self._bump(_class_of(a["move"]), _surf_of(a["move"]), True); n += 1
        for a in (context or {}).get("attempts") or []:
            mv = a.get("move") or {}
            if mv.get("_eps"):
                continue                          # epsilon-diversify pick -> not a real coverage signal
            sg = _sig(a)
            if sg in self._seen:
                continue
            self._seen.add(sg)
            self._bump(_class_of(mv), _surf_of(mv), a.get("verdict") == "verified"); n += 1
        return n

    def record_sink(self, sink: dict):
        if sink and sink not in self.sinks:
            self.sinks.append(sink)

    # ---- derived signals ----
    def saturated(self, cls: str) -> bool:
        c = self.classes.get((cls or "").lower())
        if not c or c["tried"] < SAT_MIN:
            return False
        return (c["confirms"] / c["tried"]) < SAT_RATE

    def bias(self) -> dict:
        """{class: delta} additive bandit bias: NEGATIVE for saturated classes (down-weight the exhausted
        obvious ones). Returned to the bandit's select-time sort only; never persisted to learned reward."""
        return {cls: -SAT_PENALTY for cls in self.classes if self.saturated(cls)}

    def under_probed(self, k: int = 5) -> list:
        """Surfaces seen but barely tried relative to the busiest -- candidates to steer toward."""
        if not self.surfaces:
            return []
        mx = max(s["tried"] for s in self.surfaces.values()) or 1
        ranked = sorted(self.surfaces.items(), key=lambda kv: kv[1]["tried"])
        return [surf for surf, s in ranked if s["tried"] <= max(1, mx // 3)][:k]

    def hint(self) -> str:
        sat = [c for c in self.classes if self.saturated(c)]
        up = self.under_probed()
        if not sat and not up:
            return ""
        parts = []
        if sat:
            parts.append("saturated classes (tried heavily with ~0 payoff -- AVOID / try a different angle): "
                         + ", ".join(sorted(sat)))
        if up:
            parts.append("under-probed surfaces (PREFER these): " + ", ".join(up))
        return "TARGET MEMORY -- " + "; ".join(parts) + "."


# ---- module-level opt-in helpers (used by t0_bandit / board; inert unless AEGIS_TARGET_PROFILE set) ----
def _path():
    return os.environ.get("AEGIS_TARGET_PROFILE") or ""


def active() -> bool:
    return bool(_path())


def load() -> "TargetProfile | None":
    p = _path()
    return TargetProfile(path=p) if p else None


def active_bias() -> dict:
    """Per-class bandit bias from the persisted profile ({} when inert)."""
    tp = load()
    return tp.bias() if tp else {}


def active_hint() -> str:
    tp = load()
    return tp.hint() if tp else ""


def observe_and_save(context: dict) -> int:
    """Fold a round's context into the persisted profile (no-op when inert)."""
    tp = load()
    if not tp:
        return 0
    n = tp.observe_context(context)
    tp.save()
    return n
