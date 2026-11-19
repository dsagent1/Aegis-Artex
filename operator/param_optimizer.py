#!/usr/bin/env python3
"""
param_optimizer.py -- per-target PROBE-KNOB optimization for discovery (gap #3). The bandit picks the
vuln-CLASS; this tunes the probe's KNOBS (encoding / content-type / nesting depth / id-form / HTTP verb /
wordlist / race concurrency) to the target's observed behaviour, so probes reach NON-DEFAULT code paths --
where novel gaps live. Default parameters find default bugs.

It is a lightweight learning policy over knob VALUES: `variants(move)` proposes a base tuned probe plus
single-knob perturbations (focused exploration, not a cartesian explosion); `observe(cls, params, signal)`
up-weights the knob values that produced an INTERESTING response (a status/size/timing/error delta vs the
baseline). Over a run it converges the knobs toward the target's live-wire behaviour.

Coverage-oriented (exercise the app's own parser/router/deserializer/recursion paths), NOT filter/WAF
evasion. Opt-in + inert by default ($AEGIS_PARAM_OPT=<path>; unset -> callers just use defaults). The
values are plain data; stdlib-only, offline-safe.
"""
from __future__ import annotations

import json
import os
import time

# coverage-oriented knob space per vuln-class (exercise different code paths, not defender evasion)
KNOB_SPACE = {
    "injection":     {"encoding": ["none", "url", "double_url", "unicode", "base64"],
                      "content_type": ["json", "form", "xml"]},
    "depth":         {"nesting": [64, 256, 1024, 3600], "shape": ["json", "array"]},
    "traversal":     {"encoding": ["none", "url", "double_url", "unicode"], "depth": [3, 6, 12]},
    "idor":          {"id_form": ["increment", "decrement", "uuid_swap", "negative", "zero"],
                      "content_type": ["json", "form"]},
    "authz":         {"verb": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                      "path_case": ["as_is", "trailing_slash", "mixed_case"]},
    "mass_assignment": {"extra_field": ["role", "is_admin", "owner_id", "verified", "balance"],
                        "content_type": ["json", "form"]},
    "content_discovery": {"wordlist": ["common", "big", "api", "backup", "config"],
                          "ext": ["", "php", "bak", "json", "zip", "old"]},
    "race":          {"concurrency": [2, 8, 32], "pattern": ["parallel", "interleave"]},
    "ssrf":          {"scheme": ["http", "https"], "host_form": ["name", "ip", "ipv6", "localhost_alias"]},
}


def response_signal(baseline: dict, resp: dict) -> float:
    """Strength (0..1) of how INTERESTING `resp` is vs the `baseline` response -- a status/size/timing/error
    delta means the knob reached a different code path (a discovery lead). Pure."""
    if not resp:
        return 0.0
    b = baseline or {}
    s = 0.0
    if resp.get("status") is not None and b.get("status") is not None and resp["status"] != b["status"]:
        s += 0.4
    bl, rl = float(b.get("length", 0) or 0), float(resp.get("length", 0) or 0)
    if bl and abs(rl - bl) / max(1.0, bl) > 0.2:
        s += 0.3
    if float(resp.get("elapsed", 0) or 0) - float(b.get("elapsed", 0) or 0) > 0.5:
        s += 0.3
    body = (resp.get("body") or "").lower()
    if resp.get("status", 0) and int(resp.get("status") or 0) >= 500 or "traceback" in body or "stack trace" in body or "exception" in body:
        s += 0.3
    return min(1.0, round(s, 3))


class ParamOptimizer:
    def __init__(self, path: str = None):
        self.path = path
        self.scores: dict = {}    # {cls: {knob: {value: score}}}
        self._load()

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            self.scores = json.load(open(self.path, encoding="utf-8")).get("scores", {}) or {}
        except Exception:
            self.scores = {}

    def save(self):
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            json.dump({"scores": self.scores, "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                      open(tmp, "w", encoding="utf-8"), indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def knobs_for(self, cls: str) -> dict:
        return KNOB_SPACE.get((cls or "").lower(), {})

    def _score(self, cls, knob, value) -> float:
        return float(self.scores.get(cls, {}).get(knob, {}).get(str(value), 0.0))

    def _ranked_values(self, cls, knob, values) -> list:
        # highest learned score first; ties preserve declared order (so untried values still get explored)
        return sorted(values, key=lambda v: (-self._score(cls, knob, v), values.index(v)))

    def variants(self, move: dict, limit: int = 5) -> list:
        """Ranked probe-param variants for this move's class: the best-scored value per knob (the base tuned
        probe), then single-knob perturbations swapping in each knob's 2nd-best value. Returns param dicts."""
        cls = (move or {}).get("vuln_class") or (move or {}).get("angle") or ""
        cls = str(cls).split("/")[0].strip().lower()
        knobs = self.knobs_for(cls)
        if not knobs:
            return []
        ranked = {k: self._ranked_values(cls, k, vals) for k, vals in knobs.items()}
        base = {k: rv[0] for k, rv in ranked.items()}
        out = [dict(base)]
        for k, rv in ranked.items():          # single-knob perturbations (breadth-first, not cartesian)
            if len(rv) > 1:
                v = dict(base); v[k] = rv[1]; out.append(v)
            if len(out) >= limit:
                break
        # de-dup preserving order
        seen, uniq = set(), []
        for p in out:
            key = json.dumps(p, sort_keys=True)
            if key not in seen:
                seen.add(key); uniq.append(p)
        return uniq[:max(1, limit)]

    def observe(self, cls: str, params: dict, signal: float):
        """Up-weight the knob values that produced an interesting response."""
        cls = str(cls or "").split("/")[0].strip().lower()
        if not cls or not params or signal <= 0:
            return
        cs = self.scores.setdefault(cls, {})
        for knob, value in params.items():
            cs.setdefault(knob, {})
            cs[knob][str(value)] = round(cs[knob].get(str(value), 0.0) + float(signal), 4)


# ---- opt-in module helpers (inert unless AEGIS_PARAM_OPT set) ----
def active() -> bool:
    return bool(os.environ.get("AEGIS_PARAM_OPT"))


def load() -> "ParamOptimizer | None":
    p = os.environ.get("AEGIS_PARAM_OPT")
    return ParamOptimizer(path=p) if p else None


def variants_for(move: dict, limit: int = 5) -> list:
    """Tuned variants when enabled; [] when inert (caller falls back to its default params)."""
    opt = load()
    return opt.variants(move, limit) if opt else []
