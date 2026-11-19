"""t0_bandit.py -- T0 SELECTOR: a UCB1 bandit over TECHNIQUE-CLASSES (the board-converged architecture:
deterministic-first, board as ranker/stall-breaker). It answers ONE question cheaply -- "which technique-
class is worth trying next?" -- from observed reward, so the loop spends budget where confirms actually
come from instead of asking the multi-model board every round.

Reward model (board consensus: expected information-gain x expected impact):
  verified confirm -> 1.0, scaled UP on a high-impact surface (money/auth/egress); an info-gaining CLEAN
  (a real refutation) -> a small positive (you learned the surface is guarded); noise/404 -> 0. UCB1's
  exploration term keeps under-tried classes in play so the bandit can't collapse onto one class.

Pure, persisted (JSON), offline-safe. No LLM. Feeds the tiered brainstorm; the board still runs as the
stall-breaker when the deterministic tiers are exhausted.
"""
from __future__ import annotations
import json, math, os, time

_IMPACT = {  # expected-impact weight per class keyword (money/auth/egress dig deeper -- MECH 5)
    "money": 1.6, "invariant": 1.6, "idempotency": 1.5, "business": 1.5, "authz": 1.4,
    "accesscontrol": 1.4, "auth": 1.3, "privesc": 1.5, "ssrf": 1.4, "exfil": 1.5, "secrets": 1.4,
    "deserialization": 1.4, "injection": 1.3, "race": 1.4, "toctou": 1.4,
}
_DEFAULT_ARMS = ["authz", "business_logic", "idempotency", "injection", "ssrf", "auth", "race",
                 "mass_assignment", "info_disclosure", "supply_chain", "misconfig", "recon",
                 "privesc", "lateral"]

# Score for an untried arm (UCB1 "try every arm once first"). A LARGE FINITE sentinel rather than
# float('inf'): inf swallows the priority-bonus / TargetProfile-saturation deltas in select()'s sort key
# (inf +/- anything == inf), so those steers were silently inert for untried arms and ordering collapsed
# to pure jitter. A finite value >> any real UCB score (rewards <= ~2.56, exploration term small, so real
# scores stay well under ~20) keeps untried arms ahead of tried ones AND lets the biases + jitter order
# them sensibly. Also removes inf from the arithmetic entirely (no inf/NaN risk downstream).
_UNTRIED = 1e12


def _impact(cls: str) -> float:
    c = (cls or "").lower()
    return max([w for k, w in _IMPACT.items() if k in c] or [1.0])


# ------------------------------------------------------------------ PRIORITY SWITCH (opt-in, non-persisting)
# A run-scoped bias toward a chosen SET of gap families -- so effort can shift in SEVERAL directions and the
# parallel agents SPLIT across them, instead of the bandit converging on one class run after run. Driven by
# $AEGIS_PRIORITY at select() time ONLY; NEVER written to reward_sum/n or the saved JSON (board-converged:
# the on-disk means stay a pure function of verdicts, so the switch is fully reversible and can't poison the
# learned signal). Unset/blank/none -> totally inert (select() is byte-identical to before).
_PROFILES = {
    # trust-chain / config / privilege gaps -- the g236-style, high-yield direction
    "trust_chain": ["authz", "accesscontrol", "auth", "ssrf", "misconfig",
                    "mass_assignment", "privesc", "lateral", "recon"],
    # novel-code direction (memory/logic depth in code + deps)
    "novel_code":  ["injection", "deserialization", "ssti", "supply_chain",
                    "race", "business_logic", "fuzz", "depth"],
    # de-herd ONLY: split the agents across distinct arms, no directional preference
    "balanced":    [],
}


def _profile_families():
    """None = inert (AEGIS_PRIORITY unset/none/off). A list (possibly EMPTY for 'balanced') = active.
    Accepts a known profile name OR an ad-hoc comma-list of family tokens (e.g. 'authz,ssrf,misconfig')."""
    raw = (os.environ.get("AEGIS_PRIORITY") or "").strip().lower()
    if not raw or raw in ("none", "off", "0", "false"):
        return None
    if raw in _PROFILES:
        return list(_PROFILES[raw])
    return [t.strip() for t in raw.split(",") if t.strip()]


def priority_active() -> bool:
    return _profile_families() is not None


def _bonus_value() -> float:
    try:
        return float(os.environ.get("AEGIS_PRIORITY_BONUS", "0.5"))
    except (TypeError, ValueError):
        return 0.5


def _profile_bonus(arm: str) -> float:
    """Transient additive bonus for an in-family arm (rewards run ~0.15..2.5, so a flat ~0.5 reorders the
    top-k without permanently pinning). 0.0 when inert or for the 'balanced' (no-direction) profile."""
    fams = _profile_families()
    if not fams:                       # None (inert) or [] (balanced -> de-herd only, no directional bonus)
        return 0.0
    a = (arm or "").lower()
    return _bonus_value() if any(k in a for k in fams) else 0.0


def _split_on() -> bool:
    return str(os.environ.get("AEGIS_PRIORITY_SPLIT", "1")).lower() not in ("0", "false", "off", "no")


def _span_families(ordered: list, fams: list, k: int) -> list:
    """Round-robin the (already score+bonus-sorted) arms across the priority FAMILIES so the returned top-k
    SPANS several directions (one best arm per family, then the next, ...), instead of k arms of one family.
    Non-family arms fill any remainder, preserving score order."""
    buckets = {f: [] for f in fams}
    rest = []
    for a in ordered:
        al = a.lower()
        for f in fams:
            if f in al:
                buckets[f].append(a)
                break
        else:
            rest.append(a)
    out, seen = [], set()
    while len(out) < k:
        progressed = False
        for f in fams:
            if buckets[f]:
                a = buckets[f].pop(0)
                if a not in seen:
                    out.append(a); seen.add(a); progressed = True
                    if len(out) >= k:
                        break
        if not progressed:
            break
    if len(out) < k:
        for a in [x for f in fams for x in buckets[f]] + rest:
            if a not in seen:
                out.append(a); seen.add(a)
                if len(out) >= k:
                    break
    return out[:max(1, k)]


class Bandit:
    """UCB1 over technique-classes. State = {arm: {n, reward_sum}}. `select(k)` returns the top-k arms
    to try next; `update(cls, verdict, surface_impact)` records a pull's reward."""
    def __init__(self, path=None, c: float = 1.4, arms=None, seed=None):
        self.path = path
        self.c = c
        self.arms = {}
        for a in (arms or _DEFAULT_ARMS):
            self.arms[a] = {"n": 0, "reward_sum": 0.0}
        # SEEDED stochastic tie-break (board audit (e)): UCB is deterministic given counts, so equal-value
        # arms would always resolve by enumeration order -> a fixed exploration bias. A seeded RNG breaks
        # ties without harming reproducibility (seed logged). Seed: AEGIS_SEED, else time-derived.
        import random as _r
        if seed is None:
            try:
                seed = int(os.environ.get("AEGIS_SEED", "")) if os.environ.get("AEGIS_SEED") else None
            except Exception:
                seed = None
        self.seed = seed if seed is not None else (int(time.time() * 1000) & 0xFFFFFFFF)
        self.rng = _r.Random(self.seed)
        self._load()

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            d = json.load(open(self.path, encoding="utf-8"))
            for a, st in (d.get("arms") or {}).items():
                self.arms[a] = {"n": int(st.get("n", 0)), "reward_sum": float(st.get("reward_sum", 0.0))}
        except Exception:
            pass

    def save(self):
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            json.dump({"arms": self.arms, "saved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                      open(tmp, "w", encoding="utf-8"), indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def _total(self) -> int:
        return sum(a["n"] for a in self.arms.values())

    def score(self, arm: str) -> float:
        st = self.arms.get(arm) or {"n": 0, "reward_sum": 0.0}
        if st["n"] == 0:
            return _UNTRIED                         # UCB1: try every arm once first (finite sentinel, not inf)
        mean = st["reward_sum"] / st["n"]
        total = max(1, self._total())
        return mean + self.c * math.sqrt(math.log(total) / st["n"])

    def select(self, k: int = 3, exclude=None) -> list:
        """Top-k arms by UCB score, best-first. `exclude` = classes already saturated/closed this run."""
        ex = {str(e).lower() for e in (exclude or [])}
        cands = [a for a in self.arms if a.lower() not in ex]
        # sort by UCB score desc; two transient, opt-in, NEVER-persisted biases ride ONLY in this sort key:
        # the priority bonus (up-weight a chosen family) and the TargetProfile saturation bias (down-weight
        # classes already tried heavily with ~0 payoff -- the saturation fix). Ties break with a seeded RNG.
        try:
            import target_profile as _tp
            _tpb = _tp.active_bias()          # {class: negative delta} for saturated classes; {} when inert
        except Exception:
            _tpb = {}
        jitter = {a: self.rng.random() for a in cands}
        cands.sort(key=lambda a: (-(self.score(a) + _profile_bonus(a)
                                    + _tpb.get(a.split("/")[0].lower(), 0.0)), jitter[a]))
        # PRIORITY SPLIT: with >=2 priority families, span them (round-robin) so the top-k covers several
        # directions rather than k arms of one family. Inert unless AEGIS_PRIORITY is set.
        fams = _profile_families()
        if fams and len(fams) >= 2 and _split_on():
            return _span_families(cands, fams, k)
        return cands[:max(1, k)]

    def register(self, arm: str):
        """Ensure an arm exists (the synthesizer/board can introduce classes the seed list didn't have)."""
        if arm and arm not in self.arms:
            self.arms[arm] = {"n": 0, "reward_sum": 0.0}

    def update(self, cls: str, verdict: str, *, info_gain: int = 1, surface_class: str = None):
        """Record a pull. verified -> impact-scaled 1.0; info-gaining clean -> small positive; noise -> 0.
        `cls` is the technique-class arm; `surface_class` (optional) scales impact by the surface too."""
        if not cls:
            return
        arm = cls.lower()
        self.register(arm)
        if verdict == "verified":
            reward = 1.0 * _impact(cls) * _impact(surface_class or cls)
        elif info_gain and info_gain > 0:
            reward = 0.15                            # a real refutation is small information, not zero
        else:
            reward = 0.0                             # noise never rewards
        self.arms[arm]["n"] += 1
        self.arms[arm]["reward_sum"] += reward

    def snapshot(self) -> dict:
        return {a: {"n": st["n"], "mean": round(st["reward_sum"] / st["n"], 3) if st["n"] else None,
                    "ucb": (None if st["n"] == 0 else round(self.score(a), 3))}
                for a, st in self.arms.items()}


def _class_of(move: dict) -> str:
    return str((move or {}).get("vuln_class") or (move or {}).get("angle")
               or (move or {}).get("class") or (move or {}).get("technique") or "").split("/")[0].strip()


def _attempt_sig(a: dict) -> str:
    mv = a.get("move") or {}
    d = a.get("delta")
    return "|".join([str(mv.get("surface") or mv.get("path")), _class_of(mv), str(a.get("verdict")),
                     json.dumps(d, sort_keys=True)[:80] if d is not None else str(a.get("gain"))])


def learn_from_context(bandit: Bandit, context: dict) -> int:
    """Idempotently fold the loop's attempt history (in `context`) into the bandit. `context['attempts']`
    is a SLIDING window (last-N) and `context['confirmed']` is the full confirm list, so we dedup by a
    per-attempt SIGNATURE (not index) -- robust to the window sliding and to a confirm also appearing in
    the recent-attempts window. Returns how many NEW attempts were learned."""
    seen = getattr(bandit, "_seen_sigs", None)
    if seen is None:
        seen = bandit._seen_sigs = set()
    n = 0
    # confirms first (full list): impact-scaled positive reward
    for c in (context or {}).get("confirmed") or []:
        a = {"move": c.get("move") or {}, "verdict": "verified", "gain": 1, "delta": None}
        sig = _attempt_sig(a)
        if sig not in seen:
            seen.add(sig); bandit.update(_class_of(a["move"]), "verified", info_gain=1,
                                         surface_class=a["move"].get("surface")); n += 1
    for a in (context or {}).get("attempts") or []:
        sig = _attempt_sig(a)
        if sig in seen:
            continue
        seen.add(sig)
        mv = a.get("move") or {}
        if mv.get("_eps"):
            continue          # epsilon-diversify pick: log-only, NO posterior update (keep T0 unbiased)
        bandit.update(_class_of(mv), a.get("verdict", "rejected"),
                      info_gain=a.get("gain", 0), surface_class=mv.get("surface"))
        n += 1
    return n


def default_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rag", "bandit_state.json")
