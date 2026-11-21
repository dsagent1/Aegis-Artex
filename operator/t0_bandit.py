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
import json, math, os, re, time

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


# ---- ARM CANONICALIZATION: merge synonym spellings so the yield signal isn't split across duplicates ----
# Maps an EXACT normalized (hyphenated) class spelling -> one canonical arm. Only clear synonyms of the SAME
# single class are merged; COMPOUND arms (contain '+', a real chain like 'idempotency+race') are preserved,
# and anything not listed keeps its own cleaned name. Values use the _DEFAULT_ARMS style so the hunt's angle
# families and the bandit arms line up. Every canonical's own hyphenated form maps back to itself -> _canon
# is IDEMPOTENT.
_CANON_SYN = {
    "information-disclosure": "info_disclosure", "info-disclosure": "info_disclosure",
    "information-leak": "info_disclosure", "sensitive-data-exposure": "info_disclosure",
    "source-code-disclosure": "info_disclosure", "source-code-exposure": "info_disclosure",
    "mass-assignment": "mass_assignment",
    "server-side-request-forgery": "ssrf",
    "cross-site-scripting": "xss", "reflected-xss": "xss",
    "cross-site-request-forgery": "csrf",
    "server-side-template-injection": "ssti",
    "sql-injection": "injection", "nosql-injection": "injection", "filter-injection": "injection",
    "path-traversal": "traversal", "directory-traversal": "traversal",
    "supply-chain": "supply_chain", "supply-chain-attack": "supply_chain",
    "supply-chain-compromise": "supply_chain", "supply-chain-attack": "supply_chain",
    "dependency-confusion": "supply_chain", "vulnerable-dependency": "supply_chain",
    "broken-access-control": "authz", "broken-object-level-authorization": "authz",
    "broken-object-level-authz": "authz", "bola": "authz", "idor": "authz",
    "authorization": "authz", "access-control": "authz", "authorization-bypass": "authz",
    "broken-authentication": "auth", "broken-auth": "auth", "authn": "auth",
    "authentication-bypass": "auth", "auth-bypass": "auth",
    "username-enumeration": "auth", "user-enumeration": "auth", "credential-stuffing": "auth",
    "security-misconfiguration": "misconfig", "misconfiguration": "misconfig",
    "business-logic": "business_logic", "business-logic-flaw": "business_logic",
    "race-condition": "race", "rate-limiting": "rate_enum", "rate-enum": "rate_enum",
}


def _canon(cls: str) -> str:
    """Canonical arm name for a raw technique-class string. Takes the primary class (before any '/'),
    normalizes separators to '-', then maps a known synonym to its canonical arm (else returns the cleaned
    name). COMPOUND arms with '+' are preserved as distinct. Idempotent."""
    s = (cls or "").strip().lower().split("/")[0].strip()
    if not s:
        return ""
    norm = re.sub(r"-{2,}", "-", re.sub(r"[\s_]+", "-", s)).strip("-")
    return _CANON_SYN.get(norm, norm)


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
        arm = _canon(cls)                            # merge synonym spellings onto one canonical arm
        if not arm:
            return
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

    def normalize_inplace(self) -> dict:
        """One-time hygiene: fold arms onto canonical names (summing n + reward_sum) so a split synonym's
        yield is reunited into a single, higher-n arm. Returns {canonical: [raw names merged into it]}."""
        new_arms: dict = {}
        merged: dict = {}
        for raw, st in self.arms.items():
            canon = _canon(raw) or raw
            tgt = new_arms.setdefault(canon, {"n": 0, "reward_sum": 0.0})
            tgt["n"] += int(st.get("n", 0))
            tgt["reward_sum"] += float(st.get("reward_sum", 0.0))
            if canon != raw:
                merged.setdefault(canon, []).append(raw)
        self.arms = new_arms
        return merged


def _class_of(move: dict) -> str:
    return str((move or {}).get("vuln_class") or (move or {}).get("angle")
               or (move or {}).get("class") or (move or {}).get("technique") or "").split("/")[0].strip()


def _attempt_sig(a: dict) -> str:
    mv = a.get("move") or {}
    d = a.get("delta")
    return "|".join([str(mv.get("surface") or mv.get("path")), _class_of(mv), str(a.get("verdict")),
                     json.dumps(d, sort_keys=True)[:80] if d is not None else str(a.get("gain"))])


def _norm_surface_lite(move: dict) -> str:
    """Stable surface key: path with numeric ids/hex runs collapsed, plus the param name -- so the SAME
    endpoint-shape coalesces across runs (e.g. /api/Users/42 and /api/Users/99 -> /api/Users/{id})."""
    s = str((move or {}).get("surface") or (move or {}).get("path") or "").lower().split("?")[0]
    s = re.sub(r"/[0-9a-f]{8,}", "/{hex}", s)
    s = re.sub(r"/\d+", "/{id}", s)
    p = str((move or {}).get("param") or "").lower().strip()
    return (s.strip("/") + ("#" + p if p else "")) or "?"


def _fine_key(move: dict):
    """Fine hypothesis signature (finer than the bandit's approach-FAMILY arm): the canonical class, the
    normalized surface+param, the mechanism, the HTTP method and the expected oracle-signal -- so a SPECIFIC
    approach is tracked across runs. Returns (sig16, parts). PAYLOAD VALUE is deliberately absent."""
    cls = _canon(_class_of(move)) or "unknown"
    parts = [cls, _norm_surface_lite(move),
             str((move or {}).get("mechanism") or "").lower().strip()[:48],
             str((move or {}).get("method") or "").upper().strip(),
             str((move or {}).get("expected_oracle") or (move or {}).get("expected_signal") or "").lower().strip()[:28]]
    import hashlib
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16], parts


def _fine_label(parts) -> str:
    cls, surf, mech, method, oracle = (list(parts) + [""] * 5)[:5]
    return f"{cls} @ {surf or '?'}" + (f" [{mech}]" if mech else "") + (f" ({method})" if method else "")


def default_sig_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rag", "sig_yield.json")


class SigYield:
    """Per-SPECIFIC-approach yield accumulator -- finer than the bandit's approach-FAMILY arms. Keyed by a
    fine hypothesis signature (class, normalized surface+param, mechanism, method, oracle-signal) so you can
    see WHICH concrete approach produced confirms across runs, not just which family. SAME reward model as
    the bandit (verified -> impact-scaled 1.0; info-gaining clean -> 0.15; noise -> 0). Pure, persisted,
    offline-safe, never raises into the loop. Gated with AEGIS_SIG_YIELD=0."""
    def __init__(self, path=None):
        self.path = path
        self.sigs = {}
        self._load()

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            d = json.load(open(self.path, encoding="utf-8"))
            for k, v in (d.get("sigs") or {}).items():
                self.sigs[k] = {"n": int(v.get("n", 0)), "reward_sum": float(v.get("reward_sum", 0.0)),
                                "label": v.get("label", ""), "last": v.get("last", "")}
        except Exception:
            pass

    def save(self):
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            json.dump({"sigs": self.sigs, "saved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                      open(tmp, "w", encoding="utf-8"), indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def update(self, move: dict, verdict: str, *, info_gain: int = 1, surface_class: str = None):
        if not isinstance(move, dict):
            return
        sig, parts = _fine_key(move)
        cls = parts[0]
        if verdict == "verified":
            reward = 1.0 * _impact(cls) * _impact(surface_class or cls)
        elif info_gain and info_gain > 0:
            reward = 0.15
        else:
            reward = 0.0
        st = self.sigs.setdefault(sig, {"n": 0, "reward_sum": 0.0, "label": _fine_label(parts), "last": ""})
        st["n"] += 1
        st["reward_sum"] += reward
        st["last"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def report(self, top: int = 0, min_n: int = 1):
        rows = sorted(((k, v) for k, v in self.sigs.items() if v["n"] >= min_n),
                      key=lambda kv: (kv[1]["reward_sum"] / kv[1]["n"] if kv[1]["n"] else -1), reverse=True)
        if top:
            rows = rows[:top]
        print(f"{'specific approach  (class @ surface [mechanism] (verb))':58}{'n':>4}{'mean_yield':>11}")
        print("-" * 73)
        for _, v in rows:
            print(f"{v['label'][:58]:58}{v['n']:>4}{(v['reward_sum'] / v['n'] if v['n'] else 0):>11.3f}")
        print("-" * 73)
        confirmed = sum(1 for v in self.sigs.values() if v["reward_sum"] / max(1, v["n"]) >= 1.0)
        print(f"distinct specific approaches: {len(self.sigs)}   (>=1.0 mean, i.e. a confirm: {confirmed})")


def learn_from_context(bandit: Bandit, context: dict) -> int:
    """Idempotently fold the loop's attempt history (in `context`) into the bandit. `context['attempts']`
    is a SLIDING window (last-N) and `context['confirmed']` is the full confirm list, so we dedup by a
    per-attempt SIGNATURE (not index) -- robust to the window sliding and to a confirm also appearing in
    the recent-attempts window. Returns how many NEW attempts were learned."""
    seen = getattr(bandit, "_seen_sigs", None)
    if seen is None:
        seen = bandit._seen_sigs = set()
    # Fine-grained companion store (per-SPECIFIC-approach yield), fed from the SAME verdict stream as the
    # family bandit. Attached to the bandit so it persists across folds; gated with AEGIS_SIG_YIELD=0.
    sy = getattr(bandit, "_sigyield", None)
    if sy is None and os.environ.get("AEGIS_SIG_YIELD", "1") != "0":
        sy = bandit._sigyield = SigYield(default_sig_path())
    n = 0
    # confirms first (full list): impact-scaled positive reward
    for c in (context or {}).get("confirmed") or []:
        a = {"move": c.get("move") or {}, "verdict": "verified", "gain": 1, "delta": None}
        sig = _attempt_sig(a)
        if sig not in seen:
            seen.add(sig)
            bandit.update(_class_of(a["move"]), "verified", info_gain=1,
                          surface_class=a["move"].get("surface"))
            if sy:
                sy.update(a["move"], "verified", info_gain=1, surface_class=a["move"].get("surface"))
            n += 1
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
        if sy:
            sy.update(mv, a.get("verdict", "rejected"), info_gain=a.get("gain", 0),
                      surface_class=mv.get("surface"))
        n += 1
    if sy:
        sy.save()             # persist the fine store alongside the bandit (guarded, never raises)
    return n


def default_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rag", "bandit_state.json")


def _report(b: "Bandit", top: int = 0):
    """Print the APPROACH-YIELD benchmark: mean reward (verified confirms, impact-scaled) per approach-class,
    best-first. This is the persisted answer to 'which approach produces more viable findings'."""
    rows = sorted(((arm, st["n"], st["reward_sum"]) for arm, st in b.arms.items()),
                  key=lambda r: (r[2] / r[1] if r[1] else -1), reverse=True)
    rows = [r for r in rows if r[1] > 0]                      # only arms with real pulls
    if top:
        rows = rows[:top]
    print(f"{'approach-class':30}{'pulls':>6}{'reward':>9}{'mean_yield':>12}{'ucb':>8}")
    print("-" * 65)
    for arm, n, rs in rows:
        print(f"{arm:30}{n:>6}{rs:>9.2f}{(rs / n if n else 0):>12.3f}{(round(b.score(arm), 3) if n else 0):>8}")
    print("-" * 65)
    print(f"total pulls: {b._total()}   arms with data: {len(rows)} / {len(b.arms)} total")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="T0 bandit -- the approach-yield benchmark over technique-classes.")
    ap.add_argument("--path", default=default_path(), help="bandit_state.json (default: ../rag/bandit_state.json)")
    ap.add_argument("--report", action="store_true", help="print the per-approach yield table (default action)")
    ap.add_argument("--top", type=int, default=0, help="report: show only the top-N approaches by mean yield")
    ap.add_argument("--normalize", action="store_true",
                    help="ONE-TIME: merge synonym arms into canonical names (sums counts; backs up first)")
    ap.add_argument("--sigs", action="store_true",
                    help="report the FINE-grained per-SPECIFIC-approach yield (class @ surface [mechanism]) instead")
    ap.add_argument("--sig-path", default=default_sig_path(), help="sig_yield.json (fine store)")
    a = ap.parse_args()
    if a.sigs:
        SigYield(path=a.sig_path).report(top=a.top)
        return
    b = Bandit(path=a.path)
    if a.normalize:
        import shutil
        bak = a.path + ".pre-normalize.bak"
        if os.path.exists(a.path) and not os.path.exists(bak):   # keep the FIRST backup; never clobber it
            shutil.copy2(a.path, bak)
        before = len(b.arms)
        merged = b.normalize_inplace()
        b.save()
        print(f"normalized: {before} -> {len(b.arms)} arms "
              f"(backup: {os.path.basename(a.path)}.pre-normalize.bak)")
        for canon, raws in sorted(merged.items(), key=lambda kv: -len(kv[1])):
            print(f"  {canon:20} <- {', '.join(sorted(raws))}")
        print()
    _report(b, top=a.top)


if __name__ == "__main__":
    main()
