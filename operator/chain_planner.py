"""
chain_planner.py -- STEP 6 / B2 of the corpus+chaining roadmap (the capstone, board-locked to run LAST,
after the corpus is wired and the loop has single-step signal to chain).

Where the single-request loop finds one weakness at a time, real impact is usually a CHAIN: an artifact
captured at hop N (an id, a token, a leaked value) unlocks hop N+1. This module makes chaining a
first-class, reproducibility-gated, learned-back mechanism -- distinct from redteam/attack_graph.py
(cross-HOST pivots); this is intra-target, non-destructive request chains.

Board guardrails, enforced here:
  * MAX 3 HOPS (`AEGIS_CHAIN_MAX_HOPS`) -- deeper chains are non-reproducible in practice.
  * STATE-CARRY: hop N `capture`s vars from its response; hop N+1 `consume`s them via {{var}} templates
    (the same substitution the stateful leg uses) -- a chain only links when a consume matches a capture.
  * PER-HOP ORACLE: every hop must independently verify (via the loop's oracle) or the chain is dead.
  * REPRODUCIBILITY: the WHOLE chain must reproduce >= `reproduce` times end-to-end (default 2) from the
    same starting state, else it is NON-REPRODUCIBLE and does NOT count (the board's determinism gate).
  * LEARN-BACK: a reproducible, fully-verified chain is written to learned_techniques.json as a multi-step
    recipe (self-improving loop) -- attributed, never overwriting curated entries.

Non-destructive throughout: hops are ordinary guarded moves (the vectors non-destructive guard still
applies); DELETE and destructive verbs never chain.

This module is engine glue: `compose()` builds candidate chains from leads/step-specs, `grade()` runs +
reproduces + grades a chain, `record_recipe()` writes back. The live loop calls them via chain_hook().
"""
from __future__ import annotations
import json
import os
import re

MAX_HOPS = int(os.environ.get("AEGIS_CHAIN_MAX_HOPS", "3"))
_CAPTURE_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
_SAFE_VERBS = {"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"}   # DELETE never chains


def _consumes(step) -> set:
    """vars a step CONSUMES = {{var}} tokens anywhere in its path/body/surface."""
    blob = json.dumps({k: step.get(k) for k in ("path", "surface", "body", "measure")}, default=str)
    return set(_CAPTURE_RE.findall(blob))


def _captures(step) -> set:
    """vars a step CAPTURES = keys of its `capture` map."""
    return set((step.get("capture") or {}).keys())


def compose(steps, max_hops=MAX_HOPS):
    """Order/link candidate steps into chains: greedily start from a step that consumes NOTHING (a valid
    entry hop), then append any step whose consumed vars are ALL satisfied by the running captured set.
    Returns a list of chains (each an ordered list of step dicts), longest-first, capped at max_hops.
    A step that captures nothing and consumes nothing is a trivial 1-hop chain (kept only if alone)."""
    steps = [s for s in (steps or []) if (s.get("method", "GET").upper() in _SAFE_VERBS)]
    chains = []
    for i, seed in enumerate(steps):
        if _consumes(seed):
            continue                        # not a valid entry hop (needs an upstream capture)
        chain = [seed]
        have = set(_captures(seed))
        pool = [s for j, s in enumerate(steps) if j != i]
        progressed = True
        while progressed and len(chain) < max_hops:
            progressed = False
            for s in list(pool):
                need = _consumes(s)
                if need and need.issubset(have):
                    chain.append(s)
                    have |= _captures(s)
                    pool.remove(s)
                    progressed = True
                    break
        if len(chain) >= 2:                 # a real (multi-hop) chain
            chains.append(chain)
    chains.sort(key=len, reverse=True)
    return chains


def _get(obj, path):
    """Extract a captured value from a hop response (reuses the stateful leg's $-path extractor)."""
    try:
        import vectors
        return vectors._sf_get(obj, path)
    except Exception:
        return obj if not path else None


def _sub(val, vars):
    """Substitute {{var}} tokens from prior-hop captures (reuses the stateful leg's substituter)."""
    try:
        import vectors
        return vectors._sf_sub(val, vars)
    except Exception:
        return val


def grade(chain, execute, oracle, reproduce=2, role="owner"):
    """Run + grade a chain, CARRYING STATE across hops: hop N captures vars from its response, hop N+1
    consumes them via {{var}} substitution before it runs. `execute(move, phase)->result`,
    `oracle(result)->(verdict, receipt)` are the loop's own callables (so grading uses the SAME ground
    truth). Each hop must verify; the whole chain must reproduce `reproduce` times end-to-end. Returns a
    verdict dict; verified iff every hop verified in EVERY run."""
    import json as _j
    reproduce = max(1, int(reproduce))
    runs = []
    for r in range(reproduce):
        hop_results = []
        all_ok = True
        vars = {}                            # runtime state carried hop N -> N+1
        for hop_i, step in enumerate(chain):
            move = _sub(dict(step), vars)    # substitute prior captures into this hop
            move.setdefault("role", role)
            move.setdefault("action", step.get("action", "web"))
            try:
                res = execute(move, "chain")
                verdict, receipt = oracle(res)
            except Exception as e:
                res, verdict, receipt = {}, "error", {"err": str(e)[:120]}
            ok = verdict == "verified"
            # CAPTURE from this hop's response body (best-effort JSON parse) for downstream hops
            cap = step.get("capture") or {}
            if cap:
                body = res.get("body") if isinstance(res, dict) else None
                try:
                    j = _j.loads(body) if isinstance(body, str) else body
                except Exception:
                    j = None
                for var, jp in cap.items():
                    vars[var] = _get(j, jp)
            hop_results.append({"hop": hop_i, "action": move.get("action"),
                                "surface": move.get("path") or move.get("surface"),
                                "verdict": verdict})
            if not ok:
                all_ok = False
                break                        # a broken hop kills this run (no point continuing)
        runs.append({"run": r, "hops_ok": all_ok, "hops": hop_results})
        if not all_ok:
            break                            # non-reproducible -> stop early
    reproduced = sum(1 for x in runs if x["hops_ok"])
    verified = reproduced >= reproduce
    return {"verdict": "verified" if verified else "non-reproducible" if reproduced else "rejected",
            "hops": len(chain), "reproduce_required": reproduce, "reproduced": reproduced,
            "runs": runs, "chain": [{"action": s.get("action", "web"),
                                     "surface": s.get("path") or s.get("surface"),
                                     "captures": sorted(_captures(s)),
                                     "consumes": sorted(_consumes(s))} for s in chain]}


def record_recipe(chain, verdict, learned_path=None, objective="", source_run="chain"):
    """Write a reproducible, verified chain back to learned_techniques.json as a multi-step recipe.
    Non-destructive to the DB: appends, never overwrites curated entries; deduped by recipe id."""
    if verdict.get("verdict") != "verified":
        return {"written": False, "why": "chain not verified/reproducible"}
    learned_path = learned_path or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                "..", "rag", "learned_techniques.json")
    learned_path = os.path.abspath(learned_path)
    try:
        with open(learned_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        data = {"_note": "LEARNED techniques (self-improving loop).", "techniques": []}
    techs = data.setdefault("techniques", [])
    surfaces = [h.get("surface") for h in verdict.get("chain", [])]
    rid = "learned.chain." + re.sub(r"[^a-z0-9]+", "-", ("-".join(str(s) for s in surfaces))[:60].lower()).strip("-")
    if any(t.get("id") == rid for t in techs):
        return {"written": False, "why": "recipe already learned", "id": rid}
    steps_desc = " -> ".join("%s %s" % (h.get("action"), h.get("surface")) for h in verdict.get("chain", []))
    techs.append({
        "id": rid, "class": "Chain", "learned": True, "chain": True,
        "desc": ("Reproducible %d-hop chain: %s" % (verdict.get("hops"), steps_desc))[:400],
        "how_to_test": "Replay the multi-step chain (state-carried); reproduced %d/%d from clean state."
                       % (verdict.get("reproduced"), verdict.get("reproduce_required")),
        "kali_tools": [], "new_code": ["operator chain_planner"], "applies_to": surfaces,
        "oracle": "per-hop oracle + whole-chain reproducibility", "severity_hint": "high",
        "steps": verdict.get("chain"), "source_run": source_run, "objective": objective[:200]})
    try:
        with open(learned_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return {"written": True, "id": rid, "path": learned_path}
    except Exception as e:
        return {"written": False, "why": str(e)}


def chain_hook(leads, execute, oracle, *, reproduce=2, role="owner", learn=True, objective=""):
    """Loop entry point: compose chains from `leads` (step specs carrying capture/consume hints), grade the
    most promising ones, learn back the reproducible winners. Bounded (composes+grades, not a search).
    Returns {chains_tried, verified:[...], recorded:[...]}. Offline-safe: any error -> empty result."""
    out = {"chains_tried": 0, "verified": [], "recorded": []}
    try:
        chains = compose(leads)
    except Exception:
        return out
    max_try = int(os.environ.get("AEGIS_CHAIN_MAX_TRY", "5"))
    for chain in chains[:max_try]:
        out["chains_tried"] += 1
        v = grade(chain, execute, oracle, reproduce=reproduce, role=role)
        if v["verdict"] == "verified":
            out["verified"].append(v)
            if learn:
                rec = record_recipe(chain, v, objective=objective)
                if rec.get("written"):
                    out["recorded"].append(rec["id"])
    return out
