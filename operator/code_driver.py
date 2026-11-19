# -*- coding: utf-8 -*-
"""AEGIS -- CODE DRIVER: the adaptive "driver seat" for custom-code / novel / zero-day-class discovery.

The board's headline gap: today "direction" is split across the Planner (STATIC seed_moves), iterative_hunt
(fixed-vector dispatch) and one-shot code-bench writing -- NOTHING reasons over running RESULTS to choose the
next custom-code experiment or iterate a failed exploit. Without it AEGIS is a known-CVE replay engine. This
module is that missing adaptive controller. It sits BETWEEN the planner (which seeds it) and iterative_hunt/
test_suggestions (which execute), and runs the tight loop the board specified:

    propose falsifiable code HYPOTHESIS  (strong reasoner = ds, biased to NOVELTY / under-explored surface)
      -> write BESPOKE code for it       (the 6-model code bench; on a REFINE, the prior code + ERROR TRACE
                                          are fed back so the bench fixes it -- closes the no-feedback gap)
      -> RUN it oracle-gated, non-destructive (test_suggestions harness on the contained mirror)
      -> READ oracle result + error trace, DECIDE {refine | pivot surface | new hypothesis | give up}
      -> WRITE BACK to the hypothesis ledger: BOTH wins AND instructive failures (so dead-ends aren't retried
         and a win's code+preconditions+oracle are reusable) -> redirect.

Hypothesis IDENTITY reuses iterative_hunt's fingerprint (angle, normalized-surface, vuln-class, mechanism,
oracle-type) so a value-only tweak is NOT a new hypothesis (no lazy convergence). Budget-capped; novelty-
biased scheduling. Doctrine: CONTAINED MIRROR ONLY, non-destructive (the test_suggestions guard enforces it),
only ORACLE-verified findings count. Offline/dry mode (`--dry`) simulates run+propose so the loop is testable
without a live mirror.
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import probe_state as PS               # G24: mechanical state-carry across refine attempts (board design A)
import schema_discovery as SD          # G27: read-then-mutate -- learn an endpoint's real field contract
try:
    import meta_oracle as MO           # G44: trustworthy confirmation gate for SQL-invariant wins (baseline-empty->exec->rows-after)
except Exception:
    MO = None
LEDGER = os.path.join(HERE, "code_driver_ledger.db")
LEARNED = os.path.join(HERE, "..", "rag", "learned_techniques.json")
TECH_SEARCH = os.path.join(HERE, "..", "rag", "technique_search.py")   # G29: query the KNOWN techniques DB


def _env_fingerprint(target_ctx):
    """G30 (board): build the environment profile the precondition gate checks against -- stack tokens,
    discovered endpoints, role count, auth, and a SINK INVENTORY inferred at zero network cost from the
    stack + endpoint names. A technique whose sink isn't present here is not applicable and must be dropped."""
    tc = target_ctx or {}
    stack = str(tc.get("stack", "")).lower()
    eps = [str(e).lower() for e in (tc.get("endpoints") or [])]
    try:
        roles = len(json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}")) or {})
    except Exception:
        roles = 0
    joined = " ".join(eps)
    sinks = {
        "sql": ("postgres" in stack or "prisma" in stack or "mysql" in stack or "sql" in stack),
        "file_upload": any(k in joined for k in ("upload", "import", "attachment", "/file", "document")),
        "ssrf": any(k in joined for k in ("url", "webhook", "fetch", "proxy", "callback", "import-from")),
        "ssti": any(k in joined for k in ("template", "render", "preview")),
        "xxe": any(k in joined for k in ("xml", "soap", "wsdl")),
        "deserialization": any(k in joined for k in ("pickle", "serialize", "yaml")),
    }
    return {"stack": stack, "endpoints": eps, "roles": roles,
            "auth": ("cookie-session" if "caddy" in stack or "express" in stack else "unknown"),
            "sinks": sinks, "has_endpoints": bool(eps),
            "mutating": bool(eps)}   # discovered REST money/state endpoints accept POST/PATCH


# technique-class -> the environment PRECONDITION it needs (board: hard gate, drop if not met).
_TECH_REQS = {
    "ssrf": ("sinks", "ssrf"), "upload": ("sinks", "file_upload"), "file": ("sinks", "file_upload"),
    "ssti": ("sinks", "ssti"), "template": ("sinks", "ssti"), "xxe": ("sinks", "xxe"),
    "xml": ("sinks", "xxe"), "deser": ("sinks", "deserialization"), "pickle": ("sinks", "deserialization"),
    "sqli": ("sinks", "sql"), "nosqli": ("sinks", "sql"), "sql": ("sinks", "sql"),
    "idor": ("roles>=", 2), "authz": ("roles>=", 2), "role": ("roles>=", 2), "access": ("roles>=", 1),
}


def _applicable(tech, env):
    """Hard precondition gate: a technique is applicable only if the environment provides what it needs.
    Prefers a structured applies_to on the technique; falls back to a class/id keyword -> requirement map.
    recon/discovery/logic/stateful classes are broadly applicable to any HTTP app and pass by default."""
    # structured predicate (board's durable form): a `preconditions` dict, or an applies_to that is a dict.
    ap = tech.get("preconditions") if isinstance(tech.get("preconditions"), dict) else None
    if ap is None and isinstance(tech.get("applies_to"), dict):
        ap = tech.get("applies_to")
    if ap:
        if ap.get("requires_stack") and not all(s in env["stack"] for s in ap["requires_stack"]):
            return False
        if ap.get("excludes_stack") and any(s in env["stack"] for s in ap["excludes_stack"]):
            return False
        sink = ap.get("requires_sink")
        if sink and not env["sinks"].get(sink):
            return False
        if ap.get("requires_roles") and env["roles"] < int(str(ap["requires_roles"]).lstrip(">=") or 1):
            return False
        if ap.get("requires_endpoints") and not env["has_endpoints"]:
            return False
        if ap.get("requires_mutation") and not env.get("mutating"):
            return False
        return True
    blob = f"{tech.get('id','')} {tech.get('class','')} {tech.get('desc','')}".lower()
    for kw, req in _TECH_REQS.items():
        if kw in blob:
            kind, val = req
            if kind == "sinks" and not env["sinks"].get(val):
                return False
            if kind == "roles>=" and env["roles"] < val:
                return False
    return True


def _endpoint_for(tech, env):
    """Pick the most representative discovered endpoint to probe/attach a technique to."""
    eps = env.get("endpoints") or []
    blob = f"{tech.get('id','')} {tech.get('class','')} {tech.get('desc','')}".lower()
    money = [e for e in eps if any(k in e for k in ("credit", "invoice", "payment", "refund", "expense", "estimate"))]
    if any(k in blob for k in ("money", "idempot", "replay", "stateful", "logic", "race")) and money:
        return money[0]
    return eps[0] if eps else None


def _applicability_probe(tech, env, role="owner", timeout=12):
    """G31 board next-tier: ONE cheap authenticated request to confirm a technique can ACTUALLY fire here --
    the endpoint answers with a REAL handler (not the SPA shell, not a bare 401/403 wall). Returns True
    (fire-able), False (wall -> drop), or None (couldn't tell -> keep, never over-filter on a flaky mirror).
    Off in dry / when AEGIS_CODE_LIVE_PROBE=0. Cached per endpoint+role."""
    if os.environ.get("AEGIS_CODE_LIVE_PROBE", "1") == "0":
        return None
    ep = _endpoint_for(tech, env)
    if not ep:
        return None
    key = f"{role}:{ep}"
    cache = _applicability_probe.__dict__.setdefault("_cache", {})
    if key in cache:
        return cache[key]
    res = None
    try:
        import test_suggestions as TS
        sess, ok = TS.login(role)
        if not ok:
            return None
        r = sess.get(TS.BASE + ep, timeout=timeout)
        ctype = (r.headers.get("content-type") or "").lower()
        bl = (r.text or "")[:400].lower()
        is_spa = (200 <= r.status_code < 300) and ("text/html" in ctype or "<!doctype html" in bl or 'id="root"' in bl)
        wall = r.status_code in (401, 403) or is_spa
        res = (not wall)                       # real handler reachable -> the technique can fire here
    except Exception:
        res = None
    cache[key] = res
    return res


# postcondition an access-class technique GRANTS -> precondition a follow-on technique NEEDS (chain edges).
_POST = {"access.idor": "object_access", "access.authz_matrix": "cross_role_access",
         "discovery.authz_fuzz": "auth_bypass", "access.": "object_access"}
_PRE = {"logic.": "object_access", "stateful.": "object_access", "logic.money_bounds": "object_access",
        "logic.idempotency_replay": "object_access", "stateful.replay_mutation": "object_access"}


def _chain_hints(techs, env, cap=3):
    """G31: build precondition->postcondition CHAINS over the APPLICABLE techniques -- an access-class move
    that GRANTS reach into an object/role, then a logic/stateful move that EXPLOITS it on the SAME real
    money endpoint. Only edges that connect on this surface; depth 2; access.* first."""
    def post_of(t):
        i = str(t.get("id", ""))
        return next((v for k, v in _POST.items() if i.startswith(k) or i == k), None)
    def pre_of(t):
        i = str(t.get("id", ""))
        return next((v for k, v in _PRE.items() if i.startswith(k) or i == k), None)
    access = [t for t in techs if post_of(t)]
    exploit = [t for t in techs if pre_of(t)]
    money = [e for e in (env.get("endpoints") or []) if any(k in e for k in ("credit", "invoice", "payment", "refund"))]
    tgt = money[0] if money else (env.get("endpoints") or ["the target endpoint"])[0]
    out = []
    for a in access:
        for b in exploit:
            if a["id"] == b["id"]:
                continue
            if post_of(a) == pre_of(b):      # a's grant satisfies b's need
                out.append(f"{a['id']} -> {b['id']} on {tgt} (first use {a['id']} to reach the object/role, "
                           f"then run {b['id']} on it)")
            if len(out) >= cap:
                return out
    return out


def _known_techniques(query, limit=6, env=None):
    """Query the techniques DB (curated + learned + MITRE ATT&CK, mirrors the Kali /opt/aegis-rag store) for
    KNOWN techniques + how-to-test applicable to the objective. G29 (access-first): the driver should try a
    known bypass/access route -- or a COMBINATION -- to GET IN before inventing a novel probe of the wall.
    Best-effort; returns [] if the DB/tool is absent (offline-safe)."""
    if not os.path.exists(TECH_SEARCH) or os.environ.get("AEGIS_CODE_KNOWN_FIRST", "1") == "0":
        return []
    try:
        r = subprocess.run([sys.executable, TECH_SEARCH, query, "--json"], capture_output=True, text=True,
                           timeout=30, env=dict(os.environ, PYTHONUTF8="1"))
        data = json.loads(r.stdout or "[]")
        data = data if isinstance(data, list) else data.get("results", data)
        rows = []
        for t in (data or []):
            row = {"id": t.get("id") or t.get("name"), "class": t.get("class"),
                   "desc": (t.get("desc") or "").split("|")[0][:90],   # curated desc is short; learned is a piped blob
                   "how": (t.get("how_to_test") or "").split("|")[0][:130],
                   "oracle": (t.get("oracle") or "").split("|")[0][:120],   # G34: the canonical INVARIANT to prove
                   "tools": t.get("kali_tools"), "applies_to": t.get("applies_to"),
                   "preconditions": t.get("preconditions")}
            # G30 HARD PRECONDITION GATE: drop techniques whose sink/roles/stack preconditions can't hold
            # in THIS environment (no SSRF/upload/SSTI sink -> those never appear). Board: gate, not rank.
            if env is not None and not _applicable(row, env):
                continue
            rows.append(row)
        # ACCESS-FIRST prefers the CURATED classes (concise, proven-general) over the driver's own verbose
        # self-learned entries -- those are re-fed via learned_ctx already, and dominate keyword ranking.
        # curated technique = a short dotted slug id (access.idor, logic.race); learned/self entries store a
        # long blob (sometimes as the id itself) -> exclude those from the curated tier.
        def _curated(t):
            i = str(t["id"] or "")
            return len(i) <= 40 and not i.startswith("learned.")
        curated = [t for t in rows if _curated(t)]
        learned = [t for t in rows if not _curated(t)]
        ranked = (curated + learned)[:max(limit, 8)]
        # G31 LIVE APPLICABILITY PROBE: one cheap request confirms each survivor can actually fire here;
        # drop only those that probe as a definite wall (False); keep True/None (never over-filter).
        if env is not None:
            kept = [t for t in ranked if _applicability_probe(t, env) is not False]
            ranked = kept or ranked          # if the probe killed everything (mirror down), fall back
        return ranked[:limit]
    except Exception:
        return []
CODER_EVENTS = os.path.join(HERE, "coder_events.jsonl")   # sub-leg coder workings, exposed to DS-orchestrator


def _log_coder_event(rec):
    """Expose every coder attempt to the orchestrator: which model wrote what, was the code VALID, did it
    actually EXECUTE (vs a dead-try), and the verdict. Append-only, never raises."""
    try:
        line = (json.dumps({"ts": time.time(), **rec}) + "\n").encode("utf-8")
        fd = os.open(CODER_EVENTS, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line)          # single O_APPEND write -> atomic per record, no interleave across
        finally:                        # concurrent campaigns (Pass 2 #10)
            os.close(fd)
    except Exception:
        pass


# A DEAD-TRY = the probe never actually executed against the target (harness/auth/format/reachability
# failure), as opposed to a real refutation. Dead-tries must be NUDGED + re-tried, not counted as a
# refuted hypothesis (the G18 class: an invalid invocation silently 'failed' the whole novel idea).
_DEAD_PATTERNS = [
    ("bad_invocation", r"usage: |unrecognized arguments|invalid choice"),
    ("auth_failed",    r"login as role .* failed|\[abort\].*login|401|not logged in|unauthor"),
    ("not_parsed",     r"parsed 0 suggestion|nothing to test|no runnable"),
    ("no_code",        r"bench produced no code|\[raw reasoning"),
    ("unreachable",    r"max retries exceeded|connection refused|could not connect|HTTP 000|failed to establish"),
    ("code_error",     r"traceback \(most recent call last\)|syntaxerror|indentationerror|nameerror|modulenotfound"),
]


def _dead_try_reason(out):
    """Return (reason, hint) if the run never really executed the probe, else (None, None)."""
    low = (out or "").lower()
    import re as _re
    for reason, pat in _DEAD_PATTERNS:
        if _re.search(pat, low):
            hint = {"bad_invocation": "the harness rejected the run args; emit a clean TARGET/CODE/ORACLE probe only",
                    "auth_failed": "the probe must use the AUTHENTICATED session (owner/finance); do not log in yourself",
                    "not_parsed": "emit EXACTLY one runnable TARGET/CODE/ORACLE block, nothing else",
                    "no_code": "you returned reasoning, not code -- output ONLY a runnable probe (TARGET/CODE/ORACLE)",
                    "unreachable": "the target was unreachable (infra) -- retry after health is restored",
                    "code_error": "your code raised before testing anything; fix the error and re-emit"}.get(reason, "")
            return reason, hint
    return None, None


# G22: GRADED progress signal. The oracle verdict is binary (verified or not), which leaves refinement
# blind -- it cannot tell a probe that is CLOSING IN (authenticated, reached the sink, provoked a server
# error) from one that is going nowhere (404s). This scores how far a run GOT on a 0-4 ladder from the
# harness output, so the refine loop can (a) feed the coder concrete progress and (b) pivot early when
# successive refinements stop advancing (convergence guard) instead of burning the whole refine budget.
# A 200 that is the SPA CATCH-ALL SHELL (an unmatched route falling through to index.html) or a bare 401
# auth-wall is a WALL, not progress -- counting it as "reached_surface" is the SPA-200 false positive that
# made invented/nonexistent endpoints look like near-misses. Detect the shell so it scores ZERO.
_SPA_WALL = r"<!doctype html|<div id=[\"']?root|text/html|bytes=(7[5-9]\d|8[0-4]\d)\b"


def _progress_score(out):
    """Return (score 0-4, [markers]) -- how far a NON-verified run got, for steering + convergence. A real
    handler must have responded: an SPA-200 shell or a bare 401 does NOT count as reaching the surface."""
    low = (out or "").lower()
    import re as _re
    spa = bool(_re.search(_SPA_WALL, low))                       # SPA catch-all shell -> a wall
    hit = []
    if _re.search(r"login .*ok|authenticated|session established|\btoken\b|set-cookie", low):
        hit.append("authenticated")
    # a REAL handler status: 4xx/5xx handler codes always count; a 2xx counts only if NOT the SPA shell
    if _re.search(r"\b(201|202|204|400|403|409|413|415|422|429|500|501|503)\b", low) or \
       (_re.search(r"\b200\b", low) and not spa):
        hit.append("reached_surface")
    if _re.search(r"\b500\b|internal server error|traceback|stack trace|exception", low):
        hit.append("server_effect")
    if _re.search(r"distinguishing|invariant|leaked|over-?read|idor|differs|mismatch", low):
        hit.append("partial_oracle")
    return len(hit), hit


def _code_syntax_ok(suggestion_text):
    """Best-effort: extract the CODE block and, if it's python, verify it COMPILES before we run it (a
    syntax-invalid probe is a dead-try, not a real test). Non-python probes pass through."""
    import re as _re
    m = _re.search(r"CODE\s*\n(.+?)(?:\nORACLE|\Z)", suggestion_text or "", _re.S | _re.I)
    code = (m.group(1) if m else "").strip().strip("`")
    if not code or not any(t in code for t in ("import ", "def ", "requests.", "print(", "=")):
        return True   # curl/prose probe -- not our syntax gate
    try:
        compile(code, "<probe>", "exec")
        return True
    except SyntaxError:
        return False
    except Exception:
        return True

REASONER = "ds"                 # strong reasoner drives proposal/decision (deepseek-v4-pro, direct)
# roster is env-tunable. Default set by the G36-G38 bake-offs (Q/4 + speed + $/run, sol excluded): the
# strong, cheap, non-reasoning-floor coders lead -- ds (fastest, thinking-disabled), qwen2.5-coder & llama-
# 3.3-70b (both Q=4/4, fast, ~$0.14/run), then claude/sonnet (Q=4/4). All fine at the 1600-tok write budget
# (no reasoning floor); kimi/r1/qwq are reasoning models that need a bigger budget and are slower, so they
# are NOT in the default writer roster (kimi 88s). AEGIS_BENCH_WRITERS overrides.
# Order = rotation preference (index 0 is the first-attempt writer). Graded bake-off: llama-3.3-70b was the
# ONLY clean 4/4 across easy->very_hard (fast+cheap) -> LEAD writer; ds is the fast fallback (7-8s, 4/4
# except very_hard); then qwen and claude/sonnet. (Q is a structural-quality proxy, not a verified win-rate.)
BENCH_WRITERS = [w.strip() for w in os.environ.get("AEGIS_BENCH_WRITERS",
                 "llama-3.3-70b,ds,qwen2.5-coder-32b,claude").split(",") if w.strip()]
# G19: kimi-k2.7-code (a reasoning coder) was dropped -- it leaks raw chain-of-thought instead of a probe,
# and the old weak "'CODE' in out" acceptance let the CoT (which contains the word CODE) through as "code".
DIRECTIONS = ("scaffold", "code")   # the reach axis (reach.py): stack/deps-only vs stack WITH app code
DEFAULT_BUDGET = 35                 # ~budget split across BOTH directions; failed novel approaches retried
# G21 (board-unanimous): DEPTH beats breadth. A hypothesis gets up to REFINE_CAP executions, and a
# clean-but-unconfirmed probe REFINES (carrying the working setup forward) instead of pivoting -- so a
# multi-step exploit (COPY FROM STDIN, CREATE EXTENSION privesc, pg_largeobject) can reach its
# setup->trigger->verify chain. Tunable; the old behaviour was 1 refine, only on an execution error.
REFINE_CAP = max(2, int(os.environ.get("AEGIS_CODE_REFINE_CAP", "5")))


# ---------------- hypothesis fingerprint (reuse iterative_hunt's normalization) ----------------
def _norm(move):
    try:
        import iterative_hunt as IH
        return (IH._norm_surface(move), IH._norm_tech(move))
    except Exception:
        s = str(move.get("surface") or move.get("target") or "").lower().split("?")[0]
        return (s, str(move.get("vuln_class") or move.get("mechanism") or "").lower())


def fingerprint(h):
    """hypothesis IDENTITY = (angle, norm-surface, vuln-class, mechanism, oracle-type). Value-only tweaks
    collide -> not a new hypothesis (the board's multi-axis distinctness, minus the payload)."""
    surf, tech = _norm(h)
    return "|".join([str(h.get("angle", "")).lower(), surf,
                     str(h.get("vuln_class", "")).lower(), str(h.get("mechanism", "")).lower(),
                     str(h.get("oracle_type", "")).lower()])


# ---------------- ledger ----------------
def connect(db=LEDGER):
    c = sqlite3.connect(db, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""CREATE TABLE IF NOT EXISTS hyps(
        fp TEXT PRIMARY KEY, angle TEXT, surface TEXT, vuln_class TEXT, mechanism TEXT, oracle_type TEXT,
        status TEXT DEFAULT 'proposed', attempts INTEGER DEFAULT 0, code TEXT, oracle_result TEXT,
        error_trace TEXT, novelty REAL DEFAULT 1.0, parent TEXT, rationale TEXT, updated REAL)""")
    c.commit()
    return c


def _tried(con):
    return {r[0] for r in con.execute("SELECT fp FROM hyps WHERE status IN ('win','dead','tried')")}


# G45: turn a rejected hypothesis's raw oracle_result/error into a SHORT, actionable reason so the proposer
# learns WHY a line failed (not just that a fingerprint is taken) and can go ORTHOGONAL. Board (gpt-oss
# dissent, ds-fullcov): fingerprint-dedup alone makes the reasoner random-walk; the rejection REASON is the
# signal that steers it to a different vuln-class/surface/mechanism.
def _reject_reason(oracle_result, error):
    blob = f"{oracle_result or ''} {error or ''}".lower()
    if "meta-demoted" in blob or "meta-oracle refuted" in blob:
        return "META-REFUTED (oracle passed but exploit did not CAUSE the breach -- causation, not a new probe value)"
    if "no ground-truth oracle" in blob or "no-oracle" in blob:
        return "NO ORACLE (nothing could verify this class here -- needs a different, verifiable oracle/class)"
    if "no_convergence" in blob or "progress stuck" in blob:
        return "NO CONVERGENCE (refined repeatedly, never reached confirmation -- the line does not lead to a breach)"
    if "spa" in blob or "404" in blob or "no distinguishing" in blob:
        return "NO SIGNAL (404 / SPA-shell / indistinguishable -- surface likely wrong or non-existent)"
    if "401" in blob or "403" in blob or "login" in blob or "not logged in" in blob:
        return "ACCESS DENIED at this surface (auth/role wall -- needs an access move first, or a different surface)"
    return ("rejected: " + " ".join((oracle_result or error or "").split())[:90]) if (oracle_result or error) else "rejected"


def _rejection_digest(con, limit=12):
    """Recent REJECTED hypotheses this run + WHY, plus an over-exploration count per (vuln_class), so the
    proposer avoids re-probing the same (class,surface) with a value tweak and diversifies to new classes.
    Returns (lines[list[str]], overworked[list[str]])."""
    rows = con.execute("SELECT vuln_class,surface,mechanism,oracle_result,error_trace FROM hyps "
                       "WHERE status IN ('tried','dead') ORDER BY updated DESC LIMIT ?", (limit,)).fetchall()
    lines, counts = [], {}
    for vc, surf, mech, ores, err in rows:
        lines.append(f"- {vc or '?'}@{surf or '?'} via {mech or '?'} -> {_reject_reason(ores, err)}")
        counts[(vc or '?')] = counts.get((vc or '?'), 0) + 1
    overworked = [f"{k} (x{v})" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]) if v >= 3]
    return lines, overworked


def _record(con, h, status, code=None, oracle_result=None, error=None):
    fp = fingerprint(h)
    con.execute("""INSERT INTO hyps(fp,angle,surface,vuln_class,mechanism,oracle_type,status,attempts,code,
        oracle_result,error_trace,novelty,parent,rationale,updated) VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,?)
        ON CONFLICT(fp) DO UPDATE SET status=excluded.status, attempts=hyps.attempts+1, code=excluded.code,
        oracle_result=excluded.oracle_result, error_trace=excluded.error_trace, updated=excluded.updated""",
        (fp, h.get("angle"), h.get("surface"), h.get("vuln_class"), h.get("mechanism"), h.get("oracle_type"),
         status, code, oracle_result, error, h.get("novelty", 1.0), h.get("parent"), h.get("rationale"), time.time()))
    con.commit()
    return fp


def stats(con):
    return dict(con.execute("SELECT status,count(*) FROM hyps GROUP BY status").fetchall())


# ---------------- the three model-backed steps (real, with dry fallbacks) ----------------
def _ds_json(prompt, max_tokens=1200, dry=False):
    if dry:
        return None
    import board_ask
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
    key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("AEGIS_LLM_API_KEY")
    try:
        out = board_ask._post(ep + "/chat/completions", key, "deepseek-v4-pro", board_ask.PANEL_SYS,
                              prompt, max_tokens, extra={"thinking": {"type": "disabled"}})
    except Exception:
        return None
    import re
    m = re.search(r"\{.*\}", out or "", re.S)
    try:
        return json.loads(m.group(0)) if m else None
    except Exception:
        return None


def propose(con, objective, target_ctx, tried, direction="code", dry=False):
    """REASONER proposes the next falsifiable code hypothesis in the given reach DIRECTION (scaffold = stack/
    installed-modules/DB only; code = the stack WITH the app source), biased to NOVELTY (avoid tried
    fingerprints, prefer under-explored surfaces). Returns a hypothesis dict (tagged with direction) or None."""
    if dry:
        import random
        pool = {"scaffold": ["dep-cve-chain", "module-misconfig", "db-tier", "supply-chain"],
                "code": ["idor", "toctou", "deserialization", "ssrf-chain", "auth-replay", "logic-race"]}[direction]
        a = random.choice(pool)
        return {"angle": a, "surface": f"/{direction}/{a}/{random.randint(1,9)}", "vuln_class": a,
                "mechanism": f"custom-{a}-probe", "oracle_type": "distinguishing-2xx", "direction": direction,
                "rationale": "dry", "code_task": f"probe {a} in the {direction} layer", "novelty": round(random.random(), 2)}
    layer = ("the STACK/dependencies/installed-modules/DB tier ONLY (no app code)" if direction == "scaffold"
             else "the stack WITH the application source code (app logic)")
    # G22: CLOSE THE LEARNING LOOP. writeback() records wins (reusable techniques) and instructive
    # dead-ends (with WHY they failed) to learned_techniques.json, but propose() previously read only the
    # fingerprint blocklist. Feed the learned CONTENT back so the reasoner builds ON confirmed mechanisms
    # and steers AWAY from known dead-ends by their reason -- not just avoiding exact repeats.
    # G25: feed the REAL API surface (if the caller discovered it into target_ctx['endpoints']) so the
    # reasoner probes endpoints that EXIST instead of inventing ones that fall through to the SPA-200 wall.
    # Generic: no endpoints hardcoded here -- the caller supplies the discovered surface.
    surface_ctx = ""
    _eps = target_ctx.get("endpoints") if isinstance(target_ctx, dict) else None
    if _eps:
        surface_ctx = ("REAL endpoints that EXIST on this target (probe THESE; do NOT invent endpoints -- an "
                       f"unknown path returns the SPA shell, which proves nothing): {list(_eps)[:60]}\n")
    # G29 ACCESS-FIRST: applicable KNOWN techniques (public DB + MITRE + Kali RAG) so the driver tries a
    # known bypass/access route -- or a COMBINATION -- before inventing a novel probe of the wall.
    known_ctx = ""; known = []; chains = []; _env = {}
    try:
        _env = _env_fingerprint(target_ctx)
        known = _known_techniques(f"{objective} {direction} " + str(target_ctx.get("stack", "")), env=_env)
        if known:
            known_ctx = ("KNOWN TECHNIQUES applicable here (public technique DB + MITRE + Kali RAG; already "
                         "filtered to what CAN fire in this environment). ACCESS-FIRST: before inventing a novel "
                         "probe, PREFER one of these -- or a COMBINATION of them -- that could get IN / achieve "
                         "the objective; go fully novel ONLY if none apply:\n"
                         + "\n".join(f"- {t['id']} [{t['class']}]: {t['desc']} | how: {t['how']}"
                                     + (f" | ORACLE(prove this): {t['oracle']}" if t.get('oracle') else "")
                                     + (f" | tools: {t['tools']}" if t.get('tools') else "") for t in known) + "\n")
            chains = _chain_hints(known, _env)
            if chains:
                known_ctx += ("APPLICABLE CHAINS (an access move that grants reach, then an exploit move on the "
                              "SAME real endpoint -- prefer chaining these):\n" + "\n".join(f"- {c}" for c in chains) + "\n")
    except Exception:
        pass
    # G32: TWO-AGENT technique CHOICE -- Claude (CLI) is a CONSULTANT on which known technique/chain to pick;
    # DS remains the FINAL direction chooser (it makes the actual proposal below, weighing Claude's advice).
    consult_ctx = ""
    if known and os.environ.get("AEGIS_TECH_CONSULT_CLAUDE", "1") != "0":
        try:
            advice = _claude_advise(objective, direction, known, chains, _env)
            if advice:
                consult_ctx = ("CONSULTANT (Claude) on the technique CHOICE (advisory -- YOU, DS, make the final "
                               f"call): {advice.strip()[:700]}\n")
        except Exception:
            pass
    # G45: THIS-RUN rejection feedback -- WHY recent hypotheses failed + which classes are over-worked, so the
    # reasoner proposes something ORTHOGONAL instead of random-walking near a rejected line (board: gpt-oss).
    reject_ctx = ""
    try:
        _rlines, _over = _rejection_digest(con)
        if _rlines:
            reject_ctx = ("REJECTED THIS RUN (and WHY) -- do NOT re-probe the same (class,surface) with a value "
                          "tweak; propose something ORTHOGONAL along at least one axis (different vuln_class OR "
                          "surface OR mechanism), and ADDRESS the reason (e.g. META-REFUTED -> make the exploit "
                          "actually CAUSE the state; NO ORACLE -> pick a class with a verifiable oracle):\n"
                          + "\n".join(_rlines) + "\n")
            if _over:
                reject_ctx += (f"OVER-ATTEMPTED classes (pick a DIFFERENT vuln_class than these): {_over}\n")
    except Exception:
        pass
    learned_ctx = ""
    try:
        _lt = json.load(open(LEARNED, encoding="utf-8")).get("techniques", []) if os.path.exists(LEARNED) else []
        _wins = [f"{t.get('vuln_class')}@{t.get('surface')} ({t.get('mechanism')})"
                 for t in _lt if t.get("status") == "verified"][-8:]
        _dead = [f"{t.get('angle')}/{t.get('vuln_class')}: {str(t.get('failure'))[:80]}"
                 for t in _lt if t.get("status") == "dead-end"][-8:]
        if _wins:
            learned_ctx += f"CONFIRMED techniques here (build ON these / chain from them): {_wins}\n"
        if _dead:
            learned_ctx += f"KNOWN DEAD-ENDS (do NOT repeat this line of attack): {_dead}\n"
    except Exception:
        pass
    prompt = (
        "You are the CODE DRIVER and the FINAL DIRECTION CHOOSER for an authorized, contained security mirror. "
        f"Propose the NEXT single falsifiable CUSTOM-CODE hypothesis probing {layer}. ACCESS-FIRST ORDER: if a "
        "KNOWN technique (or a COMBINATION of them) listed below gets you IN / achieves the objective, use/adapt "
        "THAT first; invent a genuinely NOVEL approach only when the known ones don't apply here. A Claude "
        "CONSULTANT may advise on the technique choice below -- WEIGH it, but the decision is YOURS. Either way "
        "it must be runnable and falsifiable. Bias to UNDER-EXPLORED surfaces/vuln-classes; do NOT repeat any "
        "already-tried fingerprint.\n\n"
        f"OBJECTIVE: {objective}\nREACH DIRECTION: {direction}\nTARGET CONTEXT: {json.dumps(target_ctx)[:1100]}\n"
        + (known_ctx and (known_ctx + "\n")) + (consult_ctx and (consult_ctx + "\n"))
        + (surface_ctx and (surface_ctx + "\n"))
        + (reject_ctx and (reject_ctx + "\n"))
        + (learned_ctx and (learned_ctx + "\n")) +
        f"ALREADY-TRIED fingerprints: {sorted(tried)[:40]}\n\n"
        'Reply STRICT JSON only: {"angle","surface","vuln_class","mechanism","oracle_type",'
        f'"direction":"{direction}","rationale","code_task","novelty"(0-1, higher=more distant from tried)}}')
    h = _ds_json(prompt, dry=dry)
    if h:
        h.setdefault("direction", direction)
    return h


def write_code(h, prior_code=None, error=None, dry=False, prefer=None, state_text="", schema_text=""):
    """CODE BENCH writes bespoke code for the hypothesis. On a REFINE, the prior code + ERROR TRACE are fed
    back so the bench fixes it (closes the no-failure-feedback gap the board flagged).

    G23 MODEL ROTATION: `prefer` puts one writer first so a STALLED hypothesis (same idea, no progress) is
    handed to a DIFFERENT model instead of letting one model spin on a probe it can't crack. Falls back
    through the rest of the bench as before."""
    if dry:
        return ("TARGET %s\nCODE\n# dry probe for %s\nprint('probe')\nORACLE distinguishing 2xx\n"
                % (h.get("surface"), h.get("mechanism")))
    import code_suggester
    task = (f"Write a SELF-CONTAINED, NON-DESTRUCTIVE probe (TARGET/CODE/ORACLE blocks) for this hypothesis "
            f"on the CONTAINED mirror.\nHYPOTHESIS: {json.dumps(h)}\n"
            # G34 ORACLE SEMANTICS: a 2xx only means the request was ACCEPTED -- it is NOT proof of a flaw.
            # The ORACLE must prove the INVARIANT IS VIOLATED. Prefer a SQL SELECT that returns rows ONLY when
            # the flaw holds (it is authoritative), or a before/after state read; a bare status is rejected for
            # a money/logic/state flaw. Postgres, Prisma PascalCase tables/quoted columns.
            "\nORACLE RULES: prove the INVARIANT is BROKEN, not that the request returned 2xx. Prefer a SQL "
            "SELECT that returns rows ONLY when the flaw holds -- e.g. money over-credit:\n"
            '  SELECT "invoiceId", SUM("total") s FROM "CreditNote" GROUP BY "invoiceId" '
            'HAVING SUM("total") > (SELECT "total" FROM "Invoice" i WHERE i.id="invoiceId");\n'
            "(returns rows iff some invoice is over-credited). For idempotency/replay: SELECT the duplicate "
            "count > 1. For IDOR/authz: the cross-role/other-tenant row is returned where it should be 403/404. "
            "A 2xx alone is NOT a pass.\n")
    if prior_code and error:
        task += (f"\nYOUR PREVIOUS attempt FAILED. Fix it -- do not repeat the same mistake.\nPREVIOUS CODE:\n"
                 f"{prior_code[:1500]}\nERROR/ORACLE RESULT:\n{error[:800]}\n")
    if schema_text:                      # G27: the endpoint's real field contract (build valid, then mutate)
        task += "\n" + schema_text
    if state_text:                       # G24: carry the last good session/artifacts forward (re-validate first)
        task += "\n" + state_text
    # G35 REPLAY-ACCUMULATION nudge: the app enforces per-create money bounds, so a single (even over-sized)
    # create won't breach the invariant -- the CONFIRMED mechanism (stateful.replay_mutation) is a
    # NON-IDEMPOTENT create REPLAYED N times so credits/quantities accumulate past the bound. Nudge the coder
    # to that pattern for money/idempotency/stateful hypotheses (not every probe).
    _hblob = f"{h.get('angle','')} {h.get('vuln_class','')} {h.get('mechanism','')} {h.get('code_task','')}".lower()
    if any(k in _hblob for k in ("replay", "idempot", "money", "credit", "over-credit", "double", "stateful", "bound", "invariant")):
        task += ("\nREPLAY-ACCUMULATION (the confirmed mechanism for this class): in ONE probe, POST a VALID "
                 "create once, capture the response, then REPLAY the IDENTICAL create N times (N=4-6) against the "
                 "same parent (e.g. same invoiceId). The flaw is that replays are NOT deduped/idempotent, so the "
                 "credits/amounts ACCUMULATE past the bound. Do NOT rely on a single over-sized create -- the app "
                 "enforces per-create bounds. ORACLE: after the replays, a SQL SELECT proving sum(credits) > "
                 "invoice.total for that invoice (rows iff breached) OR duplicate count>1; a 2xx alone is not proof.\n")
    order = ([prefer] + [m for m in BENCH_WRITERS if m != prefer]) if prefer in BENCH_WRITERS else BENCH_WRITERS
    for m in order:
        try:
            out = _claude_write(task) if m == "claude" else code_suggester.suggest(m, task, max_tokens=1600, temperature=0.4)
            if _looks_like_probe(out):
                return out
        except Exception:
            continue
    return None


def _claude_cli(system, user, timeout=90):
    """G37: the LEAN coding-optimized Claude CLI invocation for bench/consult work. The default `claude -p`
    spawns the FULL agent (heavy model + MCP servers + project settings/CLAUDE.md/skills + a full turn),
    which is why it was far slower than a single ds/qwen API call. This strips all of that: a FAST model
    (Haiku), NO MCP servers, NO project/local settings or skills (--restricted + strict-mcp), no tools,
    one turn. Model tunable via AEGIS_CLAUDE_BENCH_MODEL. Returns stdout or None."""
    import shutil, tempfile
    exe = shutil.which(os.environ.get("ASKBOARD_CLAUDE_BIN") or "claude")
    if not exe:
        return None
    # G38: benchmarked haiku vs sonnet (easy + hard TOCTOU tasks). On this claude -p deployment SONNET is
    # both FASTER (clean warmed median 3.9s vs haiku 7.4s) and STRONGER on the hard task (grounded the
    # exploit with a real id + more complete probe where haiku missed it). Easy task = parity. So sonnet is
    # the default; haiku is the fast/cheap fallback. Tunable via AEGIS_CLAUDE_BENCH_MODEL.
    model = os.environ.get("AEGIS_CLAUDE_BENCH_MODEL", "claude-sonnet-5")
    fb = os.environ.get("AEGIS_CLAUDE_BENCH_FALLBACK", "claude-haiku-4-5")
    argv = [exe, "-p", "--model", model, "--fallback-model", fb, "--max-turns", "1",
            "--allowed-tools", "", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--restricted",
            "--append-system-prompt", system]
    try:
        with tempfile.TemporaryDirectory(prefix="claude-bench-") as cwd:
            p = subprocess.run(argv, input=user, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout, cwd=cwd)
        return p.stdout if p.returncode == 0 else None
    except Exception:
        return None


def _claude_advise(objective, direction, known, chains, env, timeout=90):
    """G32: Claude CLI as a technique-CHOICE CONSULTANT (claude -p). Given the applicable known techniques +
    chains + environment, recommend which ONE technique or chain to try next and how to combine/adapt it --
    terse advice only. DS remains the FINAL chooser and may override. Returns short text or None."""
    kt = "\n".join(f"- {t['id']} [{t.get('class')}]: {t.get('desc')}" for t in known)
    ch = "\n".join(f"- {c}" for c in (chains or [])) or "(none)"
    sysp = ("You are a technique-selection CONSULTANT for an authorized, contained security mirror. Recommend "
            "the SINGLE best next move from the APPLICABLE known techniques/chains for this environment -- which "
            "to try, why it fits THIS target, and how to combine/adapt it. 3-4 sentences max, no code, no "
            "preamble. The DS reasoner makes the final call.")
    usr = (f"OBJECTIVE: {objective}\nREACH DIRECTION: {direction}\n"
           f"ENV: stack={env.get('stack')} roles={env.get('roles')} sinks={env.get('sinks')} "
           f"endpoints={(env.get('endpoints') or [])[:20]}\n"
           f"APPLICABLE KNOWN TECHNIQUES:\n{kt}\nAPPLICABLE CHAINS:\n{ch}\n\nWhich do you recommend, and why here?")
    out = _claude_cli(sysp, usr, timeout=timeout)   # G37: lean fast-model invocation
    return out.strip() if out else None


def _claude_write(task, timeout=120):
    """The Claude CLI as a first-class BENCH WRITER. Emits a runnable TARGET/CODE/ORACLE probe via the LEAN
    fast-model invocation (G37); opt-in via AEGIS_BENCH_WRITERS."""
    sysp = ("You are a CODE WRITER on a security bench for an AUTHORIZED, CONTAINED mirror. Output ONLY a "
            "runnable probe as TARGET / CODE / ORACLE blocks -- no prose, no markdown fences. CODE is Python "
            "using `requests` (POST/GET/PATCH as needed, verify=False). NON-DESTRUCTIVE: create/read for "
            "proof, NEVER delete real data. Do NOT log in yourself -- the harness supplies the authenticated "
            "session (a placeholder Authorization header is fine). If a REAL RECORD SHAPE is given, build a "
            "WELL-FORMED payload from it, then introduce ONLY the exploit mutation. Make the ORACLE a concrete, "
            "checkable condition (status and/or body-contains and/or a SQL SELECT).")
    return _claude_cli(sysp, task, timeout=timeout)


def _looks_like_probe(out):
    """G19: accept only a REAL runnable TARGET/CODE/ORACLE probe -- reject a reasoning-model CoT dump
    (which merely contains the word 'CODE') so a leaked chain-of-thought is never run as 'code'."""
    if not out:
        return False
    if out.lstrip().lower().startswith("[raw reasoning"):
        return False
    low = out.lower()
    return ("target" in low and "oracle" in low
            and ("```" in out or "curl" in low or "requests." in low or "import " in low
                 or "http" in low))


_VALID_ROLES = ("owner", "dispatcher", "finance", "warehouse", "technician")


# G44: META-ORACLE CONFIRMATION GATE. The board (7/8, ds-fullcov 2026-09-16) found the standard
# stateful.invariant oracle produces ARTIFACTS: a "PASS" on a SQL SELECT that returns rows never proves
# the rows are NEW or exploit-CAUSED -- it can read loose seed state or an already-broken invariant. The
# meta-oracle re-verifies exploit-causation: same SQL EMPTY on a clean baseline -> run the FULL probe code
# -> SQL must have ROWS after. This gate applies ONLY to wins whose probe carries an SQL invariant oracle
# (the exact artifact class); HTTP-observed wins (rate-limit, distinguishing-2xx) carry no SELECT -> the
# meta-oracle returns no_sql -> we leave them UNTOUCHED. Kill-switch: AEGIS_META_ORACLE=0.
_META_ON = os.environ.get("AEGIS_META_ORACLE", "1") != "0"


def _meta_confirm(suggestion_text, role):
    """For a STANDARD-oracle win, independently confirm it is exploit-caused via the meta-oracle.
    Returns (keep_verified, marker, feedback):
      keep_verified=True  -> the win stands (META_WIN, or not-applicable: no SQL / meta unavailable).
      keep_verified=False -> DEMOTE: the meta-oracle refuted causation (loose oracle or no real breach);
                             `feedback` is fed back to the bench writer so the next refine fixes causation."""
    if not (_META_ON and MO is not None) or not MO.extract_sql(suggestion_text or ""):
        return True, "", None            # gate off, or no SQL invariant -> not this artifact class, keep as-is
    try:
        v = MO.verify(suggestion_text, role=role if role in _VALID_ROLES else "owner")
    except Exception as e:
        return True, f"META-INCONCLUSIVE(verify-err: {str(e)[:60]})", None
    verdict = v.get("verdict")
    if verdict == "META_WIN":
        return True, f"META-CONFIRMED (baseline empty -> exploit produced rows: {str(v.get('after'))[:70]})", None
    if verdict == "invalid_oracle":
        reason = str(v.get("reason", ""))
        if "db error" in reason or "broke after exec" in reason:   # DB unreachable/SQL faulted -> can't judge, don't demote
            return True, f"META-INCONCLUSIVE({reason[:70]})", None
        fb = ("[META-ORACLE REFUTED THE WIN] Your ORACLE SQL returns rows on a CLEAN baseline (loose/"
              "permissive invariant, or it was already broken) -- passing it does NOT prove YOUR exploit "
              "caused anything. Rewrite the SQL to be STRICT so it returns rows ONLY for state your exploit "
              "newly creates, and make the exploit ACTUALLY cause that state.")
        return False, f"META-DEMOTED(invalid_oracle: {reason[:60]})", fb
    if verdict == "no_breach":
        fb = ("[META-ORACLE REFUTED THE WIN] On a clean baseline your full code RAN but the invariant SQL is "
              "still EMPTY afterwards -- the exploit did NOT actually cause the breach; the standard oracle "
              "passed only on pre-existing state. Make the exploit ACTUALLY produce the over-limit/invariant-"
              "violating state (real accumulation/concurrency), then re-verify.")
        return False, "META-DEMOTED(no_breach)", fb
    # code_error / no_code: the meta-runner couldn't exec the full code (its own auth/monkeypatch path) even
    # though the harness ran it -- INCONCLUSIVE, do not demote a standard win on a meta-runner quirk.
    return True, f"META-INCONCLUSIVE({verdict})", None


def run_code(suggestion_text, role="owner", dry=False, state=None):
    """RUN the bench code oracle-gated + non-destructive via the test_suggestions harness on the mirror.
    Returns (verified, oracle_result, error_trace, dead). If `state` (a ProbeState) is given, any `STATE
    {json}` block the probe emitted is merged into it (G24 state-carry) from the FULL output before trunc."""
    # G18: test_suggestions --role has choices {owner,dispatcher,finance,warehouse,technician}. Passing an
    # out-of-set role (the old default "user") makes argparse reject the whole call with a usage error, so
    # the probe NEVER RUNS -> every novel-code hypothesis silently "failed". Map to a valid role (default owner).
    role = role if role in _VALID_ROLES else "owner"
    if dry:
        import random
        ok = random.random() < 0.35
        return (ok, "distinguishing 2xx" if ok else "404 / no distinguishing signal",
                "" if ok else "assertion: expected distinguishing 2xx, got 404", None)
    md = os.path.join(HERE, "_driver_suggestion.md")
    open(md, "w", encoding="utf-8").write(suggestion_text)
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "test_suggestions.py"),
                            "--file", md, "--source", "code_driver", "--execute", "--role", role],
                           capture_output=True, text=True, timeout=180,
                           env=dict(os.environ, PYTHONUTF8="1"))
        out = (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return (False, "", "run error: " + str(e)[:200], {"reason": "run_error", "hint": "the harness failed to run the probe"})
    # G36 (critical): the harness prints its verdict as "    PASS -- ..." and a summary "pass=N" -- NOT
    # "VERIFIED"/"oracle: PASS". The old match missed EVERY real harness pass, silently dropping genuine
    # wins across all live runs. Detect the harness's actual PASS verdict (a PASS verdict line, or pass>=1).
    import re as _re36
    verified = ("VERIFIED" in out or "oracle: PASS" in out or "confirmed" in out.lower()
                or bool(_re36.search(r'(?m)^\s*PASS\s+--', out))
                or bool(_re36.search(r'\bpass=([1-9]\d*)\b', out)))
    # G44: gate a STANDARD-oracle win through the meta-oracle -- confirm it is exploit-CAUSED, not an
    # artifact of a loose SQL oracle reading pre-existing state. Only touches SQL-invariant wins.
    if verified and not dry:
        keep, marker, feedback = _meta_confirm(suggestion_text, role)
        if marker:
            out += f"\n[meta-oracle] {marker}"
        if not keep:
            # DEMOTE: the standard oracle passed but causation is unproven -> treat as clean-but-unconfirmed
            # so the refine loop feeds the meta refutation back to the writer (fix causation, don't re-polish).
            return (False, (out[-360:] + "\n" + marker)[-400:], feedback or marker, None)
    reason, hint = (None, None) if verified else _dead_try_reason(out)
    dead = {"reason": reason, "hint": hint} if reason else None
    if state is not None and not dead:          # G24: capture what the probe established, from FULL output
        try:
            state.merge_output(out, code=suggestion_text)
        except Exception:
            pass
    return (verified, out[-400:], "" if verified else out[-600:], dead)


def decide(h, verified, oracle_result, error, attempts, dry=False):
    """DECIDE the next action from the running RESULT: refine (same hypothesis, DEEPEN) | pivot (same
    class, new surface) | new (fresh hypothesis).

    G21 (board-unanimous, depth-over-breadth): a probe that RAN but did not confirm is precisely the
    state where the NEXT setup/trigger step is needed -- so it REFINES (carrying the working setup
    forward) until REFINE_CAP, instead of the old logic that refined once and only on an error. Pivot
    only on a structurally unrecoverable RUN ERROR (bad infra/transport, not the idea's fault) or once
    the refine budget for this hypothesis is exhausted."""
    if verified:
        return "win"
    if error and "run error" in error:          # infra/transport fault -> the idea can't be judged here
        return "pivot" if attempts < 2 else "new"
    if attempts < REFINE_CAP:                    # clean-but-unconfirmed OR fixable error -> DEEPEN
        return "refine"
    return "new"                                 # depth exhausted -> fresh hypothesis


# G48: DEPTH -- from a VERIFIED win, seed chained hypotheses that go DEEPER on the SAME surface (escalate the
# confirmed foothold) rather than only moving on to a new surface. Structural + cheap (no model call); the
# bench writer deepens each from the carried rationale. Tagged chained_from so provenance + dedup work.
def _chain_from_win(h, oracle_result=""):
    if os.environ.get("AEGIS_CHAIN_FROM_WIN", "1") == "0":
        return []
    base = {k: h.get(k) for k in ("surface", "role", "direction")}
    parent = fingerprint(h)
    surf = h.get("surface", "")
    escalations = [
        ("privesc-from-foothold", "privilege-escalation",
         f"CHAIN FROM CONFIRMED WIN on {surf}: you have a working authenticated foothold here. ESCALATE it -- "
         "reach data/actions of a HIGHER-privileged role from this same surface (over-read/over-write across the "
         "authz boundary), and prove it with a role-scoped oracle (a lower role obtaining a higher role's object)."),
        ("deeper-effect", h.get("vuln_class", "business-logic"),
         f"CHAIN FROM CONFIRMED WIN on {surf}: push the SAME primitive DEEPER -- a larger/compounding effect, an "
         "adjacent invariant on the same entity, or a state that persists (plant a proof marker), oracle-gated."),
        ("pivot-from-foothold", "lateral",
         f"CHAIN FROM CONFIRMED WIN on {surf}: use this foothold to REACH a NEW surface/host it grants access to "
         "(follow ids/links/tokens exposed here) and confirm a primitive there."),
        ("beacon-from-foothold", "beacon",
         f"CHAIN FROM CONFIRMED WIN on {surf}: BEACON (in-doctrine depth-of-proof, owner's own kit) -- plant a "
         "NON-DESTRUCTIVE proof marker (a benign/canary record or a written marker; NEVER delete anything) that "
         "persists, then run a READ-ONLY enumeration FROM this foothold to show what it can reach. ORACLE: the "
         "planted marker is retrievable afterwards AND/OR the enumeration returns data outside the starting scope."),
    ]
    out = []
    for angle, vclass, task in escalations:
        out.append({**base, "angle": angle, "vuln_class": vclass,
                    "mechanism": f"chain-{angle}", "oracle_type": "distinguishing-2xx",
                    "direction": h.get("direction", "code"), "chained_from": parent,
                    "intent": "beacon" if angle == "beacon-from-foothold" else "escalate",
                    "rationale": f"escalate confirmed foothold ({parent[:24]})", "code_task": task,
                    "novelty": 0.8})
    return out


# ---------------- writeback (wins AND instructive failures) ----------------
def writeback(h, verified, code, oracle_result, error):
    """record to the hypothesis ledger's durable knowledge: a WIN becomes a reusable technique (code +
    preconditions + oracle); an instructive FAILURE is stored so the dead-end isn't retried (P3 gap)."""
    try:
        learned = json.load(open(LEARNED, encoding="utf-8")) if os.path.exists(LEARNED) else {"techniques": []}
    except Exception:
        learned = {"techniques": []}
    entry = {"id": fingerprint(h), "angle": h.get("angle"), "vuln_class": h.get("vuln_class"),
             "mechanism": h.get("mechanism"), "surface": h.get("surface"),
             "status": "verified" if verified else "dead-end",
             "code": (code or "")[:2000], "oracle_result": oracle_result,
             "failure": None if verified else (error or "")[:600], "ts": time.time()}
    techs = [t for t in learned.get("techniques", []) if t.get("id") != entry["id"]]   # dedup by id
    techs.append(entry)
    learned["techniques"] = techs
    try:
        json.dump(learned, open(LEARNED, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    except Exception:
        pass


# ---------------- the drive loop ----------------
def drive(objective, target_ctx=None, budget=DEFAULT_BUDGET, dry=False, novelty_min=0.0):
    """Run the adaptive loop, splitting the budget across the TWO reach DIRECTIONS (scaffold / scaffold+code),
    breadth-first (least-used direction next, soft cap ~half each), retrying failed novel approaches, until
    the budget is spent or nothing new can be proposed."""
    con = connect()
    target_ctx = target_ctx or {}
    # G22: a small NOVELTY FLOOR (self-reported 0-1) so breadth stays genuine -- fingerprint-dedup blocks
    # exact repeats, this blocks near-duplicate low-novelty proposals. Env-tunable; 0 disables.
    try:
        novelty_min = max(novelty_min, float(os.environ.get("AEGIS_CODE_NOVELTY_MIN", "0.1")))
    except Exception:
        pass
    wins = {"scaffold": 0, "code": 0}
    used = {"scaffold": 0, "code": 0}
    chain_queue = []                             # G48: DEPTH -- chained hypotheses seeded from a verified win
    cap = budget // 2 + budget % 2               # soft per-direction cap; the other absorbs the remainder
    for step in range(1, budget + 1):
        tried = _tried(con)
        # G48 chain-from-win DEPTH: a verified win seeds a deeper probe on the SAME surface (escalate the
        # confirmed foothold before moving on). Prefer the chain queue over a fresh proposal -- that is "go
        # deeper" taking priority over "go wider", bounded so it can't starve breadth (skip if fp already tried).
        h = None
        while chain_queue and h is None:
            cand = chain_queue.pop(0)
            if fingerprint(cand) not in tried:
                h = cand; direction = h.get("direction", "code")
                print(f"  step {step} [{direction}]: CHAIN-FROM-WIN <- {h.get('chained_from','')[:24]}")
        if h is None:
            # breadth-first on the reach axis: least-used direction next; if it's capped, use the other
            direction = min(DIRECTIONS, key=lambda d: used[d])
            if used[direction] >= cap and used[other_dir(direction)] < budget:
                direction = other_dir(direction)
            h = propose(con, objective, target_ctx, tried, direction=direction, dry=dry)
        used[direction] += 1
        if not h:
            print(f"  step {step} [{direction}]: no hypothesis -> skip"); continue
        if fingerprint(h) in tried or h.get("novelty", 1.0) < novelty_min:
            print(f"  step {step} [{direction}]: stale/low-novelty -> skip"); continue
        prior_code = error = None; nudges = 0; best_prog = -1; stall = 0
        ev_common = {"step": step, "direction": direction,
                     "angle": h.get("angle"), "vuln_class": h.get("vuln_class")}
        # G24: per-hypothesis ProbeState carries session/artifacts/captured values across refine attempts
        # (board design A). Loaded from disk so a driver restart resumes; env fingerprint seeds replay.
        ps = PS.ProbeState.load(fingerprint(h))
        ps.hypothesis_id = fingerprint(h)
        ps.environment_fingerprint = {"mirror_id": target_ctx.get("base"), "stack": target_ctx.get("stack")}
        won = False
        # G27: learn the target endpoint's REAL field contract once per hypothesis (read-then-mutate) so the
        # bench builds a WELL-FORMED payload the handler accepts (2xx) instead of a 400 schema-reject. GET-only,
        # authenticated, cached; offline-safe (empty on any failure). Skip in dry mode.
        try:
            sch = "" if dry else SD.schema_text(h, role=h.get("role", "owner"))
        except Exception:
            sch = ""
        if sch:
            print(f"  step {step} [{direction}]: schema discovered for {SD.endpoint_of(h)}")
        for attempt in range(1, REFINE_CAP + 3):           # per-hypothesis loop: REFINE_CAP deepenings + nudge headroom
            # G23: rotate the bench writer by stall count -- a progressing line keeps its working model
            # (stall=0 -> first writer), a stuck line hands off to the next model instead of spinning.
            _prefer = BENCH_WRITERS[(stall + nudges) % len(BENCH_WRITERS)] if BENCH_WRITERS else None
            code = write_code(h, prior_code, error, dry=dry, prefer=_prefer,
                              state_text=ps.inject_text(), schema_text=sch)
            if not code:
                _log_coder_event({**ev_common, "code_valid": False, "executed": False,
                                  "status": "dead_try", "reason": "no_code"})
                _record(con, h, "dead", error="bench produced no code"); break
            # VALIDITY MONITOR: a non-compiling probe never tests anything -> dead-try, NUDGE (don't run it).
            if not dry and not _code_syntax_ok(code):
                nudges += 1
                _log_coder_event({**ev_common, "code_valid": False, "executed": False,
                                  "status": "dead_try", "reason": "code_error"})
                print(f"  step {step}.{attempt} [{direction}:{h.get('angle')}] -> DEAD-TRY(code_error) NUDGE")
                if nudges >= 2:
                    _record(con, h, "dead", code, "", "syntax invalid after nudges"); break
                prior_code, error = code, "your probe did NOT compile (SyntaxError); re-emit runnable code"; continue
            verified, oracle_result, err, dead = run_code(code, role=h.get("role", "owner"), dry=dry, state=ps)
            if dead:                                       # DEAD-TRY: never executed -> NUDGE, do NOT refute
                nudges += 1
                _log_coder_event({**ev_common, "model_role": h.get("role"), "code_valid": True, "executed": False,
                                  "status": "dead_try", "reason": dead["reason"], "detail": oracle_result[:120]})
                print(f"  step {step}.{attempt} [{direction}:{h.get('angle')}] -> DEAD-TRY({dead['reason']}) NUDGE "
                      f"({oracle_result[:40]})")
                if dead["reason"] == "unreachable" or nudges >= 3:   # infra fault or exhausted -> not the idea's fault
                    _record(con, h, "tried", code, oracle_result, err); break
                prior_code, error = code, f"[previous attempt did NOT run -- {dead['reason']}] {dead['hint']}"; continue
            act = decide(h, verified, oracle_result, err, attempt, dry=dry)
            _log_coder_event({**ev_common, "code_valid": True, "executed": True,
                              "status": "win" if verified else act, "oracle": oracle_result[:120]})
            print(f"  step {step}.{attempt} [{direction}:{h.get('angle')}] -> "
                  f"{'WIN' if verified else act}  ({oracle_result[:46]})")
            if verified:
                # G24: a confirmed win records the ordered REPLAY RECIPE (setup_steps + replay_seed +
                # namespace) so the proof replays from a CLEAN mirror -- the live state blob is only a hint.
                ps.replay_seed.setdefault("objective", objective); ps.save()
                _record(con, h, "win", code, oracle_result); writeback(h, True, code, oracle_result, None)
                try:
                    _record(con, {**h, "replay_recipe": ps.replay_recipe()}, "win", code,
                            "REPLAY:" + json.dumps(ps.replay_recipe())[:400])
                except Exception:
                    pass
                wins[direction] += 1; won = True
                # G48 DEPTH: seed chained hypotheses that ESCALATE this confirmed foothold on the SAME surface
                # (deeper effect / privilege-escalation / adjacent invariant) before the loop moves on to breadth.
                try:
                    for ch in _chain_from_win(h, oracle_result):
                        if fingerprint(ch) not in _tried(con):
                            chain_queue.append(ch)
                    if chain_queue:
                        print(f"  step {step}: chained {len(chain_queue)} deeper hypothesis(es) from the win")
                except Exception:
                    pass
                break
            if act == "refine":
                # G22 CONVERGENCE GUARD: score how far this run got; if successive refinements stop
                # ADVANCING (no new progress marker for 2 attempts), the idea is spinning -- stop deepening
                # and move on rather than burn the whole refine budget on a dead line.
                prog, markers = _progress_score(oracle_result)
                if prog > best_prog:
                    best_prog = prog; stall = 0
                else:
                    stall += 1
                # G45 REFINE-ENTRY BAR (board: only keep refining if a DISTINCT SIGNAL exists). A line that
                # shows a partial signal (best_prog>=1) earns the deeper budget (stall tolerance 2); a line
                # with ZERO progress after 2 attempts has no signal to converge on -> bail to a NEW orthogonal
                # hypothesis now instead of spending the whole refine budget random-walking one dead surface.
                stall_cap = 2 if best_prog >= 1 else 1
                if stall >= stall_cap:
                    print(f"  step {step}.{attempt} [{direction}:{h.get('angle')}] -> NO-CONVERGENCE "
                          f"(progress stuck at {best_prog}/4 {markers}; bar={stall_cap}) -> stop deepening")
                    _log_coder_event({**ev_common, "code_valid": True, "executed": True,
                                      "status": "no_convergence", "progress": best_prog, "oracle": oracle_result[:120]})
                    _record(con, h, "tried", code, oracle_result, err); writeback(h, False, code, oracle_result, err); break
                # feed the REAL signal back: an execution error if there was one, else the ORACLE DELTA +
                # graded PROGRESS so the bench CARRIES the working setup and adds the next step.
                prior_code = code
                error = err or (f"[the probe RAN cleanly (progress {prog}/4: {markers}) but the oracle did NOT "
                                f"confirm: {oracle_result[:200]}] REFINE: KEEP the working setup/auth that got "
                                "you here and ADD the NEXT step toward confirmation (setup->trigger->verify).")
                continue
            # pivot (infra fault) or new (depth exhausted, ran clean): a real TRIED attempt, not a dead-try
            _record(con, h, "tried", code, oracle_result, err); writeback(h, False, code, oracle_result, err); break
        # G24 NON-DESTRUCTIVE TEARDOWN: on EVERY terminal state, tear down planted artifacts in reverse
        # order (idempotent). Captured plan is persisted either way; the mirror snapshot is the backstop.
        try:
            plan = ps.teardown_plan[:]
            done = ps.teardown()          # records/clears; a live runner can be wired to execute each cmd
            if plan:
                print(f"  step {step}: teardown {len(done)}/{len(plan)} artifact(s) "
                      f"[{PS.prefix_for(ps.hypothesis_id)}] {'(win)' if won else ''}")
        except Exception:
            pass
    total = wins["scaffold"] + wins["code"]
    # monitor summary the orchestrator can read: how much of the budget was real testing vs dead-tries
    dead_n = ok_n = 0
    try:
        for ln in open(CODER_EVENTS, encoding="utf-8"):
            e = json.loads(ln)
            if e.get("status") == "dead_try": dead_n += 1
            elif e.get("executed"): ok_n += 1
    except Exception:
        pass
    print(f"CODE DRIVER done: {total} verified win(s) (NOV-SCAF={wins['scaffold']}, NOV-CODE={wins['code']}) "
          f"over budget {budget} (used scaffold={used['scaffold']}, code={used['code']}) | "
          f"coder-events: executed={ok_n} dead_tries={dead_n} -> {CODER_EVENTS}. ledger:", stats(con))
    con.close()
    return wins


def other_dir(d):
    return "code" if d == "scaffold" else "scaffold"


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AEGIS adaptive code driver (novel/zero-day-class discovery)")
    ap.add_argument("--objective", default="find a novel authz/logic flaw on the mirror")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    ap.add_argument("--dry", action="store_true", help="simulate propose/run (no live mirror/API) -- smoke")
    a = ap.parse_args()
    drive(a.objective, budget=a.budget, dry=a.dry)
