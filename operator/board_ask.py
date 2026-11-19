#!/usr/bin/env python3
"""
board_ask.py -- the HUMAN's channel into the board, via the operator/co-pilot.

You frame a question; it is posted to the board and (unless --no-panel) fanned out to the panel;
each answer lands on the board, which you watch live in board/live_board.ps1 (20-30s refresh).

Board data-hygiene (PIPELINE v3): send NO secrets/credentials here -- the panel gets only your
framed question. External members (DeepSeek/Sol/CF) see sanitized prompts, nothing privileged.

The DEFAULT panel is ds + cf (gpt-oss-120b/20b) + the coder bench. Sol (GPT-5.6) is OPT-IN only
(content-gated + ~15-25x the coders' price); add it deliberately with `--panel sol` for a
distinct-lineage second opinion.
(kimi-k2.7-code, llama-3.3-70b, llama-4-scout, deepseek-r1-distill-32b) -- the coders answer here as
CONSULTANTS (their opinion), not as code writers. Narrow it with --panel when you want fewer voices.

Usage:
    python board_ask.py "which surface should we prioritise next: the auth flow or the payment path?"
    python board_ask.py "..." --no-panel          # just post the question to the board
    python board_ask.py "..." --panel ds,sol       # limit which panel members answer
    python board_ask.py "..." --panel ds,coders    # ds + the strong coder bench only
"""
import os, sys, json, time, re, urllib.request, argparse, threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cf_agent


def _load():
    p = os.path.join(HERE, "secret.env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); k = k.strip()
                if not os.environ.get(k):
                    os.environ[k] = v.strip().strip('"').strip("'")


_load()
ROOT = os.path.dirname(HERE)
BOARD = os.environ.get("AEGIS_BOARD_DIR", os.path.join(ROOT, "board", "board_files"))
os.makedirs(BOARD, exist_ok=True)

PANEL_SYS = ("You are a security-research analyst on a shared board for the owner's OWN authorized, "
             "contained test. Answer the human's question concretely and concisely. Output only your answer.")


_CUES = ("final answer", "final recommendation", "## recommendation", "recommendation:",
         "bottom line", "in conclusion", "conclusion:", "tl;dr", "## verdict", "verdict:", "to summarize", "in summary")


def _salvage_final(text):
    """Reasoning models often emit raw chain-of-thought with no clean final answer. Salvage the actual
    answer: prefer the text after the last </think>; else from the last 'final answer'/'conclusion'/
    'recommendation' cue; else return the tail of the reasoning (where the conclusion usually lives).
    Idempotent and safe on normal answers (returns them unchanged)."""
    if not text:
        return text
    s = re.sub(r"^\s*\[raw reasoning[^\]]*\]\s*", "", text)  # strip our own label if present
    ends = list(re.finditer(r"</think>", s, re.I))
    if ends:
        tail = s[ends[-1].end():].strip()
        if len(tail) >= 40:
            return tail
    low = s.lower()
    idx = max((low.rfind(c) for c in _CUES), default=-1)
    if idx >= 0 and len(s) - idx >= 40:
        return s[idx:].strip()
    # No clean marker: this is raw chain-of-thought we could NOT distil into a final answer. Both
    # remaining callers pass genuine raw reasoning here (_post's reasoning_content fallback, and
    # _call_member only on an already-"[raw reasoning ...]"-labelled string), so LABEL it in every
    # branch -- so callers/_looks_offtask never mistake naked reasoning for a finished answer.
    if len(s) > 3000:
        return "[raw reasoning, no final content] " + s[-1500:].strip()
    return "[raw reasoning, no final content] " + s.strip()


def _post(url, key, model, sysp, usr, maxtok, extra=None):
    body = {"model": model, "messages": [{"role": "system", "content": sysp},
                                         {"role": "user", "content": usr}],
            "max_tokens": maxtok, "temperature": 0.4}
    if "openai.com" in url:
        # OpenAI GPT-5-class (reasoning) models reject max_tokens and a non-default temperature:
        # rename to max_completion_tokens and drop temperature (matches aegis_operator._create).
        body["max_completion_tokens"] = body.pop("max_tokens")
        body.pop("temperature", None)
    if extra:
        body.update(extra)
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=170))
    m = (r.get("choices") or [{}])[0].get("message", {})
    try:
        import cost_meter
        cost_meter.record(model, r.get("usage"), caller="board_ask",
                          provider=("openai" if "openai.com" in url else "deepseek"),
                          raw_chars=len((m.get("content") or m.get("reasoning_content") or "")))
    except Exception:
        pass
    _content = (m.get("content") or "").strip()
    if _content:
        return _content
    # No final `content` (a thinking model ran out of budget mid-reasoning, or put the answer inside
    # reasoning_content after a </think> marker). SALVAGE the final answer from the raw reasoning
    # rather than returning naked chain-of-thought.
    _reasoning = (m.get("reasoning_content") or "").strip()
    return _salvage_final(_reasoning) if _reasoning else ""


def write(tag, who, text):
    fn = os.path.join(BOARD, f"{tag}__{who}__{int(time.time()*1e9)}.md")
    open(fn, "w", encoding="utf-8").write(f"# {tag} from {who}\n\n" + text)
    print(f"[{who}] {tag} ({len(text)}b)")


def ds(q):
    # board chat uses flash for budget (the operator BRAIN is pro; this Q&A path is separate)
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip('/')
    model = os.environ.get("AEGIS_BOARD_MODEL") or "deepseek-v4-flash"
    try:
        # answer-only path: DISABLE thinking so the token budget produces a FINAL answer instead of
        # burning out mid-reasoning (the raw-chain-of-thought pollution). Give it room, too.
        write("ANSWER", "ds_direct", _post(ep + "/chat/completions", key, model, PANEL_SYS, q, 2600,
                                           extra={"thinking": {"type": "disabled"}}) or "[empty]")
    except Exception as e:
        write("ANSWER", "ds_direct", f"[error] {e}")


def sol(q):
    rf = "You are a senior software-quality / correctness reviewer for our OWN system. "
    try:
        write("ANSWER", "sol", _post("https://api.openai.com/v1/chat/completions", os.environ["OPENAI_API_KEY"],
              "gpt-5.6", rf + "Output only your answer.", rf + q, 1400, extra={"max_completion_tokens": 1400}) or "[empty]")
    except Exception as e:
        write("ANSWER", "sol", f"[error] {e}")


def claude_note(text):
    """Claude is a first-class board member whose answer comes DIRECTLY from the coordinator (the Claude
    Code session driving the board) -- NOT via an API call/key. The coordinator passes Claude's take with
    --claude "..." and it lands as a first-class board ANSWER alongside the panel."""
    write("ANSWER", "claude", (text or "").strip() or "[empty]")


def cf(q):
    for m in ("gpt-oss-120b", "gpt-oss-20b", "mistral-small-24b"):
        try:
            write("ANSWER", f"cf_{m}", cf_agent.ask(m, PANEL_SYS, q, max_tokens=1200) or "[empty]")
        except Exception as e:
            write("ANSWER", f"cf_{m}", f"[error] {e}")


# The strong CODER bench, as board CONSULTANTS. Called via cf_agent._post so PANEL_SYS is sent verbatim
# (NOT the code-writer ROLE_PROMPTS role) -- we want their OPINION here, not TARGET/CODE/ORACLE blocks.
# Reasoning model (kimi) gets a bigger budget so it lands a FINAL answer, not raw CoT. r1-distill DROPPED
# 2026-09-20 (timed out to empty, unreliable on CF); nemotron-120b added (proven fast + reliable coder).
CODER_PANEL = [("kimi-k2.7-code", 2800), ("llama-3.3-70b", 1600),
               ("llama-4-scout", 1600), ("nemotron-120b", 1600)]


def coders(q):
    def one(m, tok):
        try:
            write("ANSWER", f"cf_{m}", cf_agent._post(m, PANEL_SYS, q, tok, 0.4) or "[empty]")
        except Exception as e:
            write("ANSWER", f"cf_{m}", f"[error] {e}")
    ts = [threading.Thread(target=one, args=(m, t)) for m, t in CODER_PANEL]
    for t in ts: t.start()
    for t in ts: t.join()


# ==========================================================================================
# board_consult -- the FAST fan-out + ledger + dissent + summary path (board's own converged design:
#   B concurrent fan-out (hot path) -> append-only JSONL ledger (durable log, OFF the coordination
#   path) -> dedicated dissent-extractor pass -> small-payload summariser. Per-member hard timeout so
#   one slow model never gates the report; timed-out/errored members are marked, never block (quorum).
#   Multi-round critique is intentionally NOT default (it manufactures false consensus).
# ==========================================================================================

# member name -> (kind, model, default_tokens). "ds"/"sol" are direct; everything else via cf_agent.
_MEMBERS = {
    "ds": ("ds", "deepseek-v4-pro", 2200), "sol": ("sol", "gpt-5.6", 2000),
    "gpt-oss-120b": ("cf", "gpt-oss-120b", 1600), "gpt-oss-20b": ("cf", "gpt-oss-20b", 1200),
    "mistral-small-24b": ("cf", "mistral-small-24b", 1400), "qwen2.5-coder-32b": ("cf", "qwen2.5-coder-32b", 1600),
    "llama-3.3-70b": ("cf", "llama-3.3-70b", 1400), "llama-4-scout": ("cf", "llama-4-scout", 1400),
    "glm-5.2": ("cf", "glm-5.2", 1800), "gemma-4-26b": ("cf", "gemma-4-26b", 1400),
    "kimi-k2.6": ("cf", "kimi-k2.6", 2800), "kimi-k2.7-code": ("cf", "kimi-k2.7-code", 2800),
    "deepseek-r1-distill-32b": ("cf", "deepseek-r1-distill-32b", 4000), "qwq-32b": ("cf", "qwq-32b", 4000),
    "nemotron-120b": ("cf", "nemotron-120b", 2200),
}
# Named presets so a caller (or the skill) picks a tier by intent, not by typing model lists.
_PRESETS = {
    "fast": ["ds", "gpt-oss-120b", "qwen2.5-coder-32b", "llama-3.3-70b", "llama-4-scout", "glm-5.2", "mistral-small-24b"],
    "deep": ["ds", "qwen2.5-coder-32b", "kimi-k2.6", "glm-5.2", "gpt-oss-120b", "nemotron-120b"],
    "full": list(_MEMBERS.keys()),
}

# ==========================================================================================
# AEGIS SUITE CONTEXT-TUNING -- the board runs across the suite's 4 stages (3 hunt levels +
# remediation). Each stage gets a roster preset, per-member budget scaling, timeout, quorum, and a
# soft cumulative cost cap tuned to that stage's depth/cost tradeoff: cheap+fast for T1 discovery,
# deeper+bigger for T3 red-team escalation and stage-4 remediation. Resolved from the `stage` arg or
# AEGIS_BOARD_STAGE / AEGIS_STAGE env (set once per leg by complete_test), so the whole suite inherits
# the right profile with no per-call wiring. Absent a stage, the default preserves prior behaviour.
# ==========================================================================================
_STAGE_PROFILES = {
    "operator":    {"preset": "fast", "budget_scale": 0.7, "timeout": 60,  "quorum": 3, "cost_cap_usd": 0.15},
    "exploitgym":  {"preset": "fast", "budget_scale": 1.0, "timeout": 90,  "quorum": 3, "cost_cap_usd": 0.30},
    "redteam":     {"preset": "deep", "budget_scale": 1.3, "timeout": 120, "quorum": 4, "cost_cap_usd": 0.60},
    "remediation": {"preset": "deep", "budget_scale": 1.2, "timeout": 120, "quorum": 3, "cost_cap_usd": 0.60},
}
_DEFAULT_PROFILE = {"preset": "fast", "budget_scale": 1.0, "timeout": 90, "quorum": 2, "cost_cap_usd": None}

# The suite's 3 check-levels. A consult is tagged with the trust level it spoke at so downstream gates
# know the board's verdict is level-appropriate; lower trust also scales the budget down.
_TRUST_LEVELS = ("anon", "user", "admin")
_TRUST_BUDGET = {"anon": 0.6, "user": 0.85, "admin": 1.0}


def _trust_from_role(role):
    r = (role or "").lower().strip()
    if r in ("owner", "admin", "superadmin", "root"):
        return "admin"
    if r in ("", "anon", "anonymous", "guest", "public"):
        return "anon"
    return "user"


def _resolve_profile(stage, trust):
    stage = (stage or os.environ.get("AEGIS_BOARD_STAGE") or os.environ.get("AEGIS_STAGE") or "").lower().strip()
    prof = dict(_STAGE_PROFILES.get(stage, _DEFAULT_PROFILE))
    trust = (trust or os.environ.get("AEGIS_TRUST") or _trust_from_role(os.environ.get("AEGIS_ROLE"))).lower().strip()
    if trust not in _TRUST_LEVELS:
        trust = "user"
    prof["budget_scale"] = round(prof["budget_scale"] * _TRUST_BUDGET.get(trust, 1.0), 3)
    prof["stage"] = stage or "(default)"
    prof["trust"] = trust
    return prof


def _call_member(name, sysp, q, max_tokens=None, budget_scale=1.0):
    kind, model, tok = _MEMBERS.get(name, ("cf", name, 1500))
    tok = max_tokens or tok
    if budget_scale and budget_scale != 1.0:  # per-stage/trust budget scaling (Aegis suite tuning)
        tok = max(400, int(tok * budget_scale))
    if kind == "ds":
        key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
        ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
        return _post(ep + "/chat/completions", key, model, sysp, q, tok, extra={"thinking": {"type": "disabled"}})
    if kind == "sol":
        return _post("https://api.openai.com/v1/chat/completions", os.environ.get("OPENAI_API_KEY", ""),
                     model, sysp, q, tok)
    # cf_agent may hand back a LABELED "[raw reasoning ...]" string for CF reasoning models -> salvage
    # a final answer from THAT. But an already-clean answer that merely contains a cue phrase ("in
    # conclusion", "recommendation:") must be returned verbatim -- never truncated to its tail.
    out = cf_agent.ask(model, sysp, q, max_tokens=tok, temperature=0.35)
    return _salvage_final(out) if (out or "").lstrip().startswith("[raw reasoning") else out


def _looks_offtask(text):
    if not text or len(text.strip()) < 40:
        return True
    low = text.lower()
    if text.strip().startswith("[") and ("error" in low or "timeout" in low or "empty" in low or "raw reasoning" in low):
        return True
    return False


def _fallback_summary(ok, dissent):
    """Last-resort consolidation so a consult ALWAYS returns something usable even if every
    summariser model fails: a structured digest of the strongest ballots + the dissent."""
    top = sorted(ok, key=lambda e: len(e["answer"]), reverse=True)[:3]
    body = "\n\n".join(f"### {e['member']}\n{e['answer'][:1200]}" for e in top)
    return ("[consolidator unavailable -- structured digest of the strongest ballots]\n\n" + body +
            (f"\n\n## Dissent (named)\n{dissent}" if dissent and not _looks_offtask(dissent) else ""))


def _cost_note(result, prof):
    """Attach cumulative per-stage cost (from the cost-meter ledger) and flag a soft cap breach."""
    try:
        import cost_meter
        stage_cost = (cost_meter.rollup().get("by_stage") or {}).get(prof["stage"])
        result["stage_cost_usd"] = stage_cost
        cap = prof.get("cost_cap_usd")
        if cap and stage_cost is not None and stage_cost > cap:
            result["cost_over_cap"] = True
            print(f"[board] stage '{prof['stage']}' cumulative cost ≈${stage_cost} exceeds soft cap "
                  f"${cap}", file=sys.stderr)
    except Exception:
        pass


def consult(question, members=None, timeout=None, summarise=True, report_path=None,
            claude_text=None, sysp=None, ledger_path=None, stage=None, trust=None):
    """Fan out CONCURRENTLY to `members`, capture a ledger, then (optionally) extract dissent + summarise.
    Returns {ledger, dissent, summary, report_path, n_ok, n_total, stage, trust, quorum, low_confidence,
    stage_cost_usd?}. Durable append-only JSONL ledger; per-member timeout.

    AEGIS SUITE TUNING: when `stage` (or AEGIS_BOARD_STAGE / AEGIS_STAGE env) resolves to one of the
    suite stages (operator/exploitgym/redteam/remediation), that profile picks the roster preset,
    per-member budget scale, timeout, quorum and a soft cost cap. The `trust` level (or AEGIS_TRUST /
    AEGIS_ROLE -> anon/user/admin) further scales the budget and tags the verdict. With no stage the
    default profile preserves prior behaviour (fast preset, 90s, quorum 2)."""
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FT
    prof = _resolve_profile(stage, trust)
    sysp = sysp or PANEL_SYS
    members = members or [prof["preset"]]
    members = [m for pre in members for m in (_PRESETS.get(pre, [pre]))]  # expand presets
    seen = set(); members = [m for m in members if not (m in seen or seen.add(m))]
    timeout = timeout or prof["timeout"]
    bscale = prof["budget_scale"]
    write("QUESTION", "human", question)
    ledger = []
    if claude_text:  # Claude is a first-class member: answer supplied directly by the coordinator
        ledger.append({"member": "claude", "answer": claude_text.strip(), "latency": 0.0, "status": "ok"})
        write("ANSWER", "claude", claude_text.strip())

    def _one(name):
        t0 = time.time()
        try:
            return name, (_call_member(name, sysp, question, budget_scale=bscale) or ""), time.time() - t0
        except Exception as e:
            return name, f"[error] {repr(e)[:80]}", time.time() - t0

    # NOT a `with` block: its __exit__ calls shutdown(wait=True), which would block the return until a
    # hung member's ~170s socket timeout elapses -- defeating the per-member timeout/quorum this promises.
    # Gather with a per-future timeout, then drop stragglers (mirrors board_discuss._fanout).
    ex = ThreadPoolExecutor(max_workers=max(1, len(members)))
    try:
        futs = {ex.submit(_one, m): m for m in members}
        for fut in list(futs):
            name = futs[fut]
            try:
                nm, ans, lat = fut.result(timeout=timeout)
                status = "offtask" if _looks_offtask(ans) else "ok"
                ledger.append({"member": nm, "answer": ans.strip(), "latency": round(lat, 1), "status": status})
                write("ANSWER", nm, ans.strip() or "[empty]")
            except _FT:
                ledger.append({"member": name, "answer": "", "latency": timeout, "status": "timeout"})
            except Exception as e:
                ledger.append({"member": name, "answer": f"[error] {e}", "latency": 0.0, "status": "error"})
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    # durable, append-only ledger (OFF the coordination path -- the deep board's point)
    lp = ledger_path or os.path.join(BOARD, "consult_ledger.jsonl")
    try:
        with open(lp, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "q": question, "ledger": ledger}) + "\n")
    except Exception:
        pass

    ok = [e for e in ledger if e["status"] == "ok"]
    quorum = prof["quorum"]
    result = {"ledger": ledger, "dissent": None, "summary": None, "report_path": None,
              "n_ok": len(ok), "n_total": len(ledger), "stage": prof["stage"], "trust": prof["trust"],
              "quorum": quorum, "low_confidence": len(ok) < quorum}
    if len(ok) < quorum:
        print(f"[board] consult quorum not met: {len(ok)}/{quorum} valid (stage={prof['stage']} "
              f"trust={prof['trust']}) -- verdict marked low_confidence", file=sys.stderr)
    if not summarise or not ok:
        _cost_note(result, prof)
        return result

    # small-payload ballots for the dissent + summary passes (NEVER the original big context)
    ballots = "\n\n".join(f"### {e['member']} ({e['latency']}s)\n{e['answer'][:2400]}" for e in ok)

    def _summ(name, sysp2, usr2, tok):
        """One summariser attempt; None if it errors or comes back offtask/empty."""
        try:
            out = _call_member(name, sysp2, usr2, tok, budget_scale=bscale)
            return out if out and not _looks_offtask(out) else None
        except Exception:
            return None

    # dissent: ds, then a fallback member, else a plain marker
    result["dissent"] = (
        _summ("ds", "List every DISTINCT position taken and WHO held it. Name disagreements explicitly; "
              "do NOT average them away. Bullet points only.", f"QUESTION:\n{question}\n\nBALLOTS:\n{ballots}", 900)
        or _summ("gpt-oss-120b", "List the DISTINCT positions and who held each. Bullets only.",
                 f"QUESTION:\n{question}\n\nBALLOTS:\n{ballots}", 900)
        or "[dissent-extract unavailable]")
    # summary: ds, then a fallback member, then a structured digest -- a merge is ALWAYS produced
    _sum_sys = ("You are the summariser. From the ballots, write a decisive consolidation: (1) consensus, "
                "(2) a NAMED dissent section (who disagreed and why -- never averaged), (3) recommendation. Terse markdown.")
    _sum_usr = f"QUESTION:\n{question}\n\nDISSENT:\n{result['dissent']}\n\nBALLOTS:\n{ballots}"
    result["summary"] = (_summ("ds", _sum_sys, _sum_usr, 1800)
                         or _summ("kimi-k2.7-code", _sum_sys, _sum_usr, 2400)
                         or _fallback_summary(ok, result["dissent"]))

    _cost_note(result, prof)
    if report_path:
        tally = ", ".join(f"{e['member']}={e['status']}" for e in ledger)
        q_short = (question[:600] + " …[truncated]") if len(question) > 600 else question  # never echo a huge payload
        conf = "LOW-CONFIDENCE " if result.get("low_confidence") else ""
        cost = result.get("stage_cost_usd")
        cost_line = (f" · stage cost≈${cost}" + (" **OVER CAP**" if result.get("cost_over_cap") else "")) if cost is not None else ""
        rep = (f"# Board consult\n\n**Question:** {q_short}\n\n"
               f"**Stage:** {prof['stage']} · **Trust:** {prof['trust']} · "
               f"**Panel ({len(ok)}/{len(ledger)} valid, quorum {quorum})** {conf}{cost_line}\n\n"
               f"**Members:** {tally}\n\n"
               f"## Consolidation\n{result['summary']}\n\n## Dissent (named)\n{result['dissent']}\n")
        try:
            open(report_path, "w", encoding="utf-8").write(rep); result["report_path"] = report_path
        except Exception:
            pass
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("question")
    ap.add_argument("--no-panel", action="store_true", help="just post the question; don't query the panel")
    ap.add_argument("--claude", help="Claude's own board answer, supplied by the coordinator session (Claude is a first-class member; answers directly, no API key)")
    ap.add_argument("--panel", default="ds,cf,coders",   # Sol OPT-IN only (cost/value): add sol explicitly
                    help="comma list of members to ask: ds, sol, cf (gpt-oss-120b/20b), coders "
                         "(kimi-k2.7-code + llama-3.3-70b + llama-4-scout + deepseek-r1-distill-32b). "
                         "Default = all.")
    # --- board_consult path: fan-out + ledger + dissent + summary (the fast, reliable design) ---
    ap.add_argument("--consult", action="store_true",
                    help="FAST fan-out + ledger + dissent-extract + summariser (recommended). Use --members + --summarise.")
    ap.add_argument("--members", default="fast",
                    help="consult panel: a preset (fast|deep|full) or a comma list of model names.")
    ap.add_argument("--timeout", type=int, default=90, help="per-member hard timeout in seconds (consult).")
    ap.add_argument("--no-summarise", action="store_true", help="consult: skip the dissent+summary passes.")
    ap.add_argument("--report", help="consult: write the consolidated report (+named dissent) to this path.")
    a = ap.parse_args()

    if a.consult:
        members = [x.strip() for x in a.members.split(",") if x.strip()]
        res = consult(a.question, members=members, timeout=a.timeout,
                      summarise=not a.no_summarise, report_path=a.report, claude_text=getattr(a, "claude", None))
        print(f"\n[consult] {res['n_ok']}/{res['n_total']} valid  "
              f"({', '.join(e['member']+':'+e['status'] for e in res['ledger'])})")
        if res.get("summary"):
            print("\n===== CONSOLIDATION =====\n" + res["summary"])
            print("\n===== DISSENT (named) =====\n" + (res.get("dissent") or "(none)"))
        if res.get("report_path"):
            print(f"\nreport written: {res['report_path']}")
        return

    write("QUESTION", "human", a.question)
    if getattr(a, "claude", None):
        claude_note(a.claude)   # Claude (coordinator) answers directly -- first-class board member

    print(f"posted your question to the board ({BOARD}).")
    if a.no_panel:
        print("watch it (and any replies) in board/live_board.ps1"); return
    want = {x.strip() for x in a.panel.split(",")}
    fns = [f for name, f in (("ds", ds), ("sol", sol), ("cf", cf), ("coders", coders)) if name in want]
    ts = [threading.Thread(target=f, args=(a.question,)) for f in fns]
    for t in ts: t.start()
    for t in ts: t.join()
    print(f"\npanel answered on the board. Watch live: board/live_board.ps1")


if __name__ == "__main__":
    main()
