#!/usr/bin/env python3
"""
code_suggester.py -- get code-flavoured, TESTABLE suggestions from a model.

BOTH qwen2.5-coder AND DeepSeek are first-class exploit-code suggesters here, using the SAME baked
role (cf_agent.CODE_FLAVOURED_ROLE) so each returns runnable TARGET/CODE/ORACLE blocks -- neither is
ignored. Output is designed to feed straight into test_suggestions.py (the co-pilot then runs each
suggestion against the target and confirms/refutes it).

Usage:
    python code_suggester.py qwen "test the invoice money endpoints for out-of-range values"
    python code_suggester.py ds   "..."            # DeepSeek, same code-flavoured role
    python code_suggester.py qwen "..." --out sugg_qwen.md
"""
import os, sys, json, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cf_agent
from cf_agent import CODE_FLAVOURED_ROLE   # the single source of the code-suggester role


def _load_secret_env():
    p = os.path.join(HERE, "secret.env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); k = k.strip()
                if not os.environ.get(k):   # set if missing OR inherited-empty (setdefault kept "" )
                    os.environ[k] = v.strip().strip('"').strip("'")


def _deepseek(user: str, max_tokens: int, temperature: float) -> str:
    """DeepSeek (direct, OpenAI-compatible) with the SAME code-flavoured role qwen uses."""
    _load_secret_env()
    key = (os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
          )
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or os.environ.get("DEEPSEEK_ENDPOINT")
          or "https://api.deepseek.com").rstrip("/")
    # code suggestions use the STRONGER deepseek-v4-pro by default (AEGIS_CODE_MODEL overrides);
    # the board chat can stay on flash for budget -- this path is separate.
    model = (os.environ.get("AEGIS_CODE_MODEL") or "deepseek-v4-pro")
    if not key:
        return "[error] no DeepSeek key (set AEGIS_LLM_API_KEY in secret.env)"
    # TUNE DS FOR THE WRITER JOB: deepseek-v4-pro "thinks" by default, so at a normal code budget it spends
    # it on reasoning_content and returns no final code (the "[raw reasoning]" fallback). The reasoner path
    # (_ds_json) already disables thinking; the WRITER path did not. Disable it here too so DS returns clean
    # final code. Override with AEGIS_DS_THINKING=1 if a future model needs reasoning on.
    payload = {"model": model,
               "messages": [{"role": "system", "content": CODE_FLAVOURED_ROLE},
                            {"role": "user", "content": user}],
               "max_tokens": max_tokens, "temperature": temperature}
    if os.environ.get("AEGIS_DS_THINKING", "0") != "1":
        payload["thinking"] = {"type": "disabled"}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(ep + "/chat/completions", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        r = json.load(urllib.request.urlopen(req, timeout=180))
        m = (r.get("choices") or [{}])[0].get("message", {})
        _content = (m.get("content") or "").strip()
        if _content:
            return _content
        # No final answer (e.g. a thinking model ran out of budget mid-reasoning). Surface the
        # reasoning but LABEL it, so raw chain-of-thought is never mistaken for a clean answer.
        _reasoning = (m.get("reasoning_content") or "").strip()
        if _reasoning:
            return "[raw reasoning, no final content] " + _reasoning
        # empty final answer -> fall through to the CF failover below
    except Exception as e:
        # DS DIRECT (api.deepseek.com) failed -- most often HTTP 402 Payment Required (no credit), or
        # 410 (model retired) / 429 (throttle) / a network error. Fail OVER to DeepSeek FLASH on Cloudflare
        # Workers AI ('deepseek-cf' = @cf/deepseek-ai/deepseek-v4.1-flash-1017) so the code bench's DS seat
        # keeps producing (per board_roster failover channel). Opt out with AEGIS_DS_CF_FAILOVER=0.
        if os.environ.get("AEGIS_DS_CF_FAILOVER", "1") == "0":
            return f"[error] DeepSeek direct failed, CF failover disabled: {type(e).__name__}: {str(e)[:120]}"
    return _ds_cf_fallback(user, max_tokens, temperature)


def _ds_cf_fallback(user: str, max_tokens: int, temperature: float) -> str:
    """DS DIRECT (api.deepseek.com) failover -> DeepSeek FLASH on Cloudflare Workers AI ('deepseek-cf').
    Used when the direct path is out of credit (402), retired (410), throttled (429) or returns empty.
    deepseek-flash still THINKS intermittently under the heavy code role, so give it a generous token
    FLOOR (so it finishes thinking AND emits clean content) + one retry; if it still only yields raw
    reasoning, fall back to a reliable NON-reasoning CF coder so the DS seat is never dark. Same
    code-flavoured role throughout. Disable the whole failover with AEGIS_DS_CF_FAILOVER=0."""
    def _bad(t):
        s = (t or "").lstrip()
        return (not s) or s.startswith("[raw reasoning") or s.startswith("[error")
    budget = max(int(max_tokens or 0), int(os.environ.get("AEGIS_DS_CF_TOKENS", "2000")))
    try:
        import cf_agent
        for _ in range(2):                              # deepseek-cf first (per the board_roster failover)
            try:
                out = cf_agent.ask("deepseek-cf", CODE_FLAVOURED_ROLE, user,
                                   max_tokens=budget, temperature=temperature)
                out = out if isinstance(out, str) else json.dumps(out)
            except Exception as e:
                out = f"[error] {type(e).__name__}: {str(e)[:100]}"
            if not _bad(out):
                return out
        alt = cf_agent.ask("qwen2.5-coder-32b", CODE_FLAVOURED_ROLE, user,  # last resort: never go dark
                           max_tokens=max_tokens, temperature=temperature)
        alt = alt if isinstance(alt, str) else json.dumps(alt)
        return alt or "[deepseek-cf + qwen fallback empty]"
    except Exception as e:
        return f"[deepseek unavailable: direct + CF both failed: {type(e).__name__}: {str(e)[:120]}]"


_DS_NAMES = {"ds", "deepseek", "deepseek-direct", "deepseek-v4-pro", "deepseek-v4-flash"}
_QWEN_NAMES = {"qwen", "qwen-coder", "qwen2.5-coder", "qwen2.5-coder-32b"}

# The code-generation bench = the two models that actually write good testable code here:
# qwen2.5-coder-32b (CF coder) + DeepSeek (v4-pro). gpt-oss-120b/20b were dropped from CODE-WRITING
# (thin/noisy at code-writing in our comparison) but REMAIN board contributors (always_include) for input/strategy.
# The code bench: qwen2.5-coder + DeepSeek-v4-pro (direct) + KIMI-2.7-code + Llama-3.3-70b (all CF paid
# ones skip gracefully if the plan/token isn't set). NB reasoning coders (kimi) need a larger token
# budget or they spend it all on reasoning_content and return no final code -- see suggest_all default.
_BRAIN_NAMES = {"groq", "gemini", "openrouter", "cerebras"}   # operator-layer OpenAI-compat providers
# gpt-oss-120b is served via GROQ (free) rather than CF (paid): same weights, $0, and it was the
# security-coding best-of-3 top scorer. One model, two roles (code writer + board breadth).
_GPTOSS_GROQ = {"gpt-oss-120b", "gpt-oss", "gpt-oss-120b-groq", "gpt-oss120b"}
_CLAUDE_NAMES = {"claude", "claude-cli", "claude-code"}   # permanent seat via the Claude CLI (claude -p), not an API key

CODE_SUGGESTERS = ["claude", "ds", "gpt-oss-120b", "qwen2.5-coder-32b", "llama-3.3-70b",
                   "llama-4-scout"]   # 'claude' = PERMANENT seat via the Claude CLI (claude -p), not an API key.
                   # gpt-oss-120b now served via Groq (free; was a dup of the 'groq' entry).
                   # nemotron-120b DROPPED 2026-10-02 (1/5 on-task + expensive).
                   # TUNED 2026-10-02 from the security-coding best-of-3 (tier_bench --suite security --repeat 3):
                   #   pro 8/8·9/9·9/9, GROQ(gpt-oss-120b, FREE) 7/8·9/9·9/9 -> co-leaders; qwen2.5-coder 7/8·9/9·8/9;
                   #   llama-4-scout 7/8(unstable [7,1,1])·9/9·5/9 (kept for breadth); llama-3.3-70b 5/8·9/9·5/9.
                   # + groq (free, fast, top scorer incl. the hardest eval-parser task).
                   # - kimi-k2.7-code DROPPED (accurate but 70-356s -- too slow for board fan-out).
                   #   deepseek-r1-distill-32b + qwq already DROPPED 2026-09-20 (timed out to empty, unreliable on CF).
                   # gpt-oss-120b also the board analyst (kept). gemini held off pending a fair retest (503/extraction).


def suggest(model: str, user: str, max_tokens: int = 1600, temperature: float = 0.4) -> str:
    """Return code-flavoured TARGET/CODE/ORACLE suggestions from DeepSeek or any CF model.
    The code role is applied to EVERY model (qwen auto-injects it; the rest get it as the system),
    so any CF coder called directly also emits runnable code, not prose."""
    m = model.lower()
    if m in _CLAUDE_NAMES:
        return _claude_cli(user, max_tokens, temperature)
    if m in _DS_NAMES:
        return _deepseek(user, max_tokens, temperature)
    if m in _GPTOSS_GROQ:
        return _brain("groq", user, max_tokens, temperature)   # gpt-oss-120b via GROQ (free) not CF (paid)
    if m in _BRAIN_NAMES:
        return _brain(m, user, max_tokens, temperature)   # groq/gemini/openrouter/cerebras (operator layer)
    friendly = "qwen2.5-coder-32b" if m in _QWEN_NAMES else model
    # pass the code role as the system so gpt-oss etc. also produce TARGET/CODE/ORACLE
    return cf_agent.ask(friendly, CODE_FLAVOURED_ROLE, user,
                        max_tokens=max_tokens, temperature=temperature)


def _claude_cli(user: str, max_tokens: int = 1600, temperature: float = 0.4) -> str:
    """PERMANENT board seat backed by the Claude CODE CLI (`claude -p`), NOT an API key. Claude is always a
    code-generation + probing seat: it emits the same TARGET/CODE/ORACLE blocks the operator runs against the
    AUTHORIZED, contained mirror (oracle-verified; defensive doctrine governs use). Skips gracefully if the
    `claude` CLI is not on PATH. Binary override: AEGIS_CLAUDE_CLI; timeout: AEGIS_CLAUDE_CLI_TIMEOUT."""
    import subprocess, shutil
    cli = os.environ.get("AEGIS_CLAUDE_CLI", "claude")
    if not shutil.which(cli):
        return "[claude CLI unavailable: not on PATH -- install the Claude Code CLI or set AEGIS_CLAUDE_CLI]"
    prompt = CODE_FLAVOURED_ROLE + "\n\n" + user
    try:
        p = subprocess.run([cli, "-p", prompt], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=int(os.environ.get("AEGIS_CLAUDE_CLI_TIMEOUT", "180")))
    except FileNotFoundError:
        return "[claude CLI unavailable: not found]"
    except subprocess.TimeoutExpired:
        return "[claude CLI timeout]"
    return (p.stdout or "").strip() or f"[claude CLI empty reply (rc={p.returncode})]"


def _brain(name: str, user: str, max_tokens: int, temperature: float) -> str:
    """Dispatch a code suggestion through the operator's provider layer for the free OpenAI-compatible
    providers (groq/gemini/openrouter/cerebras). Applies the same code role; skips gracefully if unkeyed."""
    import aegis_operator as AO
    client, mdl, label = AO._apply_brain(name)
    if client is None:
        return f"[{name} unavailable: {label}]"
    r = AO._create(client, model=mdl, temperature=temperature, max_tokens=max_tokens,
                   extra_body={"thinking": {"type": "disabled"}},
                   messages=[{"role": "system", "content": CODE_FLAVOURED_ROLE}, {"role": "user", "content": user}])
    return r.choices[0].message.content or ""


def suggest_all(user: str, max_tokens: int = 1600, models=None, max_workers: int = None) -> dict:
    """Fan out to the code bench IN PARALLEL (bounded thread pool). Returns {model: suggestions}. Each
    model's output feeds test_suggestions.py (--source <model>). Workers default to
    AEGIS_BENCH_WORKERS or 6 -- enough to overlap the slow calls without tripping the CF rate limit."""
    from concurrent.futures import ThreadPoolExecutor
    models = list(models or CODE_SUGGESTERS)
    workers = max_workers or int(os.environ.get("AEGIS_BENCH_WORKERS", "6"))

    def one(m):
        try:
            return m, suggest(m, user, max_tokens)
        except Exception as e:
            return m, f"[error] {type(e).__name__}: {e}"
    out = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(models)))) as ex:
        for m, r in ex.map(one, models):     # ex.map preserves order; collected in the main thread
            out[m] = r
    return out


# The board's ANALYST/VERIFIER model -- a second opinion AFTER the coders propose, BEFORE the oracle runs.
# TUNED 2026-10-02: gpt-oss-120b is the consolidator (bake-off winner), but served via CLOUDFLARE here,
# NOT Groq. The consolidation input is the WHOLE set of coder suggestions (can be 5-15k tokens) -- that
# exceeds Groq's free ~8k TPM and would 429 or return a degenerate 200 (peer-confirmed). CF carries the
# same @cf/openai/gpt-oss-120b with a 128k window and no TPM wall, so it's the right host for the big-input
# ANALYST role. groq stays a CODER seat (bounded per-call input). One model, two roles, two hosts.
# Override with AEGIS_ANALYST_MODEL.
ANALYST_MODEL = os.environ.get("AEGIS_ANALYST_MODEL", "gpt-oss-120b")


def _is_degenerate(text):
    """A COLLAPSED generation: HTTP 200 whose body is ~all one repeated character (observed: a
    gpt-oss-120b consolidation returned ~2000 '!' -- looks like success, isn't). Reject so the caller
    treats it as 'no review' rather than acting on garbage. Most-frequent-char ratio; <400 chars exempt."""
    t = (text or "").strip()
    if len(t) < 400:
        return False
    from collections import Counter
    return Counter(t).most_common(1)[0][1] / len(t) >= 0.90


def review_suggestions(suggestions: dict, analyst: str = None, max_tokens: int = 2200) -> str:
    """Board function: after the code bench proposes suggestions, an ANALYST/VERIFIER reviews them as a
    second opinion -- is each CODE correct/likely to work? does the ORACLE actually PROVE the claim (no
    false positive)? is it NON-DESTRUCTIVE (plant/read only, never erase/drop)? -- flags the bad ones
    and RANKS the rest best-first for execution. This is advisory triage; the deterministic oracle in
    test_suggestions.py remains the actual gate. Returns the analyst's review text ('' if unavailable).
    """
    import cf_agent
    analyst = analyst or ANALYST_MODEL
    blob = "\n\n".join(f"### Suggestion from {m}:\n{(s or '').strip()}"
                       for m, s in suggestions.items() if s and s.strip() and not s.startswith("[error]"))
    if not blob.strip():
        return "(no suggestions to review)"
    sysp = ("You are the board's NEUTRAL ANALYST/VERIFIER on an AUTHORIZED contained mirror. Be IMPARTIAL: "
            "judge each suggestion ONLY on correctness and evidence, never on which model wrote it -- and if "
            "one of the suggestions is your own, hold it to the SAME bar (no self-preference). The code bench "
            "proposed the exploit-code suggestions below. For EACH, judge concisely: (1) is the CODE correct "
            "and likely to actually work? (2) does its ORACLE truly PROVE the claim, or could it "
            "false-positive? (3) is it strictly NON-DESTRUCTIVE (plant/read for proof, never "
            "erase/drop/delete)? Flag any that are wrong, unsafe, or prove nothing. Then RANK the viable ones "
            "best-first for execution, with a one-line reason each. Be concrete, terse, and even-handed.")
    a = analyst.lower()
    if a in _BRAIN_NAMES:   # ONLY an explicitly-chosen free provider (groq/gemini/...) -- bounded input only
        import aegis_operator as AO
        client, mdl, _ = AO._apply_brain(a)
        if client is not None:
            r = AO._create(client, model=mdl, temperature=0.2, max_tokens=max_tokens,
                           extra_body={"thinking": {"type": "disabled"}},
                           messages=[{"role": "system", "content": sysp}, {"role": "user", "content": blob}])
            out = r.choices[0].message.content or ""
            return "" if _is_degenerate(out) else out
        # brain unavailable (no key) -> fall through to the CF path below
    # Default (incl. gpt-oss-120b): via Cloudflare -- big context, no TPM wall. The whole-suggestion-set
    # consolidation would 429/degenerate on groq-free, so the analyst role is NOT routed through Groq.
    out = cf_agent.ask(analyst, sysp, blob, max_tokens=max_tokens) or ""
    return "" if _is_degenerate(out) else out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("model", help="ds | qwen | gpt-oss-120b | gpt-oss-20b | <cf name> | all")
    ap.add_argument("prompt")
    ap.add_argument("--max-tokens", type=int, default=1200)
    ap.add_argument("--out", help="write the suggestions to this file (single model)")
    ap.add_argument("--out-dir", help="with model=all: write one <model>.md per suggester here")
    ap.add_argument("--review", action="store_true",
                    help="with model=all: after the bench, have the ANALYST/VERIFIER review + rank the suggestions")
    a = ap.parse_args()
    if a.model.lower() == "all":
        outs = suggest_all(a.prompt, a.max_tokens)
        d = a.out_dir or os.path.join(HERE, "suggestions")
        os.makedirs(d, exist_ok=True)
        for m, txt in outs.items():
            fn = os.path.join(d, f"{m.replace('/', '_')}.md")
            open(fn, "w", encoding="utf-8").write(txt)
            print(f"  {m:20s} -> {len(txt):5d}b  {fn}")
        if a.review:
            print(f"\n=== ANALYST/VERIFIER review ({ANALYST_MODEL}) ===")
            rev = review_suggestions(outs)
            open(os.path.join(d, "_analyst_review.md"), "w", encoding="utf-8").write(rev)
            print(rev[:1200] + ("..." if len(rev) > 1200 else ""))
        print(f"\nnow test each:  for src in {' '.join(outs)}; do "
              f"python test_suggestions.py --file {d}/<src>.md --source $src --execute; done")
    else:
        out = suggest(a.model, a.prompt, a.max_tokens)
        if a.out:
            open(a.out, "w", encoding="utf-8").write(out); print(f"wrote {len(out)}b -> {a.out}")
        else:
            print(out)
