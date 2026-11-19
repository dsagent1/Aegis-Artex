"""tier_bench.py -- self-contained brain benchmark to TUNE the DS gate/brain policy per difficulty.

No live mirror needed: graded EASY -> HARD -> VERY-HARD -> IMPOSSIBLE coding tasks, each auto-scored by
EXECUTING the model's emitted Python against hidden test cases (correctness is objective, not self-report).

Contestants:
  - deepseek-flash            (fast DeepSeek)
  - deepseek-v4-pro           (thinking OFF)
  - deepseek-v4-pro+think     (thinking ON)
  - cheap CF Workers-AI models (llama-3.3-70b, nemotron-120b, kimi, gpt-oss-120b, qwen2.5-coder-32b, glm-5.3-flash)
  - claude                    (Claude Code CLI -- the reference bar)

Measures per (task, contestant): correctness (tests passed / total), latency (s), output size.
Prints a ranked report and RECOMMENDS: (a) the cheapest brain that clears each tier, (b) the best
relatively-cheap CF helper to call when the primary brain is failing.

Run:  python operator/tier_bench.py                 # full roster (~bounded API calls)
      python operator/tier_bench.py --roster flash,pro,pro-think,llama-3.3-70b,claude
      python operator/tier_bench.py --tiers easy,hard   # subset
Cost is bounded by max_tokens per call; each contestant answers each task exactly once.
"""
from __future__ import annotations
import os, sys, re, time, json, argparse, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# --- load secret.env (DS + CF keys) the same way bake_off.py does ---
_SE = os.environ.get("AEGIS_SECRET_ENV") or os.path.join(ROOT, "..", "ask-board", "secret.env")
if os.path.exists(_SE):
    for line in open(_SE, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

# ---------------------------------------------------------------- the graded task set
# Each task: a prompt (asks for ONE named function) + a test harness that imports the emitted
# function and asserts. Scored by executing the extracted code; correctness = tests passed / total.
TASKS = {
 "easy": {
   "prompt": "Write a Python function `is_power_of_two(n)` that returns True iff n is a positive power of "
             "two (1,2,4,8,...), else False. Reply with ONLY a ```python code block defining the function.",
   "func": "is_power_of_two",
   "tests": [("is_power_of_two(1)", True), ("is_power_of_two(2)", True), ("is_power_of_two(3)", False),
             ("is_power_of_two(0)", False), ("is_power_of_two(-4)", False), ("is_power_of_two(1024)", True),
             ("is_power_of_two(1023)", False)],
 },
 "hard": {
   "prompt": "Write a Python function `parse_qs(s)` that parses a URL query string into a dict WITHOUT using "
             "urllib. Rules: split on '&'; each item is key=value; percent-decode %XX and turn '+' into space "
             "in BOTH key and value; a key seen once maps to a str, a key seen 2+ times maps to a list of its "
             "values in order. Reply with ONLY a ```python code block.",
   "func": "parse_qs",
   "tests": [("parse_qs('a=1&b=2')", {"a": "1", "b": "2"}),
             ("parse_qs('a=1&a=3&a=5')", {"a": ["1", "3", "5"]}),
             ("parse_qs('x=hello+world')", {"x": "hello world"}),
             ("parse_qs('q=%41%42&q=%43')", {"q": ["AB", "C"]}),
             ("parse_qs('k=a%20b')", {"k": "a b"})],
 },
 "very-hard": {
   "prompt": "Write a Python function `nqueens_count(n)` returning the number of distinct solutions to the "
             "N-queens problem for an n x n board. It MUST return the exact count and handle n=12 quickly "
             "(well under 2 seconds). Reply with ONLY a ```python code block.",
   "func": "nqueens_count",
   "tests": [("nqueens_count(1)", 1), ("nqueens_count(4)", 2), ("nqueens_count(6)", 4),
             ("nqueens_count(8)", 92), ("nqueens_count(10)", 724), ("nqueens_count(12)", 14200)],
   "timeout": 6,
 },
 "impossible": {
   "prompt": "Implement a backtracking regex matcher `re_match(pattern, text)` (bool: does pattern match the "
             "WHOLE text) WITHOUT using the `re` module. Support: literals, '.' (any char), '*' '+' '?' "
             "quantifiers, character classes '[abc]' with ranges '[a-z]' and negation '[^0-9]', anchors "
             "'^' and '$' (optional, may be absent), and grouping with alternation like '(ab|c)*'. Reply "
             "with ONLY a ```python code block.",
   "func": "re_match",
   "tests": [("re_match('a*', 'aaaa')", True), ("re_match('a*', '')", True),
             ("re_match('a.c', 'abc')", True), ("re_match('a.c', 'ac')", False),
             ("re_match('[a-z]+', 'hello')", True), ("re_match('[a-z]+', 'Hello')", False),
             ("re_match('[^0-9]+', 'abc')", True), ("re_match('(ab|c)*', 'ababcab')", True),
             ("re_match('(ab|c)*', 'abx')", False), ("re_match('^a.+z$', 'abcz')", True),
             ("re_match('colou?r', 'color')", True), ("re_match('colou?r', 'colour')", True)],
   "timeout": 5,
 },
}

# Approximate price proxy: $ per 1M output tokens. EDIT with exact CF-neuron / DeepSeek rates when known;
# used only for a relative "cheapness" column. Sizes note the param class (smaller ~= cheaper).
PRICES = {  # friendly-name -> (approx $/1M out tok, param-class note)
 "flash": (0.28, "small/fast (deepseek-flash)"),
 "pro": (1.10, "large (deepseek-v4-pro)"),
 "pro-think": (1.10, "large + reasoning tokens (deepseek-v4-pro)"),
 "llama-3.3-70b": (0.30, "70B"),
 "nemotron-120b": (0.50, "120B"),
 "kimi-k2.7-code": (0.40, "MoE code"),
 "gpt-oss-120b": (0.45, "120B"),
 "qwen2.5-coder-32b": (0.20, "32B coder"),
 "glm-5.3-flash": (0.15, "flash"),
 "mistral-small-24b": (0.18, "24B"),
 "claude": (0.0, "reference bar (Claude Code CLI)"),
}

CF_NAMES = {"llama-3.3-70b", "nemotron-120b", "kimi-k2.7-code", "gpt-oss-120b",
            "qwen2.5-coder-32b", "glm-5.3-flash", "mistral-small-24b"}
DEFAULT_ROSTER = ["flash", "pro", "pro-think", "llama-3.3-70b", "nemotron-120b",
                  "kimi-k2.7-code", "gpt-oss-120b", "qwen2.5-coder-32b", "glm-5.3-flash", "claude"]

# Security-flavoured tiers (--suite security). Still objectively executable: each returns a VALUE the
# ==-harness can check (invalid/blocked inputs return a sentinel rather than raising), so grading stays
# ground-truth. These mirror the kind of defensive code the board actually writes (sanitisers, SSRF
# guards, safe evaluators) -- security competence, not generic algorithms.
SECURITY_TASKS = {
 "easy": {
   "prompt": "Write a Python function `is_safe_relpath(p)` for a file server: return True iff the "
             "user-supplied path `p` is a SAFE relative path that stays inside the base dir -- i.e. it is "
             "NOT absolute, has no '..' component that escapes, and no leading slash or drive. Normalise "
             "'.' and collapse separators. Return False for any traversal/absolute path. Reply with ONLY a "
             "```python code block.",
   "func": "is_safe_relpath",
   "tests": [("is_safe_relpath('a/b')", True), ("is_safe_relpath('a/./b')", True),
             ("is_safe_relpath('../etc/passwd')", False), ("is_safe_relpath('/etc/passwd')", False),
             ("is_safe_relpath('a/../../b')", False), ("is_safe_relpath('a/../b')", True),
             ("is_safe_relpath('..')", False), ("is_safe_relpath('')", False)],
 },
 "hard": {
   "prompt": "Write a Python function `ssrf_blocked(host)` for an SSRF guard: given an IP-literal string "
             "`host`, return True iff it is in a range that must be BLOCKED -- loopback, RFC1918 private "
             "(10/8, 172.16/12, 192.168/16), link-local (169.254/16 incl. the cloud metadata IP), or IPv6 "
             "loopback/ULA/link-local. Return False for ordinary public IPs. Use the `ipaddress` stdlib. "
             "Return False (not raise) for anything that is not a valid IP. Reply with ONLY a ```python code block.",
   "func": "ssrf_blocked",
   "tests": [("ssrf_blocked('127.0.0.1')", True), ("ssrf_blocked('10.0.0.5')", True),
             ("ssrf_blocked('169.254.169.254')", True), ("ssrf_blocked('192.168.1.1')", True),
             ("ssrf_blocked('172.16.0.1')", True), ("ssrf_blocked('172.32.0.1')", False),
             ("ssrf_blocked('8.8.8.8')", False), ("ssrf_blocked('::1')", True),
             ("ssrf_blocked('not-an-ip')", False)],
 },
 "very-hard": {
   "prompt": "Write a Python function `safe_arith(expr)` that evaluates an integer arithmetic expression "
             "using ONLY + - * and parentheses, WITHOUT using eval/exec/compile or importing anything. "
             "Return the integer result for a valid expression, or None for ANYTHING invalid or disallowed "
             "(unknown chars, names, function calls, '**', division, empty). Must resist injection like "
             "\"__import__('os')\". Reply with ONLY a ```python code block.",
   "func": "safe_arith",
   "tests": [("safe_arith('1+2*3')", 7), ("safe_arith('(4-1)*5')", 15), ("safe_arith('2*(3+4)-1')", 13),
             ("safe_arith('2**3')", None), ("safe_arith('10/3')", None), ("safe_arith('a+1')", None),
             ("safe_arith(\"__import__('os')\")", None), ("safe_arith('')", None),
             ("safe_arith('1+1;x')", None)],
   "timeout": 5,
 },
 "impossible": {
   "prompt": "Write `jwt_verify(secret, token)` that verifies an HS256 JWT. Split token into "
             "header.payload.signature (base64url, no padding). REJECT (return None) if the header `alg` "
             "is not exactly 'HS256' (so an 'alg':'none' token is refused). Recompute HMAC-SHA256 over "
             "'header.payload' with `secret` and constant-time compare (hmac.compare_digest) to the "
             "signature -- return None on mismatch. If the decoded payload has an 'exp' claim in the past "
             "(< time.time()), return None. Otherwise return the decoded payload dict. Return None for ANY "
             "malformed token. Stdlib only (base64/hmac/hashlib/json/time). Reply with ONLY a ```python code block.",
   "func": "jwt_verify",
   "tests": [
     ("jwt_verify('s3cret','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJleHAiOjk5OTk5OTk5OTl9.K6LhSJX4gR1g6sa4zdE_2jJwUCJvv5fR_InUD7ZNZGI')", {"user": "alice", "exp": 9999999999}),
     ("jwt_verify('s3cret','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.KQ_Q81hMEN5VRuSzdqvQdI_n4XqpnrY6mtLKTFkPAAA')", None),
     ("jwt_verify('s3cret','eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.5TwyqPxtkj4qc4ZZSYO-58OtK7WcKVpQaK_UjiwU2rE')", None),
     ("jwt_verify('s3cret','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYm9iIiwiZXhwIjoxfQ.xemKmv0pryrgvE4m6bNlol9Pq2juDrTBKBqmm_aO8Do')", None),
     ("jwt_verify('s3cret','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZXZlIiwiZXhwIjo5OTk5OTk5OTk5fQ.HgxIGTcTKBJZGPQHwIxj6ghOFXqc9bBHPdXFdS-H2wA')", None),
     ("jwt_verify('s3cret','not.a.jwt')", None)],
   "timeout": 5,
 },
}

SYS = ("You are an expert Python programmer. Return ONLY a single ```python code block that defines exactly "
       "the requested function. No prose, no tests, no example calls.")


# ---------------------------------------------------------------- contestants
def _extract_code(text):
    if not text:
        return ""
    m = re.search(r"```(?:python)?\s*(.+?)```", text, re.S)
    if m:
        return m.group(1).strip()
    # fallback: from the first def/import to the end
    m = re.search(r"(?ms)^(?:import|from|def)\b.*", text)
    return m.group(0).strip() if m else text.strip()


def _call_deepseek(model, prompt, think, max_tokens):
    from openai import OpenAI
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    ep = os.environ.get("AEGIS_LLM_ENDPOINT", "https://api.deepseek.com/v1")
    c = OpenAI(api_key=key, base_url=ep)
    kw = dict(model=model, max_tokens=max_tokens, temperature=0.1,
              messages=[{"role": "system", "content": SYS}, {"role": "user", "content": prompt}])
    if not think:
        kw["extra_body"] = {"thinking": {"type": "disabled"}}
    r = c.chat.completions.create(**kw)
    return r.choices[0].message.content or ""


def _call_cf(friendly, prompt, max_tokens):
    import cf_agent
    try:
        cf_agent.load_secret_env()
    except Exception:
        pass
    return cf_agent.ask(friendly, SYS, prompt, max_tokens=max_tokens, temperature=0.1)


def _call_claude(prompt, timeout=180):
    r = subprocess.run(["bash", "-lc", "claude -p --output-format json"],
                       input=SYS + "\n\n" + prompt, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    out = (r.stdout or "").strip()
    try:
        j = json.loads(out)
        return j.get("result") or j.get("content") or out
    except Exception:
        return out


def run_contestant(name, prompt, max_tokens):
    t0 = time.time()
    try:
        if name == "flash":
            txt = _call_deepseek("deepseek-flash", prompt, think=False, max_tokens=max_tokens)
        elif name == "pro":
            txt = _call_deepseek("deepseek-v4-pro", prompt, think=False, max_tokens=max_tokens)
        elif name == "pro-think":
            txt = _call_deepseek("deepseek-v4-pro", prompt, think=True, max_tokens=max_tokens)
        elif name == "claude":
            txt = _call_claude(prompt)
        elif name in CF_NAMES:
            txt = _call_cf(name, prompt, max_tokens)
        else:
            txt = _call_brain(name, prompt, max_tokens)   # groq/gemini/openrouter/cerebras, or a raw slug
        return {"latency": round(time.time() - t0, 1), "code": _extract_code(txt),
                "out_chars": len(txt or ""), "error": None}
    except Exception as e:
        return {"latency": round(time.time() - t0, 1), "code": "", "out_chars": 0, "error": repr(e)[:200]}


def _call_brain(name, prompt, max_tokens):
    """Dispatch any operator brain (groq, gemini, openrouter, cerebras, a cf_models name, or a raw slug)
    through the operator's own provider layer -- so the free providers we just wired are benchmarkable."""
    import aegis_operator as AO
    client, model, label = AO._apply_brain(name)
    if client is None:
        raise RuntimeError(label)
    r = AO._create(client, model=model, temperature=0.1, max_tokens=max_tokens,
                   extra_body={"thinking": {"type": "disabled"}},
                   messages=[{"role": "system", "content": SYS}, {"role": "user", "content": prompt}])
    return r.choices[0].message.content or ""


# ---------------------------------------------------------------- grading (execute the code)
_HARNESS = """
import json, sys
{code}
_passed = 0; _total = 0; _errs = []
for _expr, _exp in {tests!r}:
    _total += 1
    try:
        _got = eval(_expr)
        if _got == _exp:
            _passed += 1
        else:
            _errs.append(f"{{_expr}} -> {{_got!r}} != {{_exp!r}}")
    except Exception as _e:
        _errs.append(f"{{_expr}} raised {{type(_e).__name__}}: {{_e}}")
print(json.dumps({{"passed": _passed, "total": _total, "errs": _errs[:3]}}))
"""


def grade(code, task):
    if not code.strip():
        return {"passed": 0, "total": len(task["tests"]), "errs": ["no code emitted"]}
    src = _HARNESS.format(code=code, tests=task["tests"])
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    try:
        open(path, "w", encoding="utf-8").write(src)
        r = subprocess.run([sys.executable, path], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=task.get("timeout", 5))
        line = [l for l in (r.stdout or "").splitlines() if l.strip().startswith("{")]
        if line:
            return json.loads(line[-1])
        return {"passed": 0, "total": len(task["tests"]), "errs": [(r.stderr or "no output")[:160]]}
    except subprocess.TimeoutExpired:
        return {"passed": 0, "total": len(task["tests"]), "errs": ["TIMEOUT (too slow)"]}
    except Exception as e:
        return {"passed": 0, "total": len(task["tests"]), "errs": [repr(e)[:160]]}
    finally:
        try: os.remove(path)
        except Exception: pass


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description="DS brain/tier benchmark (self-contained, executes code to score)")
    ap.add_argument("--roster", default=",".join(DEFAULT_ROSTER), help="comma list of contestants")
    ap.add_argument("--suite", choices=["general", "security"], default="general",
                    help="general = algorithmic tasks; security = defensive-coding tasks (path-traversal, SSRF, safe-eval)")
    ap.add_argument("--tiers", default=None, help="comma list of tiers to run (default: all in the suite)")
    ap.add_argument("--max-tokens", type=int, default=1400)
    ap.add_argument("--repeat", type=int, default=1, help="runs per (tier,contestant); keeps the BEST score (best-of-N, to beat one-shot sample noise)")
    ap.add_argument("--out", default=os.path.join(HERE, "tier_bench_report.md"))
    a = ap.parse_args(argv)
    suite = SECURITY_TASKS if a.suite == "security" else TASKS
    roster = [x.strip() for x in a.roster.split(",") if x.strip()]
    _tiers_in = (a.tiers or ",".join(suite.keys()))
    tiers = [t.strip() for t in _tiers_in.split(",") if t.strip() in suite]
    print(f"[tier-bench] suite={a.suite}  roster={roster}\n[tier-bench] tiers={tiers}  max_tokens={a.max_tokens}", flush=True)

    N = max(1, a.repeat)
    results = {}  # (tier, name) -> {score, latency, err, samples, med_latency}
    for tier in tiers:
        task = suite[tier]
        print(f"\n===== TIER: {tier}  (func {task['func']}, {len(task['tests'])} tests) · best-of-{N} =====", flush=True)
        for name in roster:
            best = None; samples = []; lats = []
            for _k in range(N):
                r = run_contestant(name, task["prompt"], a.max_tokens)
                if r.get("error"):
                    g = {"passed": 0, "total": len(task["tests"]), "errs": [r["error"]]}
                else:
                    g = grade(r["code"], task)
                sc = g["passed"] / max(1, g["total"])
                samples.append(g["passed"]); lats.append(r["latency"])
                if best is None or sc > best["score"]:
                    best = {"score": sc, "passed": g["passed"], "total": g["total"],
                            "latency": r["latency"], "err": (g["errs"][0] if g.get("errs") else "")}
            best["samples"] = samples; best["med_latency"] = sorted(lats)[len(lats) // 2]
            results[(tier, name)] = best
            _smp = ("" if N == 1 else f"  samples={samples}")
            print(f"  {name:22s} best {best['passed']}/{best['total']}  med {best['med_latency']:5.1f}s{_smp}  "
                  f"{'OK' if best['score']==1 else best['err'][:50]}", flush=True)

    _write_report(results, roster, tiers, a.out)
    print(f"\n[tier-bench] report -> {a.out}", flush=True)


def _write_report(results, roster, tiers, out):
    L = ["# DS brain / tier benchmark", "",
         f"_Generated {time.strftime('%Y-%m-%d %H:%M')} · scored by executing emitted code · "
         "correctness = tests passed / total_", "",
         "## Scores (passed/total · latency)", "",
         "| contestant | " + " | ".join(tiers) + " | avg score | avg latency | ~$/1M out |",
         "|---|" + "|".join(["---"] * len(tiers)) + "|---|---|---|"]
    ranking = []
    for name in roster:
        cells = []
        scs, lats = [], []
        for tier in tiers:
            r = results.get((tier, name))
            if r:
                cells.append(f"{r['passed']}/{r['total']} ({r['latency']}s)")
                scs.append(r["score"]); lats.append(r["latency"])
            else:
                cells.append("-")
        avg = sum(scs) / len(scs) if scs else 0
        avl = sum(lats) / len(lats) if lats else 0
        price = PRICES.get(name, (None, ""))[0]
        ranking.append((name, avg, avl, price))
        L.append(f"| {name} | " + " | ".join(cells) + f" | {avg:.2f} | {avl:.1f}s | "
                 + (f"${price}" if price is not None else "?") + " |")
    L += ["", "## Ranking (avg correctness, then latency)", ""]
    for n, avg, avl, price in sorted(ranking, key=lambda x: (-x[1], x[2])):
        L.append(f"- **{n}** — score {avg:.2f}, {avl:.1f}s avg, ~${price}/1M out")

    # recommendations: cheapest brain clearing each tier; best cheap CF helper
    L += ["", "## Recommendation — tier -> brain", ""]
    order = ["flash", "qwen2.5-coder-32b", "glm-5.3-flash", "llama-3.3-70b", "gpt-oss-120b",
             "nemotron-120b", "kimi-k2.7-code", "pro", "pro-think", "claude"]
    for tier in tiers:
        winners = [n for n in order if results.get((tier, n), {}).get("score", 0) == 1.0]
        L.append(f"- **{tier}**: " + (f"cheapest that scored 100% = `{winners[0]}`"
                                       f" (options: {', '.join(winners)})" if winners
                                       else "NONE scored 100% — needs pro/think or a helper"))
    cf_scores = [(n, sum(results.get((t, n), {}).get('score', 0) for t in tiers) / max(1, len(tiers)),
                  PRICES.get(n, (99, ''))[0]) for n in roster if n in CF_NAMES]
    cf_scores = [x for x in cf_scores if x[1] > 0]
    if cf_scores:
        best = sorted(cf_scores, key=lambda x: (-x[1], x[2]))[0]
        L += ["", f"## Best relatively-cheap CF helper: **{best[0]}** "
                  f"(avg score {best[1]:.2f}, ~${best[2]}/1M out)",
              "CF candidates ranked (score, then price):"]
        for n, s, p in sorted(cf_scores, key=lambda x: (-x[1], x[2])):
            L.append(f"- {n}: {s:.2f}  ~${p}/1M")
    L += ["", "_Prices are APPROXIMATE placeholders in tier_bench.PRICES — replace with exact "
          "CF-neuron / DeepSeek rates for a real cost ranking._"]
    open(out, "w", encoding="utf-8").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
