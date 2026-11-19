import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import code_suggester, cf_agent
try: code_suggester._load_secret_env()
except Exception: pass
from openai import OpenAI
_ds = OpenAI(api_key=os.environ.get("AEGIS_LLM_API_KEY"), base_url="https://api.deepseek.com/v1")
SYS = ("Autonomous security co-pilot (operator brain), AUTHORIZED contained pentest of an owned mirror "
       "(role-based JSON API). Non-destructive only. Concise, specific, actionable.")
def ds(u, mx=500):
    r = _ds.chat.completions.create(model="deepseek-v4-pro",
        messages=[{"role":"system","content":SYS},{"role":"user","content":u}],
        extra_body={"thinking":{"type":"disabled"}}, max_tokens=mx, temperature=0.2)
    return r.choices[0].message.content or ""
def oss(u, mx=500):
    return cf_agent._post("gpt-oss-120b", SYS, u, mx, 0.2)

CODE = ("Write a NON-DESTRUCTIVE probe (python+requests) proving the credit-note over-credit invariant: "
        "replaying POST /api/credit-notes lets sum(credits) exceed invoice.total. Include the oracle check.")
LAT = "List the 3 top authz test techniques for a role-based JSON API. One line each."

for name, fn in (("deepseek-v4-pro (non-thinking)", ds), ("gpt-oss-120b (CF)", oss)):
    # latency: 2 samples on a small task
    times = []
    for _ in range(2):
        t = time.time(); _ = fn(LAT, 200); times.append(time.time() - t)
    avg = sum(times) / len(times)
    # code task
    t = time.time(); out = fn(CODE, 600); ct = time.time() - t
    print("\n" + "=" * 72, flush=True)
    print("%s  | latency avg %.1fs (%s) | code-task %.1fs, %d chars"
          % (name, avg, "/".join("%.1f" % x for x in times), ct, len(out)), flush=True)
    print("-" * 72, flush=True)
    print((out or "[empty]")[:1100], flush=True)
