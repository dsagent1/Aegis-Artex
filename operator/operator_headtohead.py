"""operator_headtohead.py -- compact capability head-to-head: deepseek-v4-pro vs gpt-oss-120b as the
OPERATOR BRAIN. Two core operator sub-tasks: (1) planning/reasoning from recon, (2) writing a
non-destructive exploit probe. Prints both outputs (length + snippet) for a quality read. Observation."""
import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import code_suggester, cf_agent
try:
    code_suggester._load_secret_env()
except Exception:
    pass
from openai import OpenAI
_ds = OpenAI(api_key=os.environ.get("AEGIS_LLM_API_KEY"), base_url="https://api.deepseek.com/v1")

SYS = ("You are the autonomous security co-pilot (operator brain) for an AUTHORIZED, contained pentest of "
       "an owned mirror (role-based JSON API app). Non-destructive only. Be concise, specific, actionable.")

def ds(user):
    try:
        r = _ds.chat.completions.create(model="deepseek-v4-pro",
            messages=[{"role": "system", "content": SYS}, {"role": "user", "content": user}],
            extra_body={"thinking": {"type": "disabled"}}, max_tokens=500, temperature=0.2)
        return r.choices[0].message.content or ""
    except Exception as e:
        return "[err %s]" % str(e)[:80]

def oss(user):
    try:
        return cf_agent._post("gpt-oss-120b", SYS, user, 500, 0.2)
    except Exception as e:
        return "[err %s]" % str(e)[:80]

TASKS = [
    ("PLAN", "Recon: Node/Express JSON API, roles owner/dispatcher/technician, RBAC via a RoleSubsectionDenial table. "
             "Confirmed: dispatcher reaches /api/settings (200) where technician is 403. Give the 3 highest-value NEXT "
             "hunt moves as concrete {surface, technique, oracle} triples."),
    ("CODE", "Write a NON-DESTRUCTIVE probe (python+requests) that proves the credit-note over-credit invariant: "
             "replaying POST /api/credit-notes lets sum(credits) exceed invoice.total. Include the oracle check."),
]

for tag, task in TASKS:
    print("\n" + "=" * 76 + "\n### TASK: %s\n" % tag + "=" * 76)
    for name, fn in (("deepseek-v4-pro", ds), ("gpt-oss-120b", oss)):
        t = time.time()
        out = fn(task)
        dt = time.time() - t
        body = out
        print("\n--- %s  (%.1fs, %d chars) ---" % (name, dt, len(out)))
        print(body[:900])
