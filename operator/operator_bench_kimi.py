import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import code_suggester, cf_agent
try: code_suggester._load_secret_env()
except Exception: pass
os.environ["AEGIS_CF_TIMEOUT_REASONING"] = "120"; os.environ["AEGIS_CF_TIMEOUT"] = "60"
SYS = ("Autonomous security co-pilot (operator brain), AUTHORIZED contained pentest of an owned mirror "
       "(role-based JSON API). Non-destructive only. Concise, specific, actionable.")
CODE = ("Write a NON-DESTRUCTIVE probe (python+requests) proving the credit-note over-credit invariant: "
        "replaying POST /api/credit-notes lets sum(credits) exceed invoice.total. Include the oracle check.")
LAT = "List the 3 top authz test techniques for a role-based JSON API. One line each."
PLAN = ("Recon: Node/Express JSON API, roles owner/dispatcher/technician, RBAC via a RoleSubsectionDenial table. "
        "Confirmed dispatcher reaches /api/settings (200) where technician is 403. Give the 3 highest-value NEXT "
        "hunt moves as concrete {surface, technique, oracle} triples.")
def kimi(u, mx): return cf_agent._post("kimi-k2.7-code", SYS, u, mx, 0.2)
for tag, task, mx in (("LATENCY", LAT, 800), ("PLAN", PLAN, 1200), ("CODE", CODE, 2000)):
    t = time.time(); out = kimi(task, mx); dt = time.time() - t
    reasoning_only = out.startswith("[raw reasoning")
    print("\n" + "=" * 72, flush=True)
    print("kimi-k2.7-code | %s | %.1fs | %d chars%s" % (tag, dt, len(out), "  <- REASONING-ONLY, no final answer" if reasoning_only else ""), flush=True)
    print("-" * 72, flush=True)
    print((out or "[empty]")[:1000], flush=True)
