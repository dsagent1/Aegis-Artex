"""Unit tests for the two engine-gap oracle changes (AuthzOracle mutation-awareness, IdorOracle intended)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import requests
import verified_findings as VF

class Resp:
    def __init__(self, status, text="body"): self.status_code = status; self.text = text
class Sess:
    verify = True
    def __init__(self, fn): self.fn = fn
    def request(self, method, url, json=None, verify=None, timeout=None):
        if "zz-nonexistent" in url: return Resp(404, "notfound")
        return self.fn(method, url, json)
# anon (requests.Session()) inside the SPA guard -> always 401 (denied, deterministic, no network)
requests.Session = lambda *a, **k: Sess(lambda m, u, j: Resp(401, "anon-denied"))

BASE = "http://authz-test.local"; PATH = "/api/invoices"
CONFIRM = {"jobId": "fresh-no-conflict"}
def sfr(dispatcher_status, extra=None):
    def make(role):
        def fn(method, url, json):
            if role == "dispatcher":
                if json == CONFIRM: return Resp(201, "created")
                return Resp(dispatcher_status, "disp")
            if role == "technician": return Resp(403, "denied")
            return Resp(403, "denied")
        return Sess(fn)
    return make

results = []
def check(name, cond): results.append((name, cond)); print(("PASS " if cond else "FAIL ") + name)

# 1. dispatcher POST 409, baseline technician 403 -> VERIFIED via business-conflict
v, r = VF.AuthzOracle(BASE, "POST", PATH, "dispatcher", "technician", sfr(409)).check(None)
check("1 dispatcher-POST-409 + tech-403 => verified/business-conflict",
      v == "verified" and r["via"] == "business-conflict" and r["action_confirmed"] is False)

# 2. same but GET (non-mutating), tested 409 -> REJECTED (409 only on write)
v, r = VF.AuthzOracle(BASE, "GET", PATH, "dispatcher", "technician", sfr(409)).check(None)
check("2 GET-409 => rejected (non-mutating)", v == "rejected")

# 3. POST 409 + confirm_json_body -> 201 => action_confirmed=True
v, r = VF.AuthzOracle(BASE, "POST", PATH, "dispatcher", "technician", sfr(409), confirm_json_body=CONFIRM).check(None)
check("3 POST-409 + confirm=201 => verified + action_confirmed",
      v == "verified" and r["action_confirmed"] is True and r["via"] == "business-conflict")

# 4. plain tested 2xx (GET 200) + baseline 403, SPA guard not tripped -> VERIFIED via action-2xx
v, r = VF.AuthzOracle(BASE, "GET", PATH, "dispatcher", "technician", sfr(200)).check(None)
check("4 plain-2xx + 403 => verified/action-2xx (unchanged)",
      v == "verified" and r["via"] == "action-2xx" and r["spa_or_public"] is False and r["action_confirmed"] is True)

# 5. IdorOracle intended-skip vs not-intended
lead = lambda oid, role: {"id": oid, "role": role, "owner_status": 200, "attacker_status": 200,
                          "owner_sha": "s", "attacker_sha": "s", "control_status": 404}
v, r = VF.IdorOracle([lead("job1", "dispatcher")], intended={"job1": ["dispatcher"]}).check()
check("5a IDOR role in intended[id] => rejected, intended_skipped=1",
      v == "rejected" and r["intended_skipped"] == 1 and r["n_leads"] == 0)
v, r = VF.IdorOracle([lead("job2", "technician")], intended={"job1": ["dispatcher"]}).check()
check("5b IDOR role NOT intended => verified, intended_skipped=0",
      v == "verified" and r["intended_skipped"] == 0 and r["n_leads"] == 1)
# backward-compat: no intended map => today's behaviour (verified)
v, r = VF.IdorOracle([lead("job3", "technician")]).check()
check("5c IDOR no map => verified (backward-compatible)", v == "verified" and r["intended_skipped"] == 0)

print("\n%d/%d PASS" % (sum(1 for _, c in results if c), len(results)))
sys.exit(0 if all(c for _, c in results) else 1)
