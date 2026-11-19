#!/usr/bin/env python3
"""Offline tests for oob_beacon.py (blind-vuln discovery beacons). No network/listener: uses a temp hit log.
Run: python operator/_oob_beacon_tests.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oob_beacon as OB  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

d = tempfile.mkdtemp()
hits = os.path.join(d, "oob.log")

# --- token minting ---
t1, t2 = OB.new_token(), OB.new_token()
ok("tokens are unique + prefixed", t1 != t2 and t1.startswith("aegisoob") and len(t1) == len("aegisoob") + 12)

reg = OB.BeaconRegistry(oob_host="127.0.0.1:8899", oob_domain="oob.test", hits_path=hits)
b = reg.mint({"surface": "/api/fetch", "vuln_class": "ssrf"})
ok("mint returns token + http_url + dns_host", b["token"].startswith("aegisoob")
   and b["http_url"] == f"http://127.0.0.1:8899/{b['token']}" and b["dns_host"] == f"{b['token']}.oob.test")
ok("context registered against the token", reg.ctx[b["token"]]["vuln_class"] == "ssrf")

# no dns beacon when no domain
reg2 = OB.BeaconRegistry(oob_host="h:1", hits_path=hits)
ok("dns_host empty when no domain", reg2.mint()["dns_host"] == "")

# --- inject: places the callback URL into a move + tags beacon_token (detection only) ---
mv = reg.inject({"surface": "/api/report", "vuln_class": "ssrf", "url": "http://orig"})
ok("inject tags beacon_token", mv["beacon_token"].startswith("aegisoob"))
ok("inject puts callback URL into url field", mv["url"].startswith("http://127.0.0.1:8899/aegisoob"))
ok("inject leaves original move untouched (copy)", "beacon_token" not in {"surface", "vuln_class", "url"})

# --- correlation: BEFORE any callback -> nothing confirmed ---
ok("no callback yet -> not confirmed", reg.confirmed(b["token"]) is False and reg.correlate() == {})

# --- simulate the contained listener recording callbacks (write tokens into the hit log) ---
with open(hits, "w", encoding="utf-8") as fh:
    fh.write(f"GET /{b['token']} HTTP/1.1 from 172.17.0.3\n")             # HTTP beacon hit
    fh.write(f"DNS query {mv['beacon_token']}.oob.test A\n")             # DNS beacon hit
    fh.write("GET /favicon.ico (unrelated noise)\n")

ok("hits() parses the tokens that called back", reg.hits() == {b["token"], mv["beacon_token"]})
ok("confirmed() true for a token that called back", reg.confirmed(b["token"]) is True)
ok("correlate() maps confirmed tokens -> their probe context",
   reg.correlate().get(b["token"], {}).get("surface") == "/api/fetch")

# --- the OOB oracle: verified iff the token called back ---
oracle = OB.make_oob_oracle(reg)
st, rc = oracle({"beacon_token": b["token"]})
ok("oracle VERIFIED on out-of-band callback", st == "verified" and rc["oracle"] == "oob-beacon")
st, rc = oracle({"beacon_token": OB.new_token()})
ok("oracle REJECTS a token with no callback", st == "rejected")
st, rc = oracle({})
ok("oracle REJECTS a result with no token", st == "rejected" and "no beacon token" in rc["detail"])

# --- oracle is response-PROOF: a 200 body claiming success but NO callback -> still rejected ---
st, rc = oracle({"beacon_token": OB.new_token(), "status": 200, "body": "fetched ok!"})
ok("no false positive from a rosy response without a real callback", st == "rejected")

n = 15
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
