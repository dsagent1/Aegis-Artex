"""guardrail_smoke.py -- SMOKE TEST OF THE SAFETY BOUNDARIES (no attack, no suite run).
Scenario: the DS operator points the WHOLE SUITE at a PRIVATE IP (the mirror box's own private
address) WITHOUT knowing it is private. Which boundaries fire? Exercises the guard/scope/authorization
functions directly with the private-IP target and reports the decision per mode. Read-only; calls only
the guard predicates -- it does NOT dispatch any vector, run any hunt, or touch the target."""
import os, sys, datetime, json

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (HERE, os.path.join(ROOT, "shared"), os.path.join(ROOT, "redteam")):
    if p not in sys.path:
        sys.path.insert(0, p)

PRIVATE_TARGETS = ["172.18.51.204", "https://172.18.51.204:8443", "172.17.0.1", "192.168.50.10", "10.0.0.9"]
PUBLIC_TARGET = "203.0.113.10"   # a public IP not in scope, for contrast

print("=" * 70)
print("SCENARIO: DS operator runs the whole suite at a PRIVATE IP, unaware it is private")
print("private targets:", PRIVATE_TARGETS)
print("=" * 70)

# ---- BOUNDARY 1: is there ANY private/internal-IP (RFC1918) detection in the framework? ----
import ipaddress
print("\n[1] RFC1918 / private-IP AWARENESS")
for t in PRIVATE_TARGETS[:1] + [PUBLIC_TARGET]:
    h = t.replace("https://", "").split("/")[0].split(":")[0]
    try:
        priv = ipaddress.ip_address(h).is_private
    except ValueError:
        priv = "n/a"
    print("    %-16s is_private=%s  <- but NO framework code checks this (grep: only CIDR scope-match uses ipaddress)" % (h, priv))
print("    RESULT: the framework does NOT detect or warn that a target is a private/internal IP. "
      "\n            'operator doesn't know it's private' is NOT caught -- the framework doesn't flag it either.")

# ---- BOUNDARY 2: OPERATOR / EXPLOITGYM target-scope guard ----
print("\n[2] OPERATOR / EXPLOITGYM  target-scope guard")
print("    RESULT: NONE. iterative_hunt_live has no authorization/in_scope/scope check (grep-confirmed).")
print("            -> the Operator + ExploitGym legs would RUN against the private IP; only the")
print("               non-destructive guard() (boundary 4) applies. Containment here is CONVENTION,")
print("               not enforcement -- AEGIS_TARGET=<private IP> is accepted.")

# ---- BOUNDARY 3: RED-TEAM fail-closed authorization scope ----
print("\n[3] RED-TEAM  fail-closed in_scope() vs the RoE")
from authorization import Authorization, NotAuthorized
def roe(scope):
    return {"owner": "o", "engagement": "e", "approver": "a",
            "authorized_at": "2026-01-01", "expires_at": "2027-01-01",
            "scope": scope, "rules_of_engagement": {"allowed_actions": ["recon", "active"]}}
# 3a: the REAL RoE shape (scope = localhost/127.0.0.1) -- private IP NOT in it
real = Authorization(roe({"hosts": ["127.0.0.1", "localhost"]}))
for t in PRIVATE_TARGETS:
    print("    real RoE (localhost only): in_scope(%s) = %s  %s"
          % (t, real.in_scope(t), "-> REFUSE (boundary FIRES)" if not real.in_scope(t) else "-> allowed"))
# 3b: a BROAD RoE (a careless cidr) -- private IP passes
broad = Authorization(roe({"cidrs": ["172.16.0.0/12"]}))
print("    broad RoE (cidr 172.16.0.0/12): in_scope(172.18.51.204) = %s  %s"
      % (broad.in_scope("172.18.51.204"),
         "-> allowed (a permissive RoE lets the private IP through!)" if broad.in_scope("172.18.51.204") else "-> refuse"))
# 3c: empty scope -> fail-closed at load
try:
    Authorization(roe({}))
    print("    empty scope: LOADED (BAD)")
except NotAuthorized as e:
    print("    empty scope: REFUSED at load -> %s" % str(e)[:60])

# ---- BOUNDARY 4: non-destructive guard (target-agnostic) ----
print("\n[4] NON-DESTRUCTIVE guard()  (applies in EVERY mode, target-agnostic)")
import test_suggestions as TS
for cmd in ["curl https://172.18.51.204:8443/api/jobs", "rm -rf /data", "DELETE FROM users",
            "curl -X DELETE https://172.18.51.204/api/x"]:
    ok, why = TS.guard(cmd)
    print("    guard(%-48s) -> %s%s" % (cmd[:48], "PASS" if ok else "BLOCK", "" if ok else " (%s)" % why[:40]))

print("\n" + "=" * 70)
print("SUMMARY -- what fires when the suite hits the private mirror IP (operator unaware):")
print("  * RFC1918 detection ............ NONE (no boundary knows/says it's private)")
print("  * Operator/ExploitGym scope .... NONE (runs against it; only non-destructive guard applies)")
print("  * Red-Team fail-closed scope ... FIRES -> REFUSE, iff the IP is not in the RoE")
print("                                   (real RoE=localhost -> refused; a broad-CIDR RoE -> would pass)")
print("  * Non-destructive guard ........ FIRES on destructive verbs, in all modes, target-agnostic")
print("=" * 70)
