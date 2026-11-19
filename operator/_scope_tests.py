#!/usr/bin/env python3
"""Offline tests for the scope-file authorization gate (TRUST). No network/Kali/LLM.
Run: python operator/_scope_tests.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ensure a clean env (no inherited scope config)
for k in ("AEGIS_SCOPE_FILE", "AEGIS_SCOPE_ENFORCE"):
    os.environ.pop(k, None)

import scope  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

# --- host_of ---
ok("host_of strips scheme+port+path", scope.host_of("https://mirror.internal:8443/x?y=1") == "mirror.internal")
ok("host_of bare host:port", scope.host_of("10.0.0.5:8080") == "10.0.0.5")
ok("host_of strips userinfo", scope.host_of("http://user:pw@example.com/") == "example.com")
ok("host_of bracketed ipv6", scope.host_of("http://[::1]:8443/") == "::1")
ok("host_of empty", scope.host_of("") == "")

# --- containment default (no explicit entry) ---
contained = {"authorized": [], "allow_public": False}
ok("loopback contained by default", scope.in_scope("https://127.0.0.1:8443", contained)[0])
ok("localhost contained by default", scope.in_scope("https://localhost:8443", contained)[0])
ok("rfc1918 10.x contained", scope.in_scope("http://10.2.3.4/", contained)[0])
ok("rfc1918 192.168 contained", scope.in_scope("http://192.168.1.10/", contained)[0])
ok("public host refused by default", not scope.in_scope("https://example.com/", contained)[0])
ok("public IP refused by default", not scope.in_scope("http://8.8.8.8/", contained)[0])
# link-local is NOT contained: cloud-metadata SSRF surface must be explicit, not default-allowed
ok("cloud-metadata 169.254.169.254 blocked by default", not scope.in_scope("http://169.254.169.254/latest/meta-data/", contained)[0])
ok("ipv6 link-local fe80:: blocked by default", not scope.in_scope("http://[fe80::1]/", contained)[0])
_meta_ok = {"authorized": ["169.254.169.254"], "allow_public": True}
ok("link-local honored only when explicitly listed + allow_public", scope.in_scope("http://169.254.169.254/", _meta_ok)[0])

# --- explicit entries ---
sc = {"authorized": ["mirror.internal", "203.0.113.0/24"], "allow_public": True}
ok("explicit public host honored w/ allow_public", scope.in_scope("https://mirror.internal/", sc)[0])
ok("explicit public CIDR honored w/ allow_public", scope.in_scope("http://203.0.113.9/", sc)[0])
ok("public host NOT listed still refused", not scope.in_scope("http://1.1.1.1/", sc)[0])

sc_noguard = {"authorized": ["example.com"], "allow_public": False}
ok("public host listed but allow_public false -> refused",
   not scope.in_scope("https://example.com/", sc_noguard)[0])

# --- wildcards never honored ---
sc_wild = {"authorized": ["*", "*.evil.com", "*.internal"], "allow_public": True}
ok("wildcard entry does not authorize a public host", not scope.in_scope("https://a.evil.com/", sc_wild)[0])
ok("wildcard does not override containment refusal", not scope.in_scope("https://x.internal/", sc_wild)[0])

# --- load_scope + integrity ---
d = tempfile.mkdtemp()
good = os.path.join(d, "scope.json")
written = scope.write_scope(good, ["127.0.0.1", "10.0.0.0/8"], allow_public=False)
ok("write_scope signs with sha256", "sha256" in written)
ok("load_scope reads a signed file", scope.load_scope(good)["authorized"][0] == "127.0.0.1")

tampered = os.path.join(d, "tampered.json")
import json
obj = dict(written); obj["authorized"] = obj["authorized"] + ["8.8.8.8"]   # add host, keep old hash
with open(tampered, "w") as fh: json.dump(obj, fh)
try:
    scope.load_scope(tampered); ok("tampered scope rejected", False)
except scope.ScopeError:
    ok("tampered scope rejected", True)

try:
    scope.load_scope(os.path.join(d, "nope.json")); ok("missing scope file rejected", False)
except scope.ScopeError:
    ok("missing scope file rejected", True)

# --- check_move (block-contract) + enforce ---
sc2 = scope.load_scope(good)
ok("check_move allows in-scope base", scope.check_move({"path": "/"}, "https://127.0.0.1:8443", sc2)[0])
ok("check_move blocks out-of-scope base",
   not scope.check_move({"path": "/"}, "https://evil.com", sc2)[0])
ok("check_move blocks stray move.target off-base",
   not scope.check_move({"target": "http://8.8.8.8"}, "https://127.0.0.1:8443", sc2)[0])
ok("check_move allows in-scope move.target", scope.check_move({"target": "http://10.9.9.9"}, "https://127.0.0.1", sc2)[0])

try:
    scope.enforce("https://evil.com", sc2); ok("enforce raises on out-of-scope", False)
except scope.ScopeError:
    ok("enforce raises on out-of-scope", True)
scope.enforce("https://127.0.0.1:8443", sc2)  # should not raise
ok("enforce passes in-scope base", True)

# --- inert when unconfigured; fail-closed under enforce-mode ---
ok("check_move inert with no scope + no enforce", scope.check_move({"path": "/"}, "https://anything.com", None)[0])
os.environ["AEGIS_SCOPE_ENFORCE"] = "1"
ok("check_move fail-closed under enforce-mode w/ no file",
   not scope.check_move({"path": "/"}, "https://127.0.0.1", None)[0])
try:
    scope.enforce("https://127.0.0.1", None); ok("enforce fail-closed under enforce-mode", False)
except scope.ScopeError:
    ok("enforce fail-closed under enforce-mode", True)
os.environ.pop("AEGIS_SCOPE_ENFORCE", None)

n = 33
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
