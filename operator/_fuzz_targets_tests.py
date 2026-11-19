#!/usr/bin/env python3
"""Offline tests for fuzz_targets.discovery -- synthetic source per language, no build/network.
Run: python operator/_fuzz_targets_tests.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fuzz_targets as FT  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

# --- unit: scoring ---
ok("high-value name scores >=3 with input param", FT._score("parse_config", "data: bytes") >= 3)
ok("plain name + no input param scores 1", FT._score("helper", "x, y") == 1)
ok("input param alone bumps score", FT._score("helper", "payload") == 2)

# --- python extraction ---
py = '''
def parse_message(data: bytes):
    return data
def _internal(x, y):
    return x + y
async def handle_request(body):
    return body
class C:
    def render_template(self, content):
        return content
'''
names = {n for n, _, _ in FT.extract(py, "python")}
ok("py finds parse_message", "parse_message" in names)
ok("py finds async handle_request", "handle_request" in names)
ok("py finds method render_template", "render_template" in names)

# --- C/C++ ---
c = '''
int helper(int a) { return a; }
size_t decode_frame(const uint8_t *buf, size_t len) { return len; }
void main() {}
'''
cnames = {n for n, _, _ in FT.extract(c, "c++")}
ok("c++ finds decode_frame", "decode_frame" in cnames)
ok("c++ skips main", "main" not in cnames)

# --- JS ---
js = '''
function parseToken(input) { return input; }
const loadConfig = (path) => path;
'''
jn = {n for n, _, _ in FT.extract(js, "js")}
ok("js finds function parseToken", "parseToken" in jn)
ok("js finds arrow loadConfig", "loadConfig" in jn)

# --- Go ---
go = 'func DecodePacket(b []byte) error { return nil }\nfunc noop() {}\n'
gn = {n for n, _, _ in FT.extract(go, "go")}
ok("go finds DecodePacket", "DecodePacket" in gn)

# --- end-to-end discover() over a temp tree, ranking + min_value filter ---
d = tempfile.mkdtemp()
open(os.path.join(d, "a.py"), "w").write(py)
open(os.path.join(d, "b.c"), "w").write(c)
os.makedirs(os.path.join(d, "tests"), exist_ok=True)
open(os.path.join(d, "tests", "t.py"), "w").write("def parse_should_be_skipped(data): pass")
cands = FT.discover(d)
tgts = {c["function"] for c in cands}
ok("discover finds parse_message + decode_frame", {"parse_message", "decode_frame"} <= tgts)
ok("discover ranks high-value first", cands[0]["value"] >= 2)
ok("discover skips tests/ dir", "parse_should_be_skipped" not in tgts)
ok("discover emits fuzz_driver shape", all({"target","function","language","file","value"} <= set(c) for c in cands))
ok("min_value filter drops plain helpers", "_internal" not in tgts and "helper" not in tgts)

n = 18
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
