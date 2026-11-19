#!/usr/bin/env python3
"""Offline tests for the fuzz-depth enhancements: package-dep mode + structure-aware harness + depth seeds.
No Kali/npm/LLM. Run: python operator/_fuzz_enh_tests.py"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

# --- seed_gen.depth_seeds ---
import seed_gen
ds = seed_gen.depth_seeds(depths=(64, 3600))
ok("depth_seeds returns seeds", isinstance(ds, list) and len(ds) == 4)
ok("depth_seeds has a length ramp to 3600", (b"A" * 3600) in ds)
ok("depth_seeds has nested-json of depth 64", any(s.startswith(b'{"a":' * 64) for s in ds))

# --- corpus routing (the JS depth-seed miss): JS -> project ./corpus, else base-runner dir ---
ok("corpus_dir js -> project ./corpus (Jazzer reads this)", seed_gen._corpus_dir("p", "harness", js=True).endswith("/projects/p/corpus"))
ok("corpus_dir non-js -> base-runner dir", seed_gen._corpus_dir("p", "harness", js=False).endswith("/corpus/p/harness"))

# --- _npm_install_cmd (package-dep mode) ---
import fuzz_driver as FD
ok("npm cmd pins pkg@version", FD._npm_install_cmd("deepmerge-ts", "7.1.5").endswith("deepmerge-ts@7.1.5"))
ok("npm cmd no-version", FD._npm_install_cmd("lodash").endswith("lodash"))
ok("npm cmd is an install", FD._npm_install_cmd("x", "1").startswith("npm i "))
ok("npm cmd shell-quotes an unsafe spec", "'" in FD._npm_install_cmd("a;rm -rf/", "1"))

# --- synth_harness prompt: inject a fake code_suggester to capture the task ---
captured = {}
fake = types.ModuleType("code_suggester")
def _suggest(model, task, **kw):
    captured["task"] = task
    return "```js\nexport function fuzz(d){ return d; }\n```"
fake.suggest = _suggest
sys.modules["code_suggester"] = fake

FD.synth_harness({"function": "deepMerge", "package": "deepmerge-ts", "language": "js"}, "js")
ok("depth target -> DEPTH rule in prompt", "DEPTH / RESOURCE" in captured["task"])
ok("merge target -> multi-arg OVERLAP rule", "MULTI-ARG MERGE" in captured["task"] and "OVERLAP" in captured["task"])
ok("package target -> import-from-package rule", "deepmerge-ts" in captured["task"] and "import" in captured["task"].lower())

FD.synth_harness({"function": "parseDeepConfig", "language": "js"}, "js")
ok("non-merge depth target -> DEPTH but NO merge rule",
   "DEPTH / RESOURCE" in captured["task"] and "MULTI-ARG MERGE" not in captured["task"])

FD.synth_harness({"function": "getUserName", "language": "js"}, "js")
ok("plain target -> NO depth rule", "DEPTH / RESOURCE" not in captured["task"])
ok("plain target -> NO package rule", "import ... from" not in captured["task"])

# --- JS entry-name: prompt pins Jazzer.js `fuzz`, accept-check rejects the C name ---
ok("js prompt pins export function fuzz", "export function fuzz(data)" in captured["task"])
ok("js prompt forbids the C entry name", "Do NOT name it LLVMFuzzerTestOneInput" in captured["task"])
ok("accept: good JS harness (export fuzz)", FD._harness_has_entry("export function fuzz(d){ deepmerge(d,d) }", "js"))
ok("reject: JS harness with C entry name", not FD._harness_has_entry("export function LLVMFuzzerTestOneInput(d){}", "js"))
ok("accept: python Atheris TestOneInput", FD._harness_has_entry("def TestOneInput(data):\n    pass", "python"))
ok("accept: c++ LLVMFuzzerTestOneInput", FD._harness_has_entry('extern "C" int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}', "c++"))

n = 21
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
