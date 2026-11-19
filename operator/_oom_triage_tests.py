#!/usr/bin/env python3
"""Offline tests for the OOM-class triage rule: an oom-* artifact must reproduce single-input (bounded
RSS) or auto-drop, so a cumulative/async-load OOM never reaches verified_findings. No Kali/docker/LLM.
Run: python operator/_oom_triage_tests.py

Fixtures mirror the peer's live cases:
  - exceljs oom-d09351a2 : cumulative async-load false positive -> single-input just throws, no OOM sig -> DROP
  - a real per-input libFuzzer OOM                              -> single-input shows OOM sig          -> KEEP
  - deepmerge-ts crash (crash-*, real per-input)               -> single-input shows crash sig        -> KEEP
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fuzzer as F  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

# --- artifact-name routing ---
ok("oom-* recognized as OOM artifact", F._is_oom_artifact("oom-d09351a2"))
ok("full path oom-* recognized", F._is_oom_artifact("/root/.../projects/ff/oom-abc123"))
ok("crash-* is NOT an OOM artifact", not F._is_oom_artifact("crash-deadbeef"))
ok("empty testcase not OOM", not F._is_oom_artifact(""))

# --- OOM signature detection ---
EXCELJS_CLEAN = ("Error: Can't find end of central directory : is this a zip file ?\n"
                 "    at Object.load (/root/ff-src/node_modules/exceljs/lib/xlsx/xlsx.js:...)\n"
                 "RC:1\n---tail---\n(rss ~80MB, returned in 1ms)")
REAL_LIBFUZZER_OOM = ("==12== ERROR: libFuzzer: out-of-memory (used: 2145Mb; limit: 2048Mb)\n"
                      "   To change the out-of-memory limit use -rss_limit_mb=<N>\n"
                      "SUMMARY: libFuzzer: out-of-memory")
NODE_HEAP_OOM = ("<--- Last few GCs --->\nFATAL ERROR: ... JavaScript heap out of memory\n"
                 "FatalProcessOutOfMemory")
ok("exceljs clean throw has NO OOM signature", not F._oom_confirmed(EXCELJS_CLEAN))
ok("real libFuzzer OOM has OOM signature", F._oom_confirmed(REAL_LIBFUZZER_OOM))
ok("node heap OOM has OOM signature", F._oom_confirmed(NODE_HEAP_OOM))

# --- the decision rule ---
# OOM artifact + cumulative/async clean throw -> DROP
r, why = F._decide_reproduced("oom-d09351a2", 1, EXCELJS_CLEAN, infra_err=False, crash_sig=False, js=True)
ok("cumulative exceljs OOM auto-drops", (r is False) and "cumulative" in why)
# OOM artifact + real single-input OOM -> KEEP
r, why = F._decide_reproduced("oom-abc", 1, REAL_LIBFUZZER_OOM, infra_err=False, crash_sig=True, js=False)
ok("real single-input OOM kept", r is True)
r, why = F._decide_reproduced("oom-xyz", 1, NODE_HEAP_OOM, infra_err=False, crash_sig=False, js=True)
ok("real node-heap OOM kept (js)", r is True)
# OOM artifact + infra error -> DROP regardless
r, why = F._decide_reproduced("oom-abc", 1, "Cannot find module 'x'", infra_err=True, crash_sig=False, js=True)
ok("OOM artifact with infra error drops", r is False)

# --- crash-class contract preserved (regression guard) ---
DEEPMERGE = ("Uncaught Exception: RangeError: Maximum call stack size exceeded\n"
             "    at deepmergeInto (/root/ff-src/node_modules/deepmerge-ts/...)\n")
r, why = F._decide_reproduced("crash-deep", 77, DEEPMERGE, infra_err=False, crash_sig=True, js=True)
ok("deepmerge crash still reproduces (js, sig only)", r is True)
r, why = F._decide_reproduced("crash-cc", 1, "ERROR: AddressSanitizer: heap-buffer-overflow",
                              infra_err=False, crash_sig=True, js=False)
ok("base-runner crash: sig + non-zero exit kept", r is True)
r, why = F._decide_reproduced("crash-cc", 0, "ERROR: AddressSanitizer: heap-buffer-overflow",
                              infra_err=False, crash_sig=True, js=False)
ok("base-runner crash: zero exit dropped (existing contract)", r is False)
r, why = F._decide_reproduced("crash-x", 1, "/testcase not found", infra_err=True, crash_sig=False, js=False)
ok("crash infra error dropped", r is False)

# --- to_finding class + reproduced passthrough ---
fdrop = F.to_finding("ff", "xlsx_fuzzer", "oom-d09351a2",
                     {"reproduced": False, "repro_reason": "dropped", "trace_tail": EXCELJS_CLEAN})
ok("dropped OOM -> to_finding reproduced False (won't reach verified_findings)", fdrop["reproduced"] is False)
ok("OOM artifact classed resource-exhaustion", fdrop["vuln_class"] == "resource-exhaustion")
fkeep = F.to_finding("ff", "xlsx_fuzzer", "oom-real",
                     {"reproduced": True, "trace_tail": REAL_LIBFUZZER_OOM})
ok("real OOM -> to_finding reproduced True", fkeep["reproduced"] is True and fkeep["vuln_class"] == "resource-exhaustion")
fcrash = F.to_finding("ff", "dm_fuzzer", "crash-deep", {"reproduced": True, "trace_tail": DEEPMERGE})
ok("non-OOM crash keeps its class (not resource-exhaustion)", fcrash["vuln_class"] != "resource-exhaustion")

n = 20
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
