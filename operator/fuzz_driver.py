# -*- coding: utf-8 -*-
"""AEGIS -- FUZZ DRIVER: the adaptive "driver seat" for the grey-box fuzzing campaign (the fuzzer analogue of
code_driver). fuzzer.py is the MECHANISM (scaffold/build/run/triage) and the engine drives INPUT mutation
(coverage-guided), but today nothing drives the CAMPAIGN at the harness/target level: harnesses are hand-
filled templates and iterative_hunt just dispatches `fuzz` as a vector. This module is that missing driver.

Loop (budget split across TARGETS, breadth-first over the least-explored / highest-value entry points):
    SELECT next target entry-point   (novelty: not-yet-harnessed; bias to parsers/decoders/deserializers/
                                       sinks -- the high-yield attack surface)
      -> SYNTHESIZE a harness for that REAL function (the code bench fills fuzzer.py's harness template; on a
         REFINE the prior harness + BUILD/coverage error are fed back so the bench fixes it)
      -> scaffold -> build -> run for a time slice   (fuzzer.py, contained in Kali/Docker)
      -> READ coverage + crashes; REPRODUCE crashes (the oracle -- a crash counts only when it reproduces)
      -> DECIDE {extend time | refine harness | new target | done}; write back reproduced crashes as findings,
         per-harness coverage, and the harness itself (reusable) -> redirect budget to the next target.

Budget = harness attempts; each harness gets a fuzz time-slice; low-coverage or non-building harnesses are
refined once (error fed back) then abandoned for a new target. Doctrine: CONTAINED (Docker inside Kali),
NON-DESTRUCTIVE (throwaway container, never the real target), a crash is EVIDENCE only when it REPRODUCES.
`--dry` simulates build/run/coverage/crash so the loop is testable without Kali/Docker/OSS-Fuzz."""
import argparse
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
LEDGER = os.path.join(HERE, "fuzz_driver_ledger.db")

BENCH_WRITERS = ["qwen2.5-coder-32b", "ds", "kimi-k2.7-code"]     # harness synthesis (code bench)
# high-yield surface priors: functions whose names suggest an untrusted-input boundary
_HIGH_VALUE = ("parse", "decode", "deserial", "unmarshal", "load", "read", "import", "convert",
               "render", "eval", "exec", "expand", "inflate", "unzip", "xml", "json", "yaml", "regex")


def _value(fn):
    n = (fn or "").lower()
    return 2 if any(k in n for k in _HIGH_VALUE) else 1


# ---------------- ledger ----------------
def connect(db=LEDGER):
    c = sqlite3.connect(db, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""CREATE TABLE IF NOT EXISTS harnesses(
        target TEXT PRIMARY KEY, function TEXT, language TEXT, status TEXT DEFAULT 'selected',
        attempts INTEGER DEFAULT 0, coverage REAL DEFAULT 0.0, crashes INTEGER DEFAULT 0,
        reproduced INTEGER DEFAULT 0, harness TEXT, error TEXT, value INTEGER DEFAULT 1, updated REAL)""")
    c.commit()
    return c


def _done_targets(con):
    return {r[0] for r in con.execute("SELECT target FROM harnesses WHERE status IN ('done','dead','fuzzed')")}


def _record(con, t, status, **kw):
    cols = dict(kw); cols["status"] = status; cols["updated"] = time.time()
    con.execute("INSERT INTO harnesses(target,function,language,value) VALUES(?,?,?,?) "
                "ON CONFLICT(target) DO NOTHING",
                (t["target"], t.get("function"), t.get("language", "c++"), _value(t.get("function"))))
    sets = ", ".join(f"{k}=?" for k in cols) + ", attempts=attempts+1"
    con.execute(f"UPDATE harnesses SET {sets} WHERE target=?", list(cols.values()) + [t["target"]])
    con.commit()


def stats(con):
    return dict(con.execute("SELECT status,count(*) FROM harnesses GROUP BY status").fetchall())


# ---------------- steps (real, with dry fallbacks) ----------------
def select_target(candidates, done):
    """pick the next UN-harnessed target, highest attack-surface value first (novelty = not yet done)."""
    todo = [c for c in candidates if c["target"] not in done]
    if not todo:
        return None
    return sorted(todo, key=lambda c: -_value(c.get("function")))[0]


def _harness_has_entry(src, language):
    """Accept-check: does the synthesized harness define the RIGHT entry point for its engine? JS/Jazzer.js
    needs an exported `fuzz` (NOT the C name LLVMFuzzerTestOneInput -- Jazzer refuses to load without `fuzz`,
    and the old whitelist actively nudged the bench toward the C name on JS targets). Atheris needs
    TestOneInput; libFuzzer needs LLVMFuzzerTestOneInput."""
    import re
    s = src or ""
    if language in ("js", "ts"):
        return (bool(re.search(r"\bfuzz\b", s, re.I)) and ("export" in s or "module.exports" in s)
                and "LLVMFuzzerTestOneInput" not in s)
    if language == "python":
        return "TestOneInput" in s
    return "LLVMFuzzerTestOneInput" in s


def synth_harness(target, language, prior=None, error=None, dry=False):
    """CODE BENCH synthesizes a fuzz harness for the REAL entry point (fills fuzzer.py's template). On a
    REFINE, the prior harness + build/coverage error are fed back so the bench fixes it."""
    if dry:
        return f"// harness for {target.get('function')} ({language})\n// LLVMFuzzerTestOneInput -> call target\n"
    import code_suggester
    task = (f"Write a coverage-guided FUZZ HARNESS ({language}) for OSS-Fuzz tooling that exercises ONE entry "
            f"point of the target with fuzzer-provided bytes. Fill a real call to the function under test.\n"
            f"TARGET: {json.dumps(target)}\n"
            "CRITICAL HARNESS RULES (a wrong harness reports a crashable target as clean):\n"
            "1) Do NOT wrap the target call in a catch-all try/catch that swallows or logs the exception -- the "
            "harness MUST let an unexpected exception/crash PROPAGATE so the engine (Jazzer/libFuzzer/ASan) "
            "records it as a finding. If the function has a KNOWN input-validation error for malformed input "
            "that is NOT a bug, catch ONLY that specific expected error type and RE-THROW everything else.\n"
            "2) Match the target's MODULE SYSTEM exactly: for JS/TS use ESM `import` when the scaffold's "
            "package.json has \"type\":\"module\", and CommonJS `require` otherwise -- a mismatch fails the build.\n"
            "3) Feed the fuzzer bytes straight into the entry point (decode/parse them as the function expects); "
            "do not pre-validate or filter the input.\n"
            "Return ONLY the harness source (a CODE block).\n")
    _fn = str(target.get("function", "")).lower()
    _depth = bool(target.get("depth")) or any(k in _fn for k in
             ("merge", "parse", "deep", "nest", "recur", "clone", "flatten", "walk", "traverse", "unmarshal"))
    _merge = any(k in _fn for k in ("merge", "combine", "assign", "extend", "reduce", "concat", "zip",
                                    "mix", "defaults", "coalesce"))
    if _depth:
        task += ("4) DEPTH / RESOURCE-EXHAUSTION: this entry point recurses/merges/parses nested input, so "
                 "the harness MUST derive a NESTED structure whose DEPTH scales with the fuzzer input LENGTH "
                 "(e.g. depth = len(input): build a chain of that many nested objects/arrays and pass THAT in). "
                 "Flat bytes never grow recursion depth and coverage-guided fuzzing is blind to depth, so "
                 "longer input MUST mean deeper structure for a stack-exhaustion / quadratic bug to fire.\n")
    if _depth and _merge:
        task += ("4b) MULTI-ARG MERGE/COMBINE: this function recurses over the OVERLAP of its arguments, so the "
                 "harness MUST pass TWO (or N) SEPARATE deeply-nested structures that OVERLAP -- the SAME key at "
                 "EVERY level (e.g. a = {x:{x:{x:...}}} and b = {x:{x:{x:...}}}, BOTH depth = len(input)) -- and "
                 "merge THEM together. Merging a deep object with {} or a shallow one never recurses and never "
                 "overflows, so it MUST be two overlapping deep structures.\n")
    if target.get("package"):
        task += (f"5) IMPORT the function under test from the installed package '{target['package']}' using the "
                 f"export style the package documents -- a NAMED import matching the function name "
                 f"(import {{ {target.get('function','fn')} }} from '{target['package']}') UNLESS it is the "
                 f"package's DEFAULT export; do not assume a default export. NOT a local ./target file.\n")
    if language in ("js", "ts"):
        task += ("6) ENTRY POINT: Jazzer.js requires EXACTLY `export function fuzz(data)` (data is a "
                 "Buffer/Uint8Array; may be async). Do NOT name it LLVMFuzzerTestOneInput or TestOneInput -- "
                 "those are C/JVM conventions and Jazzer.js REFUSES to load a module that doesn't export `fuzz`.\n")
    elif language == "python":
        task += ("6) ENTRY POINT: Atheris requires `def TestOneInput(data):` then "
                 "`atheris.Setup(sys.argv, TestOneInput); atheris.Fuzz()`.\n")
    else:
        task += ("6) ENTRY POINT: libFuzzer requires "
                 "`extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.\n")
    if prior and error:
        task += f"\nYOUR PREVIOUS harness failed to build/cover. Fix it.\nPREV:\n{prior[:1200]}\nERROR:\n{error[:600]}\n"
    for m in BENCH_WRITERS:
        try:
            out = code_suggester.suggest(m, task, max_tokens=1400, temperature=0.3)
            if out and _harness_has_entry(out, language):
                return out
        except Exception:
            continue
    return None


def _seeds_from_reach(t):
    """Turn a candidate's symbolic_reach reaching-input (z3-solved) into fuzzer corpus seeds (bytes),
    so the fuzzer STARTS from an input that reaches the sink instead of discovering it blindly."""
    ri = t.get("reaching_input")
    if not isinstance(ri, dict):
        return []
    return [v.encode("utf-8", "replace") for v in ri.values() if isinstance(v, str) and v]


def _kali_write(path, content):
    """Write a text file INTO the Kali workspace. Host-side Python drives Kali, so a host open() on a
    '/opt/...' path hits the WRONG filesystem (on Windows: C:\\opt\\...) and the file never reaches the
    sandbox. Route through fuzzer._kali via a base64 pipe (same trick scaffold uses; no quoting issues)."""
    import base64, shlex, fuzzer
    b = base64.b64encode((content or "").encode()).decode()
    return fuzzer._kali(f"echo {b} | base64 -d > {shlex.quote(path)}", 120)


def _npm_install_cmd(pkg, version=None):
    """Shell cmd to install a REAL dependency (with its full module graph) into the JS scaffold. The
    single-file copy path can't fuzz a package whose bug is deeper than one file, and a bare
    `npm i @jazzer.js/core` PRUNES a copied-but-undeclared dep (ERR_MODULE_NOT_FOUND at fuzz time).
    Installing the package proper fixes both."""
    import shlex
    spec = pkg + ("@" + str(version) if version else "")
    return "npm i --no-audit --no-fund " + shlex.quote(spec)   # saves to package.json by default


def _js_replay_seeds(name, fuzzer_name, seeds):
    """Depth / resource-exhaustion CVEs (stack overflow, quadratic blowup): a coverage-guided CAMPAIGN
    cannot find them by construction -- libFuzzer won't GROW nesting depth (depth yields no new coverage)
    AND it REDUCE-minimizes seeded depth away (measured: ~34KB depth-seeds shrunk to ~194b before they
    overflow). So REPLAY each depth seed as a SINGLE-INPUT testcase (jazzer <fuzzer> <seedfile> -- no
    fuzzing, no minimization): an uncaught crash there IS the finding. Persist the crashing seed as a
    crash-* artifact in the project dir so drive()'s reproduce() re-confirms it. Returns [crash_id] or [].
    (Alternative: libFuzzer -runs=0 / -reduce_inputs=0, but explicit single-input replay is cleaner and
    deterministic -- proven on deepmerge-ts@7.1.5, GHSA-ggr8-5vv4-36mx.)"""
    import fuzzer, base64, shlex, hashlib
    pdir = fuzzer._proj_dir(name)
    for s in (seeds or []):
        h = hashlib.sha1(s).hexdigest()[:16]
        sp = pdir + "/replayseed-" + h
        fuzzer._kali("echo %s | base64 -d > %s" % (base64.b64encode(s).decode(), shlex.quote(sp)), 60)
        rep = fuzzer._js_reproduce(name, fuzzer_name, "replayseed-" + h)   # single-input replay (js-repro path)
        if rep.get("reproduced"):
            crash_id = "crash-" + h
            fuzzer._kali("cp %s %s" % (shlex.quote(sp), shlex.quote(pdir + "/" + crash_id)), 60)
            return [crash_id]
    return []


def run_harness(name, language, harness_src, seconds=120, dry=False, src_root=None, src_file=None,
                seeds=None, package=None, pkg_version=None, struct=False):
    """scaffold -> copy the module-under-test in -> write the synthesized harness -> build -> (optionally
    seed the corpus with symbolic_reach reaching-inputs) -> run a time-slice via fuzzer.py (Kali/Docker).
    Returns (built, coverage, crashes, error, fuzzer_name). fuzzer.* runs IN Kali; the harness + module are
    written via _kali (never a host open() on a Kali path)."""
    js = language in ("js", "ts")
    fzdef = "harness" if js else name
    if dry:
        import random
        built = random.random() < 0.8
        if not built:
            return (False, 0.0, [], "build error: undefined reference to target function", fzdef)
        cov = round(random.uniform(0.1, 0.9), 2)
        crashes = ["crash-%d" % random.randint(1000, 9999)] if random.random() < 0.3 else []
        return (True, cov, crashes, "", fzdef)
    import fuzzer
    try:
        fuzzer.scaffold(name, language=language)
        pdir = fuzzer._proj_dir(name)
        # 1) MODULE-UNDER-TEST: copy the real source file into the scaffold so the synthesized harness has
        #    something to import/call (JS: as target.js beside harness.js). Without this the auto-synth
        #    harness references a module that isn't there and the build fails.
        if js and package:
            # PACKAGE-DEP MODE: install the REAL dependency (full module graph) so the synthesized harness
            # can `import ... from '<package>'` -- fixes the single-file-copy prune (ERR_MODULE_NOT_FOUND).
            import shlex as _shlex
            fuzzer._kali(f"cd {_shlex.quote(pdir)} && {_npm_install_cmd(package, pkg_version)}", 300)
        elif js and src_root and src_file:
            host_mod = os.path.join(src_root, src_file.replace("/", os.sep))
            try:
                mod = open(host_mod, encoding="utf-8", errors="replace").read()
            except Exception:
                mod = ""
            if mod:
                _kali_write(pdir + "/target.js", mod)
        # 2) SYNTHESIZED HARNESS: harness.js for js (imports ./target.js); harness.cc/py otherwise.
        hfile = {"c++": "harness.cc", "python": "harness.py", "js": "harness.js"}.get(language, "harness.cc")
        _kali_write(pdir + "/" + hfile, _code_block(harness_src))
        b = fuzzer.build(name, language=language)
        if not b.get("ok"):
            return (False, 0.0, [], str(b)[:400], fzdef)
        fz = (b.get("fuzzers") or [fzdef])[0]
        corpus_seeds = list(seeds or [])
        if struct:                                  # depth/resource-exhaustion -> seed a depth gradient
            try:
                import seed_gen
                corpus_seeds += seed_gen.depth_seeds()
            except Exception:
                pass
        if corpus_seeds:                            # symbolic reaching-inputs + depth seeds -> corpus
            try:
                import seed_gen
                seed_gen.write_corpus(name, fz, corpus_seeds, js=js)   # JS -> project ./corpus (what Jazzer reads)
            except Exception:
                pass
        r = fuzzer.run(name, fz, seconds=seconds)      # run() auto-detects JS; no `language` kwarg
        crashes = r.get("crashes", []) or []
        # DEPTH / RESOURCE-EXHAUSTION FALLBACK (JS/struct only): coverage-guided fuzzing is structurally
        # blind to depth (won't grow it via mutation, and REDUCE-minimizes seeded depth away), so a campaign
        # over depth-seeds finds nothing. Replay the depth-seeds as SINGLE-INPUT testcases -- the
        # deterministic mode for these CVEs. Gated to struct depth targets; normal coverage-guided targets
        # are unchanged.
        if js and struct and not crashes:
            try:
                import seed_gen
                crashes = _js_replay_seeds(name, fz, seed_gen.depth_seeds())
            except Exception:
                pass
        return (True, float(r.get("coverage", 0.0) or 0.0), crashes, "", fz)
    except Exception as e:
        return (False, 0.0, [], "run error: " + str(e)[:200], fzdef)


def _code_block(text):
    import re
    m = re.search(r"```[a-z+]*\n(.*?)```", text or "", re.S)
    return m.group(1) if m else (text or "")


def reproduce(name, language, crashes, fuzzer_name=None, dry=False):
    """ORACLE: a crash counts only when it REPRODUCES. Returns the list of reproduced crash ids.
    The fuzzer NAME (not the project name) must be passed to fuzzer.reproduce -- for JS the built
    fuzzer is always 'harness', so `fuzzer.reproduce(name, name, c)` looked up the wrong target."""
    if dry:
        import random
        return [c for c in crashes if random.random() < 0.6]
    import fuzzer
    fz = fuzzer_name or ("harness" if language in ("js", "ts") else name)
    good = []
    for c in crashes:
        try:
            rep = fuzzer.reproduce(name, fz, c)
            if rep.get("reproduced"):
                good.append(c)
        except Exception:
            pass
    return good


def decide(built, coverage, reproduced, attempts):
    if reproduced:
        return "done"                       # reproduced crash -> finding, move on
    if not built and attempts < 2:
        return "refine"                     # feed the build error back once
    if built and coverage < 0.25 and attempts < 2:
        return "refine"                     # low coverage -> refine the harness once
    return "new"                            # otherwise take a fresh target


# ---------------- the drive loop ----------------
def drive(candidates, budget=12, per_harness_seconds=120, dry=False, source_root=None, struct=False):
    con = connect()
    findings = 0
    for step in range(1, budget + 1):
        done = _done_targets(con)
        t = select_target(candidates, done)
        if not t:
            print(f"  step {step}: no un-harnessed targets left -> stop"); break
        lang = t.get("language", "c++")
        prior = error = None
        for attempt in range(1, 4):
            harness = synth_harness(t, lang, prior, error, dry=dry)
            if not harness:
                _record(con, t, "dead", error="bench produced no harness"); break
            built, cov, crashes, err, fz = run_harness(t["target"], lang, harness, per_harness_seconds,
                                                        dry=dry, src_root=source_root, src_file=t.get("file"),
                                                        seeds=_seeds_from_reach(t),
                                                        package=t.get("package"), pkg_version=t.get("version"),
                                                        struct=struct or bool(t.get("depth")))
            repro = reproduce(t["target"], lang, crashes, fuzzer_name=fz, dry=dry) if crashes else []
            act = decide(built, cov, repro, attempt)
            print(f"  step {step}.{attempt} [{t['target']}:{t.get('function')}] built={built} cov={cov} "
                  f"crashes={len(crashes)} repro={len(repro)} -> {'FINDING' if repro else act}")
            if repro:
                _record(con, t, "done", coverage=cov, crashes=len(crashes), reproduced=len(repro), harness=harness)
                findings += 1; break
            if act == "refine":
                prior, error = harness, err; continue         # feed build/coverage error back to the bench
            _record(con, t, "fuzzed" if built else "dead", coverage=cov, crashes=len(crashes), harness=harness, error=err)
            break
    print(f"FUZZ DRIVER done: {findings} reproduced crash finding(s) over budget {budget}. ledger:", stats(con))
    con.close()
    return findings


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AEGIS adaptive fuzz driver (grey-box campaign)")
    ap.add_argument("--targets", help="JSON file: [{target,function,language,file}]; optional per-target "
                                      "{package,version} for package-dep mode and {depth:true} for structure-aware")
    ap.add_argument("--source", help="auto-discover fuzz targets from this source tree (via fuzz_targets.py)")
    ap.add_argument("--struct", action="store_true",
                    help="structure-aware: seed a depth gradient (seed_gen.depth_seeds) + instruct the bench to "
                         "scale nesting depth with input length -- for depth/resource-exhaustion CVEs (stack overflow)")
    ap.add_argument("--reach", action="store_true",
                    help="use symbolic_reach to re-rank sink-reaching targets AND seed the corpus with z3-solved reaching inputs")
    ap.add_argument("--budget", type=int, default=12)
    ap.add_argument("--seconds", type=int, default=120, help="fuzz time-slice per harness")
    ap.add_argument("--dry", action="store_true", help="simulate build/run/coverage/crash (no Kali/Docker)")
    a = ap.parse_args()
    if a.targets and os.path.exists(a.targets):
        cands = json.load(open(a.targets, encoding="utf-8"))
    elif a.source and os.path.isdir(a.source):
        import fuzz_targets
        cands = fuzz_targets.discover(a.source)
        if a.reach:
            try:
                import symbolic_reach
                cands = symbolic_reach.boost_candidates(cands, a.source)
                seeded = sum(1 for c in cands if c.get("reaching_input"))
                print(f"symbolic_reach: re-ranked by sink-reachability; {seeded} target(s) carry z3 reaching-input seeds")
            except Exception as e:
                print(f"symbolic_reach unavailable ({e}); proceeding without reachability boost")
        print(f"auto-discovered {len(cands)} fuzz targets from {a.source} (top by attack-surface value)")
    else:   # dry demo target set
        cands = [{"target": f"t{i}", "function": fn, "language": "c++"} for i, fn in enumerate(
            ["parse_config", "decode_frame", "handle_request", "deserialize_msg", "load_plugin",
             "render_template", "expand_macro", "read_header"])]
    _src_root = a.source if (a.source and os.path.isdir(a.source)) else None
    drive(cands, budget=a.budget, per_harness_seconds=a.seconds, dry=a.dry, source_root=_src_root, struct=a.struct)
