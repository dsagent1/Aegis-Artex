#!/usr/bin/env python3
"""symbolic_reach.py -- SYMBOLIC REACHABILITY: which fuzz entry points can actually REACH a dangerous
sink, under what input guards, and (via z3) a concrete input that satisfies those guards.

The depth gap this closes: fuzz_targets.py finds entry points and fuzz_driver.py fuzzes them, but blind
mutation wastes budget on inputs that never reach an interesting sink behind a guard (`if len(x)>100 and
x.startswith("PK")`). This module:
  1. builds a call graph from source (Python via ast; other langs best-effort) and a catalog of
     dangerous SINKS (code-exec / command / deserialize / sql / path / ssrf),
  2. reports source -> ... -> sink call paths (static reachability),
  3. extracts the INPUT-DEPENDENT guard predicates gating the sink, and
  4. asks z3 for a concrete input satisfying those guards -- a reaching SEED for the fuzzer, or UNSAT
     (the path is dead) / unknown (guards too complex to model).

Pure static analysis + a SAT query. No build, no execution, no target action -- safe on source you own.
z3 is OPTIONAL: reachability + guard extraction always work; solving is skipped cleanly if z3 is absent.

    python symbolic_reach.py <src-dir>                 # ranked reachable-to-sink report
    python symbolic_reach.py <src-dir> --json          # machine-readable, feeds fuzz_driver seeding
"""
from __future__ import annotations

import argparse
import ast
import json
import os

try:
    import z3
    _HAVE_Z3 = True
except Exception:
    _HAVE_Z3 = False

# dotted-name substring -> sink class (the dangerous operations worth reaching)
SINKS = [
    ("eval", "code-exec"), ("exec", "code-exec"), ("compile", "code-exec"),
    ("os.system", "command-exec"), ("os.popen", "command-exec"),
    ("subprocess", "command-exec"), ("commands.getoutput", "command-exec"),
    ("pickle.load", "deserialize"), ("pickle.loads", "deserialize"),
    ("yaml.load", "deserialize"), ("marshal.load", "deserialize"), ("__import__", "dynamic-import"),
    (".execute", "sql"), (".executescript", "sql"), (".executemany", "sql"), (".raw", "sql"),
    ("open", "file-io"), ("os.remove", "file-io"), ("shutil.", "file-io"),
    ("requests.", "ssrf"), ("urllib", "ssrf"), ("urlopen", "ssrf"), ("httpx.", "ssrf"),
]

_SKIP_DIRS = {".git", "__pycache__", "node_modules", "vendor", "dist", "build", ".venv", "venv",
              "tests", "test", "__tests__", "testdata", "site-packages"}


def _dotted(node) -> str:
    """best-effort dotted name for a Call's func (a.b.c)."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _sink_class(name: str):
    for pat, cls in SINKS:
        if pat in name:
            return cls
    return None


class _FuncScan:
    """intra-procedural scan: sink calls (with enclosing input-guards) + intra-project calls."""
    def __init__(self, params):
        self.params = set(params)
        self.sinks = []      # [(sink_name, cls, [guard_src,...])]
        self.calls = set()   # simple names called (call-graph edges)

    def _refs_param(self, test) -> bool:
        try:
            for n in ast.walk(test):
                if isinstance(n, ast.Name) and n.id in self.params:
                    return True
        except Exception:
            pass
        return False

    def walk(self, body, guards):
        for stmt in body:
            if isinstance(stmt, ast.If):
                g = ast.unparse(stmt.test)
                gp = guards + ([g] if self._refs_param(stmt.test) else [])
                self.walk(stmt.body, gp)
                gn = guards + (["not (%s)" % g] if self._refs_param(stmt.test) else [])
                self.walk(stmt.orelse, gn)
            else:
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Call):
                        name = _dotted(n.func)
                        cls = _sink_class(name)
                        if cls:
                            self.sinks.append((name, cls, list(guards)))
                        simple = name.split(".")[0] if name else ""
                        if simple:
                            self.calls.add(simple)
                            if "." in name:
                                self.calls.add(name.split(".")[-1])


def scan_python(src: str):
    """-> ({func: {'params':[...], 'sinks':[...], 'calls':set()}}, ok)"""
    try:
        tree = ast.parse(src)
    except Exception:
        return {}, False
    funcs = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in node.args.args]
            fs = _FuncScan(params)
            fs.walk(node.body, [])
            funcs[node.name] = {"params": params, "sinks": fs.sinks, "calls": fs.calls, "line": node.lineno}
    return funcs, True


def _solve(guards, params):
    """z3: find an input satisfying the input-guards. Returns (verdict, example|reason).
    verdict in {'sat','unsat','unknown','no-z3','no-guards'}."""
    if not guards:
        return "no-guards", ""
    if not _HAVE_Z3:
        return "no-z3", "install z3-solver to enable constraint solving"
    # model each param as a z3 String S and its length L; support numeric compare via an Int P too.
    S = {p: z3.String("s_" + p) for p in params}
    L = {p: z3.Length(S[p]) for p in params}
    P = {p: z3.Int("p_" + p) for p in params}
    s = z3.Solver()
    modeled = 0
    for g in guards:
        try:
            expr = ast.parse(g, mode="eval").body
            c = _to_z3(expr, S, L, P, params)
            if c is not None:
                s.add(c); modeled += 1
        except Exception:
            continue
    if modeled == 0:
        return "unknown", "guards present but not modelable (complex predicates)"
    r = s.check()
    if r == z3.sat:
        m = s.model()
        ex = {}
        for p in params:
            try:
                v = m.eval(S[p], model_completion=True)
                sv = v.as_string() if hasattr(v, "as_string") else str(v)
                if sv:
                    ex[p] = sv
            except Exception:
                pass
        return "sat", ex or {"note": "any input of a satisfying length"}
    if r == z3.unsat:
        return "unsat", "guards are contradictory -- sink path is unreachable (dead)"
    return "unknown", "z3 could not decide"


def _to_z3(node, S, L, P, params):
    """translate a small predicate grammar over an input param into a z3 constraint (or None)."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _to_z3(node.operand, S, L, P, params)
        return z3.Not(inner) if inner is not None else None
    if isinstance(node, ast.BoolOp):
        parts = [_to_z3(v, S, L, P, params) for v in node.values]
        parts = [p for p in parts if p is not None]
        if not parts:
            return None
        return z3.And(*parts) if isinstance(node.op, ast.And) else z3.Or(*parts)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, op, right = node.left, node.ops[0], node.comparators[0]
        # len(param) <op> int
        if (isinstance(left, ast.Call) and _dotted(left.func) == "len" and left.args
                and isinstance(left.args[0], ast.Name) and left.args[0].id in params
                and isinstance(right, ast.Constant) and isinstance(right.value, int)):
            return _cmp(L[left.args[0].id], op, right.value)
        # param <op> int   (numeric)
        if (isinstance(left, ast.Name) and left.id in params
                and isinstance(right, ast.Constant) and isinstance(right.value, int)):
            return _cmp(P[left.id], op, right.value)
        # param == / != "literal"
        if (isinstance(left, ast.Name) and left.id in params
                and isinstance(right, ast.Constant) and isinstance(right.value, str)):
            if isinstance(op, ast.Eq):
                return S[left.id] == z3.StringVal(right.value)
            if isinstance(op, ast.NotEq):
                return S[left.id] != z3.StringVal(right.value)
        # "literal" in param
        if (isinstance(op, ast.In) and isinstance(left, ast.Constant)
                and isinstance(left.value, str) and isinstance(right, ast.Name) and right.id in params):
            return z3.Contains(S[right.id], z3.StringVal(left.value))
    # param.startswith("x") / .endswith("x")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        m = node.func.attr
        base = node.func.value
        if (isinstance(base, ast.Name) and base.id in params and node.args
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            lit = z3.StringVal(node.args[0].value)
            if m == "startswith":
                return z3.PrefixOf(lit, S[base.id])
            if m == "endswith":
                return z3.SuffixOf(lit, S[base.id])
            if m == "__contains__":
                return z3.Contains(S[base.id], lit)
    return None


def _cmp(lhs, op, val):
    if isinstance(op, ast.Lt): return lhs < val
    if isinstance(op, ast.LtE): return lhs <= val
    if isinstance(op, ast.Gt): return lhs > val
    if isinstance(op, ast.GtE): return lhs >= val
    if isinstance(op, ast.Eq): return lhs == val
    if isinstance(op, ast.NotEq): return lhs != val
    return None


def analyze(root: str, max_depth: int = 6) -> list:
    """Scan a Python source tree; return reachable-to-sink entry points enriched with path/guards/solve."""
    per_file = {}
    defined = {}     # simple name -> (file, funcinfo)
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dp, fn)
            try:
                funcs, ok = scan_python(open(path, encoding="utf-8", errors="replace").read())
            except Exception:
                continue
            if not ok:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            per_file[rel] = funcs
            for name, info in funcs.items():
                defined.setdefault(name, (rel, info))
    # global call graph + sink map (by simple name; approximate across files)
    graph = {}
    sinkmap = {}
    for rel, funcs in per_file.items():
        for name, info in funcs.items():
            graph.setdefault(name, set()).update(c for c in info["calls"] if c in defined)
            if info["sinks"]:
                sinkmap.setdefault(name, []).extend((rel,) + s for s in info["sinks"])
    out = []
    for entry, (rel, info) in defined.items():
        # BFS entry -> sink-bearing function
        seen = {entry}; queue = [(entry, [entry])]; found = None
        while queue:
            cur, path = queue.pop(0)
            if cur in sinkmap:
                found = (cur, path); break
            if len(path) > max_depth:
                continue
            for nxt in graph.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt); queue.append((nxt, path + [nxt]))
        if not found:
            continue
        sink_fn, path = found
        srel, sname, scls, guards = sinkmap[sink_fn][0]
        # solve guards against the SINK function's params (accurate where entry==sink)
        sink_params = defined.get(sink_fn, (None, {"params": []}))[1].get("params", [])
        verdict, example = _solve(guards, sink_params)
        out.append({"entry": f"{rel}:{entry}", "function": entry, "file": rel, "line": info.get("line"),
                    "reaches_sink": True, "sink": sname, "sink_class": scls, "sink_at": srel,
                    "path": path, "guards": guards, "solve": verdict, "reaching_input": example})
    # rank: solvable-with-input first, then any-reachable, then sink severity
    sev = {"code-exec": 5, "command-exec": 5, "deserialize": 4, "sql": 4, "ssrf": 3, "dynamic-import": 3, "file-io": 2}
    out.sort(key=lambda c: (0 if c["solve"] == "sat" else 1, -sev.get(c["sink_class"], 1)))
    return out


def boost_candidates(cands: list, root: str) -> list:
    """Re-rank fuzz_targets candidates: those that reach a sink (and are z3-satisfiable) go first."""
    reach = {c["entry"]: c for c in analyze(root)}
    for c in cands:
        r = reach.get(c.get("target"))
        if r:
            c["reaches_sink"] = True
            c["sink"] = r["sink_class"]
            c["reaching_input"] = r.get("reaching_input")
            c["value"] = c.get("value", 1) + (3 if r["solve"] == "sat" else 2)
    cands.sort(key=lambda c: -c.get("value", 1))
    return cands


def main():
    ap = argparse.ArgumentParser(description="symbolic reachability: entry -> sink, guards, z3-solved reaching input")
    ap.add_argument("root")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = analyze(a.root)
    if a.json:
        print(json.dumps(res, indent=2)); return
    if not _HAVE_Z3:
        print("(z3 not installed -- reachability only; `pip install z3-solver` to enable solving)")
    print(f"reachable-to-sink entry points: {len(res)}\n")
    for c in res[:40]:
        arrow = " -> ".join(c["path"])
        print(f"[{c['sink_class']:12}] {c['entry']}  =>  {c['sink']}   solve={c['solve']}")
        if c["guards"]:
            print(f"     guards: {' && '.join(c['guards'])[:160]}")
        if c["solve"] == "sat" and c["reaching_input"]:
            print(f"     reaching input: {c['reaching_input']}")
        print(f"     path: {arrow}")


if __name__ == "__main__":
    main()
