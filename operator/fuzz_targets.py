#!/usr/bin/env python3
"""fuzz_targets.py -- AUTOMATED fuzz entry-point discovery from source (the piece fuzz_driver.py was
missing). fuzz_driver drives a grey-box campaign but consumed a HAND-WRITTEN target list; this scans a
buildable source tree and emits the candidate entry points automatically -- the AIxCC-style
"auto-harness" front end, defensive: you fuzz your OWN code's untrusted-input boundaries before an
attacker does.

It ranks functions by attack-surface VALUE: names that suggest an untrusted-input boundary
(parse/decode/deserialize/load/render/...) and signatures that take bytes/strings/streams/paths. Output
is the exact JSON fuzz_driver.py --targets expects: [{target, function, language, file, line, value}].

Pure static analysis (Python via `ast`; C/C++/JS/TS/Go/Java/Rust via conservative regex). No build, no
network, no target action -- safe to run anywhere on source you own.

    python fuzz_targets.py <src-dir> --out targets.json
    python fuzz_driver.py --source <src-dir> --dry        # (driver can call this directly)
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re

# name tokens that mark an untrusted-input boundary (high yield to fuzz)
HIGH_VALUE = ("parse", "decode", "deserial", "unmarshal", "unpack", "load", "read", "import",
              "convert", "render", "eval", "exec", "expand", "inflate", "unzip", "decompress",
              "xml", "json", "yaml", "regex", "handle", "process", "ingest", "scan", "tokeni",
              "lex", "interpret", "deserialize", "fromstring", "frombytes", "b64", "base64")
# param name / type hints that mean "takes untrusted input"
INPUT_HINTS = ("data", "buf", "buffer", "input", "payload", "text", "raw", "content", "body",
               "msg", "message", "stream", "path", "file", "bytes", "str", "req", "request",
               "packet", "frame", "blob", "src", "chunk", "token", "arg", "value")

EXT_LANG = {".py": "python", ".c": "c++", ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".h": "c++",
            ".hpp": "c++", ".hh": "c++", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
            ".go": "go", ".java": "java", ".rs": "rust"}

_SKIP_DIRS = {".git", "__pycache__", "node_modules", "vendor", "dist", "build", ".venv", "venv",
              "test", "tests", "__tests__", "testdata", "fixtures", "third_party", "site-packages"}


def _name_value(name: str) -> int:
    return 2 if any(k in (name or "").lower() for k in HIGH_VALUE) else 0


def _params_take_input(params: str) -> bool:
    p = (params or "").lower()
    return any(re.search(r"\b" + re.escape(h) + r"\b", p) for h in INPUT_HINTS)


def _score(name: str, params: str) -> int:
    v = 1 + _name_value(name) + (1 if _params_take_input(params) else 0)
    return v


# ---------------- language extractors: (name, params_str, lineno) ----------------
def _py(src: str):
    try:
        tree = ast.parse(src)
    except Exception:
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = ", ".join(
                (a.arg + (":" + ast.unparse(a.annotation) if getattr(a, "annotation", None) else ""))
                for a in node.args.args)
            yield node.name, params, node.lineno


_C_RE = re.compile(r"(?m)^[\w \t\*&:<>]+?\b([A-Za-z_]\w+)\s*\(([^;{)]*)\)\s*\{")
_JS_FN = re.compile(r"(?m)\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
_JS_ARROW = re.compile(r"(?m)\b([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?\(([^)]*)\)\s*=>")
_GO_RE = re.compile(r"(?m)^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)")
_JAVA_RE = re.compile(r"(?m)^\s*(?:public|private|protected|static|final|\s)+[\w<>\[\].]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:throws[\w,\s]+)?\{")
_RUST_RE = re.compile(r"(?m)^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)")

_RE_LANG = {"c++": _C_RE, "go": _GO_RE, "java": _JAVA_RE, "rust": _RUST_RE}
_SKIP_NAMES = {"if", "for", "while", "switch", "catch", "return", "sizeof", "main", "printf"}


def _regex_lang(src: str, rx: re.Pattern):
    for m in rx.finditer(src):
        name = m.group(1)
        if name in _SKIP_NAMES:
            continue
        line = src.count("\n", 0, m.start()) + 1
        yield name, m.group(2), line


def _js(src: str):
    for rx in (_JS_FN, _JS_ARROW):
        for m in rx.finditer(src):
            name = m.group(1)
            if name in _SKIP_NAMES:
                continue
            line = src.count("\n", 0, m.start()) + 1
            yield name, m.group(2), line


def extract(src: str, language: str):
    if language == "python":
        yield from _py(src)
    elif language == "js":
        yield from _js(src)
    elif language in _RE_LANG:
        yield from _regex_lang(src, _RE_LANG[language])


def discover(root: str, min_value: int = 2, limit: int = 0, include_all: bool = False) -> list:
    """Scan a source tree and return ranked fuzz candidates: [{target,function,language,file,line,value}]."""
    out = []
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            lang = EXT_LANG.get(os.path.splitext(fn)[1].lower())
            if not lang:
                continue
            path = os.path.join(dp, fn)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            for name, params, line in extract(src, lang):
                v = _score(name, params)
                if not include_all and v < min_value:
                    continue
                out.append({"target": f"{rel}:{name}", "function": name, "language": lang,
                            "file": rel, "line": line, "value": v})
    # de-dup by target, keep highest value; rank by value then file
    best = {}
    for c in out:
        k = c["target"]
        if k not in best or c["value"] > best[k]["value"]:
            best[k] = c
    ranked = sorted(best.values(), key=lambda c: (-c["value"], c["file"], c["line"]))
    return ranked[:limit] if limit else ranked


def main():
    ap = argparse.ArgumentParser(description="auto-discover fuzzable entry points from source (feeds fuzz_driver)")
    ap.add_argument("root", help="source tree to scan (buildable source you own)")
    ap.add_argument("--min-value", type=int, default=2, help="min attack-surface score (1=all, 2=input-boundary, 3=named+input)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--all", action="store_true", help="include every function, not just the attack surface")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    cands = discover(a.root, min_value=a.min_value, limit=a.limit, include_all=a.all)
    js = json.dumps(cands, indent=2)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(js)
        by_lang = {}
        for c in cands:
            by_lang[c["language"]] = by_lang.get(c["language"], 0) + 1
        print(f"wrote {len(cands)} fuzz candidates -> {a.out}  ({by_lang})")
    else:
        print(js)


if __name__ == "__main__":
    main()
