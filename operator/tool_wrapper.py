#!/usr/bin/env python3
"""tool_wrapper.py -- auto-wrap on-demand Kali tools into STRUCTURED descriptors.

When kali_tool_extend installs a new binary, synthesize() derives an invocation
TEMPLATE + output PARSER + metadata and registers it in tool_wrappers.json, so the
operator can call the tool as a typed tool (kali_driver's run_tool) with normalized
output -- matching the turnkey feel of a pre-wrapped tool table while KEEPING our
unbounded, install-on-demand reach.

Three synthesis tiers (first usable wins):
  1. curated seed       -- hand-written templates for high-value tools (best quality)
  2. --help introspection -- detect a JSON/output flag + the input kind from the tool's
                          OWN help text (self-extending; needs no network)
  3. board fallback     -- ask the board for a template (FIXED slots only), low-confidence
If all fail -> a line-mode descriptor so the tool is still callable, just unparsed.

Doctrine: templates have FIXED {target}/{extra} slots only; models NEVER supply raw
shell -- they fill, or select from an allowlist. Board/help text is parsed into slots
and rejected if it carries shell operators. Contained tooling lane; audited.
"""
from __future__ import annotations
import json
import os
import re
import shlex
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(HERE, "tool_wrappers.json")
AUDIT_PATH = os.path.join(HERE, "tool_install_audit.jsonl")

_MAX_LINES = 500
_MAX_RAW = 60000

# Reject shell operators in anything a model/board supplies (slots are stripped first).
_METAS = re.compile(r"[;&|`$><\n\\]")
# Safe binary/tool name (mirrors kali_tool_extend._SAFE_TOOL).
_SAFE_TOOL = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


# --- tier 1: curated seed (correct, high-confidence templates for common tools) ---
# template is the FULL command with {target}/{extra} slots. Kept tight + verified.
_CURATED = {
    "nuclei":      {"input_kind": "url",  "template": "nuclei -silent -jsonl -u {target} {extra}",   "output_mode": "ndjson", "category": "web/scan",        "timeout": 900},
    "httpx":       {"input_kind": "url",  "template": "httpx -silent -json -u {target} {extra}",      "output_mode": "ndjson", "category": "web/probe",       "timeout": 300},
    "subfinder":   {"input_kind": "host", "template": "subfinder -silent -oJ -d {target} {extra}",    "output_mode": "ndjson", "category": "recon/subdomains","timeout": 300},
    "naabu":       {"input_kind": "host", "template": "naabu -silent -json -host {target} {extra}",   "output_mode": "ndjson", "category": "recon/ports",     "timeout": 600},
    "katana":      {"input_kind": "url",  "template": "katana -silent -jsonl -u {target} {extra}",    "output_mode": "ndjson", "category": "web/crawler",     "timeout": 600},
    "gau":         {"input_kind": "host", "template": "gau {target} {extra}",                         "output_mode": "lines",  "category": "recon/urls",      "timeout": 300},
    "waybackurls": {"input_kind": "host", "template": "waybackurls {target} {extra}",                 "output_mode": "lines",  "category": "recon/urls",      "timeout": 300},
    "dalfox":      {"input_kind": "url",  "template": "dalfox url {target} --format json {extra}",     "output_mode": "json",   "category": "web/xss",         "timeout": 600},
}

# --- tier 2: machine-readable output flags, ndjson-first then json. Longest/most
# specific first so '-jsonl' isn't shadowed by '-json'. Token matched as a whole flag. ---
_JSON_TOKENS = [
    ("-jsonl", "ndjson"), ("--jsonl", "ndjson"),
    ("-jsonlines", "ndjson"), ("--jsonlines", "ndjson"),
    ("-oJ", "ndjson"),
    ("-json", "json"), ("--json", "json"),
]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe(name) -> bool:
    return bool(isinstance(name, str) and _SAFE_TOOL.match(name))


def _strip_ansi(s: str) -> str:
    return _ANSI.sub("", s or "")


def _flag_present(flag: str, text: str) -> bool:
    """True if `flag` appears in `text` as a standalone flag (not a substring of a longer flag)."""
    return bool(re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", text or ""))


def _detect_json_flag(help_text: str):
    for tok, mode in _JSON_TOKENS:
        if _flag_present(tok, help_text):
            return tok, mode
    return "", ""


def _detect_input_kind(help_text: str) -> str:
    h = help_text or ""
    if _flag_present("-u", h) or re.search(r"\b(url|urls)\b", h, re.I):
        return "url"
    if _flag_present("-host", h) or _flag_present("-d", h) or re.search(r"\b(host|hosts|domain)\b", h, re.I):
        return "host"
    if _flag_present("-f", h) or re.search(r"\b(file|path|directory|input\s+file)\b", h, re.I):
        return "path"
    return "none"


def _input_prefix(kind: str, help_text: str) -> str:
    """The flag that precedes the target value, if the help shows one; else positional ('')."""
    if kind == "url" and _flag_present("-u", help_text):
        return "-u "
    if kind == "host":
        if _flag_present("-host", help_text):
            return "-host "
        if _flag_present("-d", help_text):
            return "-d "
    if kind == "path" and _flag_present("-f", help_text):
        return "-f "
    return ""


def _introspect(bin_: str, help_text: str) -> dict:
    """Tier 2: synthesize a descriptor from the tool's --help text."""
    flag, mode = _detect_json_flag(help_text)
    kind = _detect_input_kind(help_text)
    inp = _input_prefix(kind, help_text)
    parts = [bin_]
    if flag:
        parts.append(flag)
    parts.append(f"{inp}{{target}}")
    parts.append("{extra}")
    tmpl = re.sub(r"\s+", " ", " ".join(parts)).strip()
    return {
        "input_kind": kind,
        "template": tmpl,
        "output_mode": mode or "lines",
        "provenance": "help-introspect",
        "confidence": "medium" if flag else "low",
    }


def _get_help(bin_: str, run) -> str:
    """Fetch help text via the injected `run(cmd)->str`. Merges stderr (many tools print help there)."""
    cmd = (f"{bin_} --help 2>&1 | head -200; echo ---; {bin_} -h 2>&1 | head -200; "
           f"echo ---; {bin_} 2>&1 | head -60")
    try:
        return run(cmd) or ""
    except Exception:
        return ""


def _board_template(bin_: str, ask) -> dict | None:
    """Tier 3: ask the board for ONE template. Parsed into fixed slots; rejected on shell operators."""
    prompt = (f"Give ONE invocation template for the CLI tool '{bin_}' for an AUTHORIZED, CONTAINED "
              f"security lab. Use the literal placeholders {{target}} and {{extra}}. Prefer a flag that "
              f"emits JSON or JSONL. Reply EXACTLY one line: 'TEMPLATE <command>'. No prose. No shell "
              f"operators (no ; | & $ backticks < > redirection).")
    try:
        text = ask(prompt) or ""
    except Exception:
        return None
    m = re.search(r"TEMPLATE\s+(.+)", text)
    if not m:
        return None
    tmpl = m.group(1).strip().strip("`").strip()
    if not tmpl.startswith(bin_ + " ") and tmpl != bin_:
        return None                              # must invoke the named tool
    if "{target}" not in tmpl:
        return None
    probe = tmpl.replace("{target}", "").replace("{extra}", "")
    if _METAS.search(probe):
        return None                              # reject shell operators
    mode = "ndjson" if re.search(r"json", tmpl, re.I) else "lines"
    if "{extra}" not in tmpl:
        tmpl = tmpl + " {extra}"
    return {"input_kind": "url", "template": tmpl, "output_mode": mode,
            "provenance": "board", "confidence": "low"}


def _finalize(bin_: str, d: dict, provenance: str, confidence: str) -> dict:
    tmpl = d["template"]
    if "{extra}" not in tmpl:
        tmpl = tmpl + " {extra}"
    return {
        "bin": bin_,
        "input_kind": d.get("input_kind", "none"),
        "template": tmpl,
        "output_mode": d.get("output_mode", "lines"),
        "category": d.get("category", ""),
        "timeout": int(d.get("timeout", 600)),
        "provenance": provenance,
        "confidence": confidence,
        "added": _now(),
    }


def load_registry() -> dict:
    try:
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _register(name: str, desc: dict) -> None:
    reg = load_registry()
    reg[name] = desc
    try:
        with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(reg, f, indent=1, sort_keys=True)
    except Exception:
        pass


def _audit(entry: dict) -> None:
    try:
        entry["ts"] = _now()
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def synthesize(name: str, bin_: str | None = None, run=None, ask=None, write: bool = True) -> dict:
    """Derive + register a structured wrapper for a tool. `run(cmd)->str` enables tier-2 help
    introspection; `ask(prompt)->str` enables the tier-3 board fallback. Returns the descriptor
    (with a 'name' key) or a {'status': 'rejected-unsafe-name'} dict."""
    bin_ = bin_ or name
    if not _safe(name) or not _safe(bin_):
        return {"name": name, "status": "rejected-unsafe-name"}
    seed = _CURATED.get(bin_) or _CURATED.get(name)
    if seed:
        desc = _finalize(bin_, dict(seed), "curated", "high")
    else:
        d = _introspect(bin_, _get_help(bin_, run) if run else "")
        if d.get("confidence") == "low" and ask:
            b = _board_template(bin_, ask)
            if b:
                d = b
        desc = _finalize(bin_, d, d.get("provenance", "help-introspect"), d.get("confidence", "low"))
    desc["name"] = name
    if write:
        _register(name, desc)
        _audit({"tool": name, "bin": bin_, "action": "wrap", "provenance": desc["provenance"],
                "confidence": desc["confidence"], "template": desc["template"]})
    return desc


def _safe_extra(extra: str) -> str:
    extra = (extra or "").strip()
    if not extra:
        return ""
    if _METAS.search(extra):
        raise ValueError("extra_args contains shell operators")
    return extra


def build_command(desc: dict, target: str = "", extra: str = "") -> str:
    """Render a descriptor's template into a concrete command. target is shell-quoted; extra is
    metachar-rejected. Raises ValueError on unsafe extra."""
    t = shlex.quote(target) if target else ""
    e = _safe_extra(extra)
    cmd = desc["template"].format(target=t, extra=e)
    return re.sub(r"\s+", " ", cmd).strip()


def _try_json(out: str):
    out = (out or "").strip()
    if not out:
        return None, "empty"
    try:
        return json.loads(out), ""
    except Exception as e:
        last = out.splitlines()[-1].strip()
        try:
            return json.loads(last), ""
        except Exception:
            return None, str(e)


def _parse_ndjson(out: str):
    items, bad = [], 0
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except Exception:
            bad += 1
    return items, bad


def normalize(desc: dict, stdout: str, stderr: str = "", returncode: int = 0) -> dict:
    """Turn raw tool output into a structured result per the descriptor's output_mode. Always
    degradable: on a parse miss, mode falls back to raw and the tail is preserved."""
    mode = desc.get("output_mode", "lines")
    out = stdout or ""
    res = {"tool": desc.get("bin"), "output_mode": mode, "returncode": returncode,
           "provenance": desc.get("provenance"), "confidence": desc.get("confidence")}
    if mode == "json":
        parsed, err = _try_json(out)
        if parsed is not None:
            res["normalized"] = parsed
            res["count"] = len(parsed) if isinstance(parsed, list) else 1
        else:
            res["output_mode"] = "raw"
            res["normalized"] = None
            res["parse_error"] = err
            res["raw_tail"] = _strip_ansi(out)[-4000:]
    elif mode == "ndjson":
        items, bad = _parse_ndjson(out)
        res["normalized"] = items
        res["count"] = len(items)
        if bad:
            res["unparsed_lines"] = bad
    elif mode == "lines":
        lines = [l for l in _strip_ansi(out).splitlines() if l.strip()]
        res["count"] = len(lines)
        res["truncated"] = len(lines) > _MAX_LINES
        res["normalized"] = lines[:_MAX_LINES]
    else:  # raw
        s = _strip_ansi(out)
        res["truncated"] = len(s) > _MAX_RAW
        res["normalized"] = s[:_MAX_RAW]
    if stderr:
        res["stderr"] = stderr[:1000]
    return res


def backfill(names, run, ask=None) -> dict:
    """Synthesize wrappers for a list of already-present tools (seeds the registry from the current
    Kali). Returns {name: provenance}."""
    out = {}
    for n in names:
        if not _safe(n):
            continue
        d = synthesize(n, n, run=run, ask=ask, write=True)
        out[n] = d.get("provenance", d.get("status", "?"))
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Inspect / test the tool-wrapper registry.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    ps = sub.add_parser("show")
    ps.add_argument("name")
    a = ap.parse_args()
    reg = load_registry()
    if a.cmd == "list":
        for n, d in sorted(reg.items()):
            print(f"  {n:18} [{d.get('output_mode')}/{d.get('confidence')}/{d.get('provenance')}]  {d.get('template')}")
    elif a.cmd == "show":
        print(json.dumps(reg.get(a.name, {"error": "no such wrapper"}), indent=2))


if __name__ == "__main__":
    main()
