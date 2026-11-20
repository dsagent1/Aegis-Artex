#!/usr/bin/env python3
"""Standalone tests for tool_wrapper.py -- no Kali/network (run/ask are injected)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tool_wrapper as TW  # noqa: E402

_PASS = 0
_FAIL = 0


def ok(cond, label):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  ok   {label}")
    else:
        _FAIL += 1
        print(f"  FAIL {label}")


# ---- tier 1: curated ----
def test_curated():
    d = TW.synthesize("nuclei", write=False)
    ok(d["provenance"] == "curated", "nuclei -> curated provenance")
    ok(d["confidence"] == "high", "nuclei -> high confidence")
    ok(d["output_mode"] == "ndjson", "nuclei -> ndjson")
    ok("{target}" in d["template"] and "{extra}" in d["template"], "nuclei template has both slots")


# ---- tier 2: --help introspection ----
def test_introspect_json_flag():
    help_text = ("Usage: zap [options] -u url\n  -jsonl   write JSONL output\n  -u url   target url\n")
    d = TW.synthesize("zap", "zap", run=lambda c: help_text, write=False)
    ok(d["provenance"] == "help-introspect", "zap -> help-introspect")
    ok(d["confidence"] == "medium", "zap (flag found) -> medium")
    ok(d["output_mode"] == "ndjson", "zap -jsonl -> ndjson")
    ok(d["input_kind"] == "url", "zap -> url input")
    ok(d["template"] == "zap -jsonl -u {target} {extra}", f"zap template: {d['template']}")


def test_introspect_no_flag():
    help_text = "Usage: oldtool <host>\n  prints plain text, no json option\n"
    d = TW.synthesize("oldtool", "oldtool", run=lambda c: help_text, write=False)
    ok(d["confidence"] == "low", "oldtool (no flag) -> low")
    ok(d["output_mode"] == "lines", "oldtool -> lines mode")
    ok("{target}" in d["template"], "oldtool template still callable")


def test_jsonl_not_shadowed_by_json():
    # help offers both --json and --jsonl: ndjson/-jsonl must win (listed first)
    help_text = "  --json    json output\n  --jsonl   streaming json lines\n  -u url\n"
    d = TW.synthesize("probe", "probe", run=lambda c: help_text, write=False)
    ok("-jsonl" in d["template"], "jsonl preferred over json")
    ok(d["output_mode"] == "ndjson", "both present -> ndjson")


# ---- tier 3: board fallback ----
def test_board_fallback_accepts_clean():
    help_text = "no machine-readable output here\n"  # forces low -> board
    ask = lambda p: "TEMPLATE scanx -json -u {target} {extra}"
    d = TW.synthesize("scanx", "scanx", run=lambda c: help_text, ask=ask, write=False)
    ok(d["provenance"] == "board", "scanx -> board provenance")
    ok(d["template"].startswith("scanx "), "board template invokes the tool")
    ok("{target}" in d["template"], "board template has target slot")


def test_board_fallback_rejects_shell():
    help_text = "no json here\n"
    ask = lambda p: "TEMPLATE evil; rm -rf / {target}"
    d = TW.synthesize("evil", "evil", run=lambda c: help_text, ask=ask, write=False)
    ok(d["provenance"] != "board", "malicious board template rejected (not board)")
    ok(d["provenance"] == "help-introspect", "falls back to introspect on rejection")


def test_board_fallback_rejects_wrong_tool():
    help_text = "no json here\n"
    ask = lambda p: "TEMPLATE otherbin -u {target} {extra}"   # doesn't invoke the named tool
    d = TW.synthesize("mytool", "mytool", run=lambda c: help_text, ask=ask, write=False)
    ok(d["provenance"] != "board", "template for wrong tool rejected")


# ---- build_command safety ----
def test_build_command_quotes_target():
    desc = {"template": "nuclei -jsonl -u {target} {extra}"}
    cmd = TW.build_command(desc, "https://ex.com/a b", "")
    ok("'https://ex.com/a b'" in cmd, "target shell-quoted")
    ok("{extra}" not in cmd, "empty extra collapses cleanly")


def test_build_command_rejects_shell_extra():
    desc = {"template": "nuclei -u {target} {extra}"}
    try:
        TW.build_command(desc, "https://ex.com", "-t 50; rm -rf /")
        ok(False, "shell operator in extra should raise")
    except ValueError:
        ok(True, "shell operator in extra raises ValueError")


def test_build_command_allows_clean_extra():
    desc = {"template": "ffuf -u {target} {extra}"}
    cmd = TW.build_command(desc, "https://ex.com/FUZZ", "-w /usr/share/wl.txt -t 40")
    ok("-w /usr/share/wl.txt -t 40" in cmd, "clean extra flags pass through")


# ---- normalize ----
def test_normalize_ndjson():
    desc = {"bin": "nuclei", "output_mode": "ndjson"}
    out = '{"a":1}\n{"b":2}\nnot-json\n'
    r = TW.normalize(desc, out)
    ok(r["count"] == 2, "ndjson parses 2 objects")
    ok(r.get("unparsed_lines") == 1, "ndjson flags 1 unparsed line")


def test_normalize_json_array():
    desc = {"bin": "dalfox", "output_mode": "json"}
    r = TW.normalize(desc, '[{"x":1},{"y":2}]')
    ok(r["count"] == 2, "json array -> count 2")
    ok(isinstance(r["normalized"], list), "json normalized is a list")


def test_normalize_json_fallback_to_raw():
    desc = {"bin": "broken", "output_mode": "json"}
    r = TW.normalize(desc, "this is not json at all")
    ok(r["output_mode"] == "raw", "unparseable json -> raw mode")
    ok("raw_tail" in r, "raw tail preserved on parse miss")


def test_normalize_json_reclassifies_ndjson():
    # a tool flagged -json but actually emitting NDJSON (dnsx-class) must parse, not fall to raw
    desc = {"bin": "dnsx", "output_mode": "json"}
    r = TW.normalize(desc, '{"host":"a"}\n{"host":"b"}\n')
    ok(r["output_mode"] == "ndjson", "json-mode with ndjson body reclassified to ndjson")
    ok(r["count"] == 2, "reclassified ndjson count == 2")


def test_normalize_lines_truncation():
    desc = {"bin": "gau", "output_mode": "lines"}
    out = "\n".join(f"line{i}" for i in range(TW._MAX_LINES + 50))
    r = TW.normalize(desc, out)
    ok(r["truncated"] is True, "lines over cap flagged truncated")
    ok(len(r["normalized"]) == TW._MAX_LINES, "lines capped at _MAX_LINES")


def test_normalize_strips_ansi():
    desc = {"bin": "x", "output_mode": "lines"}
    r = TW.normalize(desc, "\x1b[31mred\x1b[0m\n")
    ok(r["normalized"] == ["red"], "ANSI colour codes stripped")


# ---- safety: names ----
def test_unsafe_name_rejected():
    d = TW.synthesize("bad;name", write=False)
    ok(d.get("status") == "rejected-unsafe-name", "unsafe tool name rejected")


def test_roundtrip_registry(tmpname="__wrap_test_tool__"):
    # write a wrapper, read it back, then clean it out of the registry
    TW.synthesize(tmpname, "nuclei", write=True)   # name=key, bin nuclei is curated
    reg = TW.load_registry()
    ok(tmpname in reg, "synthesize(write=True) persists to registry")
    ok(reg[tmpname]["provenance"] == "curated", "persisted descriptor is correct")
    # cleanup
    reg.pop(tmpname, None)
    import json
    with open(TW.REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=1, sort_keys=True)
    ok(tmpname not in TW.load_registry(), "cleanup removed the test entry")


def main():
    for fn in [test_curated, test_introspect_json_flag, test_introspect_no_flag,
               test_jsonl_not_shadowed_by_json, test_board_fallback_accepts_clean,
               test_board_fallback_rejects_shell, test_board_fallback_rejects_wrong_tool,
               test_build_command_quotes_target, test_build_command_rejects_shell_extra,
               test_build_command_allows_clean_extra, test_normalize_ndjson,
               test_normalize_json_array, test_normalize_json_fallback_to_raw,
               test_normalize_json_reclassifies_ndjson,
               test_normalize_lines_truncation, test_normalize_strips_ansi,
               test_unsafe_name_rejected, test_roundtrip_registry]:
        print(f"\n[{fn.__name__}]")
        fn()
    print(f"\n==== tool_wrapper: {_PASS} passed, {_FAIL} failed ====")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
