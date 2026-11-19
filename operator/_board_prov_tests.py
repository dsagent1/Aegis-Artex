#!/usr/bin/env python3
"""Offline tests for board PROVENANCE instrumentation (no egress). Stubs the LLM post so the single-pass
board path runs fully offline. Run: python operator/_board_prov_tests.py"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["AEGIS_BOARD_DISCUSS"] = "0"          # skip the CF roster -> single-pass deepseek path
os.environ.setdefault("AEGIS_LLM_API_KEY", "test-key")

import remediation_board as RB  # noqa: E402
# stub the network call: return two board-proposed moves (one is the intended SSRF hypothesis)
RB._post_openai_style = lambda *a, **k: (
    '{"angle":"ssrf","surface":"/api/fetch","vuln_class":"ssrf",'
    '"mechanism":"server-side fetch reaches internal metadata","expected_oracle":"leaked credential"}\n'
    '{"angle":"authz","surface":"/internal/crown","vuln_class":"authz","expected_oracle":"200 with stolen cred"}'
)

import iterative_hunt as IH  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")

# --- _board_prov: pure tagging ---
tagged = IH._board_prov("board_discuss", [{"vuln_class": "idor"}, {"angle": "ssrf"}, "not-a-dict"])
ok("_board_prov tags dict moves with _origin", tagged[0]["_origin"] == "board_discuss" and tagged[1]["_origin"] == "board_discuss")
ok("_board_prov leaves non-dicts alone", tagged[2] == "not-a-dict")
ok("_board_prov does not clobber an existing _origin",
   IH._board_prov("x", [{"_origin": "seed", "vuln_class": "a"}])[0]["_origin"] == "seed")

# --- single-pass board path tags provenance (end-to-end, offline via the stub) ---
moves = IH.board_brainstorm({"phase": "map"})
ok("single-pass returned the stubbed moves", len(moves) == 2)
ok("every board move tagged single_pass:deepseek-v4-pro",
   all(m.get("_origin") == "single_pass:deepseek-v4-pro" for m in moves))
ok("the intended SSRF hypothesis is present + attributable",
   any(m.get("vuln_class") == "ssrf" and m.get("_origin") == "single_pass:deepseek-v4-pro" for m in moves))

# --- audit-row origin fallback contract (what iterhunt records) ---
def _origin_for(move):
    return move.get("_origin") or move.get("tier") or "seed/det"
ok("board move -> board origin in audit row", _origin_for({"_origin": "single_pass:deepseek-v4-pro"}) == "single_pass:deepseek-v4-pro")
ok("synth move -> synth origin", _origin_for({"tier": "T1-synth", "_origin": "synth"}) == "synth")
ok("untagged seed/deterministic move -> seed/det", _origin_for({"vuln_class": "x"}) == "seed/det")

n = 9
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
