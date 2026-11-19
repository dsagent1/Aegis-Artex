#!/usr/bin/env python3
"""Offline truth-table for _novelcode_http_verdict (vectors.py) -- the round-2 real-witness fix.

Proves the novel-code HTTP oracle REJECTS the three FPs round-2 triage caught, and still ACCEPTS a
real witness (SELECT db-proof or a >=4-char marker that differentials against the baseline). No network,
no LLM -- pure decision logic. Run: python operator/_novelcode_oracle_tests.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from vectors import _novelcode_http_verdict as V  # noqa: E402

CASES = [
    # (label, expected_verified, kwargs)
    ("FP alg:none-JWT (body~'a', 200)", False,
     dict(oracle_txt="body~'a'", check_verdict="pass", status=200, body="aaa page a",
          baseline_status=200, baseline_body="different shell")),
    ("FP XXE rate-limited (429 marked pass)", False,
     dict(oracle_txt="contains 'root:x:0:0'", check_verdict="pass", status=429, body="Too Many Requests",
          baseline_status=404, baseline_body="nope")),
    ("FP job-statuses (body~'at', 200)", False,
     dict(oracle_txt="body~'at'", check_verdict="pass", status=200, body="job data at 10:00",
          baseline_status=200, baseline_body="also has at here")),
    ("TP SELECT db-witness", True,
     dict(oracle_txt="SELECT id FROM users WHERE role='admin';", check_verdict="pass", status=200,
          body="[{'id':1}]", baseline_status=404, baseline_body="nope")),
    ("TP >=4-char marker, differential", True,
     dict(oracle_txt="body contains 'AEGIS_CANARY_9f3a1c'", check_verdict="pass", status=200,
          body="...AEGIS_CANARY_9f3a1c...", baseline_status=404, baseline_body="not found")),
    ("REJECT ambient marker (in baseline too)", False,
     dict(oracle_txt="contains 'sessionToken'", check_verdict="pass", status=200,
          body="sessionToken=x", baseline_status=200, baseline_body="sessionToken cookie banner")),
    ("REJECT spa_fallback (2xx == nonexistent baseline)", False,
     dict(oracle_txt="contains 'root:x:0:0'", check_verdict="pass", status=200, body="<spa/>",
          baseline_status=200, baseline_body="<spa/>")),
    ("REJECT check_oracle did not pass", False,
     dict(oracle_txt="SELECT 1;", check_verdict="fail", status=200, body="x",
          baseline_status=404, baseline_body="y")),
    ("REJECT bare-status oracle (no marker/SELECT)", False,
     dict(oracle_txt="expect http 200", check_verdict="pass", status=200, body="ok",
          baseline_status=404, baseline_body="nope")),
    ("TP marker, baseline unavailable (guards 1-3 hold)", True,
     dict(oracle_txt="contains 'AEGIS_CANARY_9f3a1c'", check_verdict="pass", status=200,
          body="...AEGIS_CANARY_9f3a1c...", baseline_status=None, baseline_body=None)),
]


def main():
    fails = 0
    for i, (label, expected, kw) in enumerate(CASES, 1):
        got, notes = V(**kw)
        ok = (got == expected)
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL':4} {i} {label:48s} -> verified={got}  ({notes})")
    n = len(CASES)
    print(f"\n{n - fails}/{n} PASS")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
