#!/usr/bin/env python3
"""Offline tests for signal_correlator.py (weak-signal fusion -> hypothesis moves). No network.
Run: python operator/_signal_correlator_tests.py"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import signal_correlator as SC  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")


def moves_by_surface(moves):
    return {(m["surface"], m["vuln_class"]): m for m in moves}


# --- single STRONG signal (beacon callback) emits an ssrf hypothesis ---
bus = SC.SignalBus()
bus.add("beacon_callback", "/api/fetch", token="aegisoobdeadbeef0001")
moves = SC.correlate(bus)
mbs = moves_by_surface(moves)
ok("beacon callback -> ssrf move", ("/api/fetch", "ssrf") in mbs)
ok("ssrf move high confidence", mbs[("/api/fetch", "ssrf")]["_corr_conf"] >= 0.9)
ok("ssrf move carries the beacon token", mbs[("/api/fetch", "ssrf")].get("beacon_token") == "aegisoobdeadbeef0001")
ok("move tagged origin=correlator", mbs[("/api/fetch", "ssrf")]["_origin"] == "correlator")

# --- two WEAK signals co-occurring on one surface -> emitted with co-occurrence boost ---
bus = SC.SignalBus()
bus.add("timing_delta", "/api/search")     # 0.45 injection
bus.add("error_5xx", "/api/search")        # 0.40 injection
moves = SC.correlate(bus)
mbs = moves_by_surface(moves)
ok("two weak injection signals co-occur -> injection move", ("/api/search", "injection") in mbs)
ok("co-occurrence boost pushed conf over threshold (0.45+0.40+0.2)",
   mbs[("/api/search", "injection")]["_corr_conf"] >= 0.6)
ok("mechanism lists both signal kinds",
   "error_5xx" in mbs[("/api/search", "injection")]["mechanism"] and "timing_delta" in mbs[("/api/search", "injection")]["mechanism"])

# --- a SINGLE weak signal below threshold -> NO move (sub-threshold) ---
bus = SC.SignalBus()
bus.add("size_delta", "/api/item")         # 0.40 idor, single -> below 0.6
ok("single sub-threshold signal emits nothing", SC.correlate(bus) == [])

# --- role differential -> authz hypothesis (strong single) ---
bus = SC.SignalBus()
bus.add("role_diff", "/api/records")       # 0.70 authz
ok("role_diff -> authz move above threshold", ("/api/records", "authz") in moves_by_surface(SC.correlate(bus)))

# --- explicit class override + custom strength ---
bus = SC.SignalBus()
bus.add("fuzzer_nearmiss", "/parse", cls="deserialization", strength=0.8)
mv = SC.correlate(bus)
ok("class override honored", mv and mv[0]["vuln_class"] == "deserialization")

# --- moves are ranked best-first + expected_oracle set per class ---
bus = SC.SignalBus()
bus.add("beacon_callback", "/a")            # ssrf 0.9
bus.add("role_diff", "/b")                  # authz 0.7
ranked = SC.correlate(bus)
ok("ranked best-first by confidence", ranked[0]["_corr_conf"] >= ranked[-1]["_corr_conf"])
ok("expected_oracle set per class", "out-of-band" in ranked[0]["expected_oracle"].lower())

# --- ingesters: beacon registry + target profile -> signals ---
import types
reg = types.SimpleNamespace(correlate=lambda: {"aegisoobfeed0001": {"surface": "/api/hook", "vuln_class": "ssrf"}})
prof = types.SimpleNamespace(under_probed=lambda: ["/admin/debug"])
bus = SC.SignalBus()
SC.ingest_beacons(bus, reg)
SC.ingest_coverage(bus, prof)
kinds = {s["kind"] for s in bus.signals}
ok("ingest_beacons adds a beacon_callback signal", "beacon_callback" in kinds)
ok("ingest_coverage adds a coverage_gap signal", "coverage_gap" in kinds)
ok("beacon ingest -> emitted ssrf move on the hook surface", ("/api/hook", "ssrf") in moves_by_surface(SC.correlate(bus)))

n = 15
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
