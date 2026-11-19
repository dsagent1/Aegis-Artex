#!/usr/bin/env python3
"""Offline tests for the BlackArch/Arch discovery adapters (katana/gau/waybackurls/hakrawler/x8/gowitness),
routed through distro_backend. No live tools: monkeypatch compare_recall._distro_cmd with canned output.
Run: python operator/_distro_adapters_tests.py"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare_recall as CR  # noqa: E402

fails = 0
def ok(label, cond):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL':4} {label}")


def with_out(sample):
    CR._distro_cmd = lambda tool, cmd, timeout=240: sample   # monkeypatch the distro router


# --- registration ---
ok("distro discovery tools registered in ADAPTERS",
   all(t in CR.ADAPTERS for t in ("katana", "gau", "waybackurls", "hakrawler", "x8", "gowitness")))

# --- helpers ---
ok("_host_of strips scheme/port", CR._host_of("https://mirror.internal:8443/x") == "mirror.internal")
ok("_urls keeps only http(s) lines", CR._urls("http://a/x\nnoise\nhttps://a/y") == ["http://a/x", "https://a/y"])

# --- katana ---
with_out("http://twin/api/users\nhttp://twin/admin\nnot-a-url\n")
b, note = CR.adapt_katana("http://twin")
ok("katana parses crawled endpoints", len(b) == 2 and all("discovered endpoint" in x for x in b))

# --- gau / waybackurls (host-based, passive) ---
with_out("http://twin/old.php?id=1\nhttp://twin/backup.zip\n")
b, _ = CR.adapt_gau("http://twin:8443/app")
ok("gau parses historical urls", len(b) == 2 and "historical url" in b[0])
b, _ = CR.adapt_waybackurls("http://twin")
ok("waybackurls parses archive urls", len(b) == 2 and "wayback url" in b[0])

# --- hakrawler ---
with_out("http://twin/js/app.js\nhttp://twin/api/v2/orders\n")
b, _ = CR.adapt_hakrawler("http://twin")
ok("hakrawler parses crawled endpoints", len(b) == 2 and "crawled endpoint" in b[0])

# --- x8 (param discovery) ---
with_out("found parameter: debug\nparam role reflected\nunrelated line\n")
b, _ = CR.adapt_x8("http://twin/api")
ok("x8 parses hidden-parameter signals", len(b) == 2 and all("hidden parameter" in x for x in b))

# --- gowitness (tech/fingerprint) ---
with_out("url=http://twin title='Login' server=nginx status=200\nrandom\n")
b, _ = CR.adapt_gowitness("http://twin")
ok("gowitness parses tech/fingerprint notes", len(b) >= 1 and "tech/fingerprint" in b[0])

# --- graceful skip on empty output ---
with_out("")
ok("empty -> [] + skip note (katana)", CR.adapt_katana("http://x")[0] == [] and "0" in CR.adapt_katana("http://x")[1])
ok("empty -> [] (x8)", CR.adapt_x8("http://x")[0] == [])

# --- routing helper falls back to _kali when distro_backend absent (smoke: does not raise) ---
import importlib
importlib.reload(CR)   # restore the real _distro_cmd
ok("_distro_cmd is callable after reload", callable(CR._distro_cmd))

n = 13
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
