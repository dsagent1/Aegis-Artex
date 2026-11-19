#!/usr/bin/env python3
"""Offline tests for the fuller-parity Kali arsenal adapters (nmap/ffuf/dalfox). No live tools: monkeypatch
compare_recall._kali to feed canned tool output and assert parsing + registration + graceful-skip.
Run: python operator/_kali_adapters_tests.py"""
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


def with_kali(sample):
    CR._kali = lambda cmd, timeout: sample   # monkeypatch the live runner


# --- registration ---
ok("nmap/ffuf/dalfox registered in DAST ADAPTERS", all(t in CR.ADAPTERS for t in ("nmap", "ffuf", "dalfox")))

# --- nmap parse ---
with_kali("Starting Nmap\n80/tcp  open  http    nginx 1.25.3\n443/tcp open  ssl/http nginx\n"
          "|_http-server-header: nginx/1.25.3\n22/tcp closed ssh\n")
blobs, note = CR.adapt_nmap("http://twin:8080")
ok("nmap parses open ports", any("80/tcp" in b for b in blobs) and any("443/tcp" in b for b in blobs))
ok("nmap parses NSE script lines", any("http-server-header" in b for b in blobs))
ok("nmap ignores closed ports", not any("closed" in b for b in blobs))

# --- ffuf parse (csv) ---
with_kali("FUZZword,url,status_code,length\nbackup,http://twin/backup,200,1024\nadmin,http://twin/admin,401,10\n")
blobs, note = CR.adapt_ffuf("http://twin")
ok("ffuf parses discovered rows", len(blobs) == 2 and any("backup" in b for b in blobs))
ok("ffuf skips the csv header", not any("FUZZword" in b for b in blobs))

# --- dalfox parse ---
with_kali("[*] scanning\n[POC][G][GET] http://twin/?q=<script> reflected XSS\n[I] some info line\n")
blobs, note = CR.adapt_dalfox("http://twin/?q=1")
ok("dalfox parses POC/xss signals", len(blobs) == 1 and "POC" in blobs[0])

# --- graceful skip on empty output ---
with_kali("")
ok("nmap empty -> [] + note", CR.adapt_nmap("http://x")[0] == [] and "0" in CR.adapt_nmap("http://x")[1])
ok("ffuf empty -> [] + note", CR.adapt_ffuf("http://x")[0] == [])
ok("dalfox empty -> [] + note", CR.adapt_dalfox("http://x")[0] == [])

# --- recall wiring: ffuf 'backup' -> misconfig class; dalfox -> xss class ---
ok("ffuf backup path recalls misconfig",
   CR.match_expected([{"class": "misconfig", "surface": "", "match": []}],
                     ["discovered path backup,http://twin/backup,200,1024"])[0]["recalled"] is True)
ok("dalfox signal recalls xss",
   CR.match_expected([{"class": "xss", "surface": "", "match": []}],
                     ["[POC][G][GET] http://twin/?q=<script> reflected XSS"])[0]["recalled"] is True)

n = 12
print(f"\n{n - fails}/{n} PASS")
sys.exit(1 if fails else 0)
