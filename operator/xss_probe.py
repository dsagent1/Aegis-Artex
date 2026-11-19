#!/usr/bin/env python3
"""Subprocess-isolated XSS browser probe for vectors.xss. Runs Playwright sync_api on the MAIN THREAD of a
FRESH PROCESS -- which avoids BOTH the Windows asyncio-loop deadlock AND the WSL thread+sync stall that the
old dedicated-thread wrapper hit (observed: 'driver stall', 0 execution witnessed even though the DOM-XSS
fires). Reads a JSON job on stdin, prints one JSON line {"hit": {context,param,url}|null, "err": str|null}.
The parent enforces a hard subprocess timeout so a driver stall can never wedge the hunt."""
import sys, json, urllib.parse


def main():
    try:
        job = json.load(sys.stdin)
    except Exception as e:
        print(json.dumps({"hit": None, "err": "bad job: %s" % e})); return
    base = job["base"]; surface = str(job["surface"]); tok = job["tok"]
    payloads = job["payloads"]; params = job.get("params") or ["q"]; cookies = job.get("cookies") or []
    url0 = base.rstrip("/") + (surface if surface.startswith("/") else "/" + surface)
    out = {"hit": None, "err": None}
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(json.dumps({"hit": None, "err": "playwright unavailable: %s" % e})); return
    _q = lambda v: urllib.parse.quote(v, safe="")
    try:
        with sync_playwright() as p:
            br = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
            cx = br.new_context(ignore_https_errors=True)
            if cookies:
                try: cx.add_cookies(cookies)
                except Exception: pass
            pg = cx.new_page()
            pg.on("dialog", lambda d: d.dismiss())
            _seg = [s for s in surface.split("/") if s]
            _spa_routes = ["/#/" + (_seg[-1] if _seg else "search"),
                           "/#" + (surface if surface.startswith("/") else "/" + surface)]
            targets = []
            for pv in payloads:
                for _rt in dict.fromkeys(_spa_routes):
                    for pr in ("q", "search", "query", "s"):
                        targets.append(("spa-route", pr, base.rstrip("/") + _rt + "?" + pr + "=" + _q(pv)))
            for pv in payloads:
                for pr in params:
                    targets.append(("reflected", pr, url0 + ("&" if "?" in url0 else "?") + pr + "=" + _q(pv)))
                targets.append(("dom-hash", "#", url0 + "#" + _q(pv)))

            def _await(poll_s):
                import time as _t
                dl = _t.time() + poll_s
                while _t.time() < dl:
                    try:
                        if pg.evaluate("window.__aegis_xss || null") == tok:
                            return True
                    except Exception:
                        pass
                    try: pg.wait_for_timeout(400)
                    except Exception: break
                return False

            for ctxt, pr, u in targets:
                spa = ctxt in ("spa-route", "dom-hash")
                try:
                    pg.goto(u, wait_until=("networkidle" if spa else "domcontentloaded"),
                            timeout=(12000 if spa else 8000))
                except Exception:
                    try: pg.goto(u, wait_until="domcontentloaded", timeout=8000)
                    except Exception: pass
                if _await(3.0 if spa else 0.6):
                    out["hit"] = {"context": ctxt, "param": pr, "url": u[:200]}; break
                try: pg.evaluate("window.__aegis_xss=null")
                except Exception: pass
            br.close()
    except Exception as e:
        out["err"] = str(e)[:200]
    print(json.dumps(out))


if __name__ == "__main__":
    main()
