"""capture.py -- ARTEX-port #1: authenticated / real-traffic CAPTURE -> hunt (the reach-extender).

An UNAUTHENTICATED scan sees ~10% of a real app. The other 90% -- and almost every high-value class
(IDOR/BOLA, broken access control, business logic, privilege escalation) -- lives BEHIND a login, or in a
mobile/thick-client backend the crawler can't reach at all. `session_factory` can only reach surfaces it can
programmatically LOG IN to (needs creds/PIN); it is helpless against captcha / OTP / 2FA / SSO.

CAPTURE closes that gap. A human logs in ONCE (solving whatever challenge), their traffic is recorded by any
tool that exports HAR -- the browser's DevTools ("Save all as HAR"), Burp, mitmproxy, or a phone pointed at a
proxy -- and this module turns that capture into the three things the iterative hunt already consumes:

  * EVIDENCE  -- every captured exchange is written to the content-addressed EvidenceStore (role=baseline),
                 so the hunt starts with real request/response bytes bound and replayable.
  * an authenticated SESSION -- captured cookies + bearer/JWT -> session_for_role(role)->requests.Session
                 (the exact contract run_hunt/make_execute/AuthzOracle already use), so every leg runs AS the
                 logged-in user. A non-privileged "anon" role is served UNAUTHENTICATED, so the cross-role
                 AuthzOracle can PROVE over-reach (authed role reaches what anon is denied).
  * surface SEEDS -- the real endpoints the human exercised become extra_seeds, so the loop probes routes
                 that actually exist (not board-guessed paths), authenticated, from move #1.

We reimplement the CAPABILITY, not ARTEX's code (ARTEX is AGPL). No proxy/CA plumbing of our own: we consume
the universal HAR export. `record_mitm()` is a thin optional convenience for live recording.

CLI:
    python operator/capture.py --har session.har --base https://target --ingest-only   # load + summarize
    python operator/capture.py --har session.har --base https://target --objective "..." --hunt --budget 28
"""
from __future__ import annotations
import os, sys, json, base64, argparse
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "shared"))
sys.path.insert(0, HERE)
from verified_findings import capture_exchange, EvidenceStore  # noqa: E402

# auth-bearing request headers we lift into the replay session (lowercased match). Cookies handled separately.
_AUTH_HEADERS = ("authorization", "x-api-key", "x-auth-token", "x-access-token", "x-amz-security-token",
                 "x-xsrf-token", "x-csrf-token", "x-csrftoken", "api-key", "x-session-token")
# anon/unauth role names that must receive an UNAUTHENTICATED session (so the AuthzOracle has a baseline).
_ANON = {"anon", "anonymous", "unauth", "unauthenticated", "public", "none", "", "guest"}
# static asset extensions that are not worth seeding as test surfaces.
_STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
           ".map", ".webp", ".mp4", ".mp3", ".pdf", ".eot")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).netloc or "").lower()
    except Exception:
        return ""


def _path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except Exception:
        return "/"


def _headers_to_dict(hs) -> dict:
    """HAR headers are a list of {name,value}; also accept a plain dict. Last value wins."""
    if isinstance(hs, dict):
        return {str(k): str(v) for k, v in hs.items()}
    out = {}
    for h in (hs or []):
        if isinstance(h, dict) and "name" in h:
            out[str(h["name"])] = str(h.get("value", ""))
    return out


def _content_text(content: dict) -> str:
    """HAR response/postData body; base64-decode when the HAR says so."""
    if not isinstance(content, dict):
        return ""
    txt = content.get("text", "") or ""
    if content.get("encoding") == "base64" and txt:
        try:
            return base64.b64decode(txt).decode("utf-8", "replace")
        except Exception:
            return txt
    return txt


def parse_har(src) -> list:
    """Parse a HAR (path, JSON string, or already-loaded dict) into normalized exchanges. Also accepts an
    already-normalized list of exchange dicts (pass-through), so callers can synthesize captures directly."""
    if isinstance(src, list):
        return src
    if isinstance(src, str):
        data = json.loads(src) if src.lstrip().startswith("{") else json.load(open(src, encoding="utf-8"))
    else:
        data = src
    entries = (((data or {}).get("log") or {}).get("entries")) or []
    out = []
    for e in entries:
        req, resp = e.get("request", {}) or {}, e.get("response", {}) or {}
        out.append({
            "method": (req.get("method") or "GET").upper(),
            "url": req.get("url") or "",
            "req_headers": _headers_to_dict(req.get("headers")),
            "req_cookies": {c.get("name"): c.get("value", "") for c in (req.get("cookies") or []) if c.get("name")},
            "req_body": _content_text(req.get("postData") or {}),
            "status": int(resp.get("status") or 0),
            "resp_headers": _headers_to_dict(resp.get("headers")),
            "resp_cookies": {c.get("name"): c.get("value", "") for c in (resp.get("cookies") or []) if c.get("name")},
            "resp_body": _content_text(resp.get("content") or {}),
            "started": e.get("startedDateTime", ""),
        })
    return out


def _parse_cookie_header(val: str) -> dict:
    out = {}
    for part in (val or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def extract_auth(exchanges, base: str = None) -> dict:
    """Collect the authenticated session material (cookies + bearer/CSRF/api-key headers) from the capture.
    SECURITY HYGIENE: when `base` is given, only exchanges to the SAME host contribute -- we never fold the
    user's auth for a third-party domain into the target session. Latest value wins."""
    want = _host(base) if base else None
    cookies, headers = {}, {}
    for ex in exchanges:
        if want and _host(ex.get("url", "")) != want:
            continue
        cookies.update(ex.get("req_cookies") or {})
        for k, v in (ex.get("req_headers") or {}).items():
            lk = k.lower()
            if lk == "cookie":
                cookies.update(_parse_cookie_header(v))
            elif lk in _AUTH_HEADERS and v:
                headers[k] = v
        cookies.update(ex.get("resp_cookies") or {})
    return {"cookies": cookies, "headers": headers}


def _is_id(seg: str) -> bool:
    """Heuristic: a path segment that looks like an object id (numeric / uuid / long hex / mongo-ish)."""
    s = seg or ""
    if s.isdigit():
        return True
    low = s.lower()
    if len(s) >= 8 and all(c in "0123456789abcdef-" for c in low) and any(c.isdigit() for c in low):
        return True
    return False


def endpoints(exchanges, base: str = None) -> list:
    """Dedup the captured surfaces by (method, path), dropping static assets and (if base given) off-host
    traffic. Keeps query/body keys + a sample status + an id-bearing flag for IDOR seeding."""
    want = _host(base) if base else None
    seen, out = set(), []
    for ex in exchanges:
        url = ex.get("url", "")
        if want and _host(url) != want:
            continue
        path = _path(url)
        if any(path.lower().endswith(x) for x in _STATIC):
            continue
        method = ex.get("method", "GET")
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        q = urlsplit(url).query
        qkeys = [p.split("=", 1)[0] for p in q.split("&") if p]
        bkeys = []
        try:
            jb = json.loads(ex.get("req_body") or "")
            if isinstance(jb, dict):
                bkeys = list(jb.keys())
        except Exception:
            pass
        segs = [s for s in path.split("/") if s]
        out.append({"method": method, "path": path, "query_keys": qkeys, "body_keys": bkeys,
                    "status": ex.get("status", 0), "id_bearing": any(_is_id(s) for s in segs),
                    "content_type": (ex.get("resp_headers") or {}).get("Content-Type", "")})
    return out


def ingest(exchanges, store: "EvidenceStore" = None, base: str = None, role: str = "captured") -> dict:
    """Write every captured exchange into the content-addressed EvidenceStore (role=baseline) and return the
    capture bundle: {evidence, auth, endpoints, n}. Offline-safe (a capture failure never raises)."""
    from dataclasses import asdict
    st = store or EvidenceStore()
    want = _host(base) if base else None
    evs = []
    for ex in exchanges:
        if want and _host(ex.get("url", "")) != want:
            continue
        try:
            ev = capture_exchange(method=ex.get("method", "GET"), url=ex.get("url", ""),
                                  req_headers=ex.get("req_headers"), req_body=ex.get("req_body", ""),
                                  status=ex.get("status", 0), resp_headers=ex.get("resp_headers"),
                                  resp_body=ex.get("resp_body", ""), role="baseline",
                                  detail="captured", store=st)
            evs.append(asdict(ev))
        except Exception:
            continue
    return {"evidence": evs, "auth": extract_auth(exchanges, base), "endpoints": endpoints(exchanges, base),
            "n": len(evs)}


def session_factory(auth: dict, base: str = None):
    """Build a session_for_role(role)->requests.Session from captured auth material, matching the exact
    contract run_hunt/make_execute/AuthzOracle use. The CAPTURED (authenticated) identity is served for every
    role EXCEPT an explicit anon/unauth role, which gets a clean UNAUTHENTICATED session so the cross-role
    AuthzOracle can prove over-reach. No login round-trip -- the session is already authenticated by capture."""
    cookies = dict((auth or {}).get("cookies") or {})
    headers = dict((auth or {}).get("headers") or {})

    def session_for_role(role=None):
        import requests
        try:
            requests.packages.urllib3.disable_warnings()
        except Exception:
            pass
        s = requests.Session(); s.verify = False
        if str(role or "").lower() in _ANON:
            return s                                   # baseline: unauthenticated on purpose
        for k, v in cookies.items():
            try:
                s.cookies.set(k, v)
            except Exception:
                pass
        s.headers.update(headers)
        return s
    return session_for_role


def seeds_from_endpoints(eps, role: str = "owner") -> list:
    """Turn captured endpoints into iterative-hunt SEED MOVES against REAL routes (shapes mirror the live
    loop's own moves so they dispatch): a security-headers probe per surface, and an IDOR/BOLA sweep on any
    id-bearing surface (authenticated role vs anon baseline). De-duped; tagged seed='capture'."""
    seeds, seen = [], set()
    for ep in eps:
        path, method = ep.get("path", "/"), ep.get("method", "GET")
        if ("sh", path) not in seen:
            seen.add(("sh", path))
            seeds.append({"action": "security_headers", "surface": path, "path": path, "method": "GET",
                          "vuln_class": "security-misconfiguration", "technique": "security-headers",
                          "role": role, "seed": "capture", "intent": "foothold", "severity": "low"})
        if ep.get("id_bearing"):
            segs = [s for s in path.split("/") if s]
            # the collection is the path with the trailing id segment removed (the enumerable parent).
            coll = "/" + "/".join(segs[:-1]) if len(segs) > 1 else path
            if ("idor", coll) not in seen:
                seen.add(("idor", coll))
                seeds.append({"action": "idor", "collection": coll, "surface": path, "owner_role": role,
                              "attacker_roles": ["anon"], "sample": 5, "vuln_class": "broken-object-level-authz",
                              "technique": "idor.sweep", "role": role, "seed": "capture", "intent": "foothold",
                              "severity": "high"})
    return seeds


def load_capture(har, base: str = None, role: str = "owner", store: "EvidenceStore" = None) -> dict:
    """One-call bundle: parse -> ingest(evidence) -> auth/session_for_role -> endpoints -> seeds."""
    exchanges = parse_har(har)
    bundle = ingest(exchanges, store=store, base=base, role=role)
    bundle["session_for_role"] = session_factory(bundle["auth"], base)
    bundle["seeds"] = seeds_from_endpoints(bundle["endpoints"], role)
    bundle["authenticated"] = bool(bundle["auth"].get("cookies") or bundle["auth"].get("headers"))
    return bundle


def run_captured_hunt(objective: str, har, base: str, role: str = "owner", budget: int = 28,
                      store_path: str = None):
    """Glue: load the capture, then drive the EXISTING iterative hunt authenticated, seeded with the real
    captured surfaces. Returns the run_hunt result dict."""
    import iterative_hunt_live as ihl
    bundle = load_capture(har, base=base, role=role)
    print(f"[capture] authenticated={bundle['authenticated']} exchanges={bundle['n']} "
          f"endpoints={len(bundle['endpoints'])} seeds={len(bundle['seeds'])}", flush=True)
    return ihl.run_hunt(objective, role=role, budget=budget, store_path=store_path, base=base,
                        session_for_role=bundle["session_for_role"], extra_seeds=bundle["seeds"])


def record_mitm(port: int = 8899, out: str = "capture.flows"):
    """Optional convenience: start a live recording proxy (mitmdump) so a browser/mobile device pointed at
    127.0.0.1:<port> is recorded; export the flows to HAR afterwards and feed --har. Best-effort: requires
    mitmproxy on PATH. (The core engine consumes HAR; this is just a way to PRODUCE one.)"""
    import shutil, subprocess
    exe = shutil.which("mitmdump")
    if not exe:
        raise RuntimeError("mitmdump not found -- `pip install mitmproxy`, or capture with the browser/Burp "
                           "DevTools and pass the HAR to --har instead")
    print(f"[capture] recording on 127.0.0.1:{port} -> {out} (Ctrl-C to stop; trust the mitmproxy CA in the "
          f"client first). Then export to HAR and run with --har.", flush=True)
    return subprocess.call([exe, "--listen-port", str(port), "-w", out])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ARTEX-port #1: capture authenticated traffic -> authenticated hunt.")
    ap.add_argument("--har", help="HAR file captured from a browser/Burp/mitmproxy/mobile proxy")
    ap.add_argument("--base", default=os.environ.get("AEGIS_TARGET"), help="target base (scheme://host[:port])")
    ap.add_argument("--role", default="owner", help="role name the captured session represents")
    ap.add_argument("--objective", default="Find oracle-verified weaknesses on the captured authenticated surface.")
    ap.add_argument("--budget", type=int, default=28)
    ap.add_argument("--store", default=None, help="findings ledger path")
    ap.add_argument("--ingest-only", action="store_true", help="load + summarize the capture, do not hunt")
    ap.add_argument("--hunt", action="store_true", help="run the authenticated hunt on the captured surface")
    ap.add_argument("--record", action="store_true", help="start a live mitmdump recorder instead")
    ap.add_argument("--port", type=int, default=8899)
    a = ap.parse_args(argv)
    if a.record:
        return int(record_mitm(a.port) or 0)
    if not a.har:
        ap.error("--har is required (or use --record to capture first)")
    if a.hunt and not a.ingest_only:
        res = run_captured_hunt(a.objective, a.har, a.base, role=a.role, budget=a.budget, store_path=a.store)
        print(json.dumps({k: res.get(k) for k in ("confirmed", "attempts_used", "coverage", "assurance")},
                         indent=2, default=str))
        return 0
    bundle = load_capture(a.har, base=a.base, role=a.role)
    print(f"[capture] authenticated={bundle['authenticated']} exchanges={bundle['n']} "
          f"endpoints={len(bundle['endpoints'])} seeds={len(bundle['seeds'])}")
    print(f"[capture] auth: cookies={list(bundle['auth']['cookies'])} headers={list(bundle['auth']['headers'])}")
    for ep in bundle["endpoints"][:25]:
        print(f"    {ep['method']:6} {ep['path']}  id_bearing={ep['id_bearing']}  status={ep['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
