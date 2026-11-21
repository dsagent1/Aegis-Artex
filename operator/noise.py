"""noise.py -- ARTEX-port B1: the NOISE GOVERNOR (request pacing + 429/503 backoff).

Paces the HTTP traffic Aegis sends to a TARGET so a hunt can run low-and-slow (evade rate limits / WAF
tarpits / accidental DoS of a fragile mirror). One global hook: it wraps `requests.Session.request`, which
every vector and oracle call funnels through (top-level requests.get/post also route through an internal
Session), so no per-call-site edits are needed.

CRUCIALLY it only paces the TARGET host(s) -- LLM/board/API traffic (api.deepseek.com, Cloudflare, ...) is
never slowed. Target hosts come from $AEGIS_TARGET (+ optional $AEGIS_NOISE_HOSTS). If no target host is
known, it paces all hosts (fail-safe-slow). Default OFF: with $AEGIS_NOISE_PROFILE unset it is a no-op and
nothing is patched, so behavior is identical to today.

    AEGIS_NOISE_PROFILE = quiet | balanced | aggressive
    AEGIS_NOISE_HOSTS   = extra host[:port] entries to pace, comma-separated (optional)
    AEGIS_NOISE_UA      = override the low-and-slow User-Agent (optional)

Profile = per-host min interval (s), jitter fraction, per-host max in-flight, backoff base (s), max retries,
          GLOBAL max in-flight (across hosts), short-GET cache TTL (s).

--- ARTEX-port B1 EXTENSION (parity with ARTEX egress/) ---
  * Retry-After respected on 429/503 (falls back to exponential backoff when the header is absent/bad).
  * GET coalescing + short-lived GET response cache: identical concurrent GETs to a paced host share ONE
    upstream request; a repeat GET inside the TTL is served from cache (fewer target requests = quieter).
  * GLOBAL in-flight cap across all paced hosts (on top of the per-host cap).
  * Configurable low-and-slow User-Agent injected on paced requests.
  * scanner_flags(tool): low-and-slow CLI flags for the installed scanners (nuclei/httpx/ffuf/katana/
    subfinder) so the Kali legs pace themselves to match the active profile.
"""
from __future__ import annotations
import os, time, threading, random
from urllib.parse import urlsplit

_PROFILES = {
    "quiet":      {"interval": 1.5, "jitter": 0.5, "inflight": 1, "backoff": 5.0, "retries": 4, "global": 2,  "cache_ttl": 8.0},
    "balanced":   {"interval": 0.4, "jitter": 0.3, "inflight": 3, "backoff": 2.0, "retries": 3, "global": 6,  "cache_ttl": 4.0},
    "aggressive": {"interval": 0.0, "jitter": 0.1, "inflight": 8, "backoff": 1.0, "retries": 2, "global": 20, "cache_ttl": 1.0},
}

# Low-and-slow CLI flags per scanner per profile: a blend-in rate (-rl) + concurrency (-c/-t) that matches
# the active target-noise profile. Consumed by the Kali legs via scanner_flags("nuclei"), etc.
_SCANNER_FLAGS = {
    "quiet":      {"nuclei": ["-rl", "10", "-c", "2"],  "httpx": ["-rl", "10", "-t", "2"],
                   "ffuf": ["-rate", "10", "-t", "2"],  "katana": ["-rl", "10", "-c", "2"],
                   "subfinder": ["-rl", "10"]},
    "balanced":   {"nuclei": ["-rl", "50", "-c", "10"], "httpx": ["-rl", "50", "-t", "10"],
                   "ffuf": ["-rate", "50", "-t", "10"], "katana": ["-rl", "50", "-c", "10"],
                   "subfinder": ["-rl", "50"]},
    "aggressive": {"nuclei": ["-rl", "150", "-c", "25"], "httpx": ["-rl", "150", "-t", "25"],
                   "ffuf": ["-rate", "150", "-t", "25"], "katana": ["-rl", "150", "-c", "25"],
                   "subfinder": ["-rl", "150"]},
}

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_state = {"installed": False, "last": {}, "sema": {}, "gsema": None, "gcap": 0,
          "cache": {}, "clocks": {}, "lock": threading.Lock()}


def _profile():
    name = (os.environ.get("AEGIS_NOISE_PROFILE") or "").strip().lower()
    return name if name in _PROFILES else None


def _ua() -> str:
    return (os.environ.get("AEGIS_NOISE_UA") or "").strip() or _DEFAULT_UA


def _host(url: str) -> str:
    try:
        return (urlsplit(url).netloc or "?").lower()
    except Exception:
        return "?"


def _target_hosts() -> set:
    hosts = set()
    t = os.environ.get("AEGIS_TARGET", "")
    if t:
        hosts.add(_host(t))
    for h in (os.environ.get("AEGIS_NOISE_HOSTS", "") or "").split(","):
        if h.strip():
            hosts.add(h.strip().lower())
    return hosts


def _should_pace(host: str) -> bool:
    th = _target_hosts()
    return (host in th) if th else True   # no declared target -> pace everything (fail-safe-slow)


def _sema(host: str, cap: int) -> threading.Semaphore:
    with _state["lock"]:
        s = _state["sema"].get(host)
        if s is None:
            s = threading.Semaphore(cap)
            _state["sema"][host] = s
        return s


def _global_sema(cap: int):
    """One process-wide semaphore bounding total in-flight paced requests across ALL hosts."""
    with _state["lock"]:
        if _state["gsema"] is None or _state["gcap"] != cap:
            _state["gsema"] = threading.Semaphore(cap)
            _state["gcap"] = cap
        return _state["gsema"]


def _clock(key) -> threading.Lock:
    """A per-(method,url) lock so identical concurrent GETs coalesce onto one upstream request."""
    with _state["lock"]:
        lk = _state["clocks"].get(key)
        if lk is None:
            lk = threading.Lock()
            _state["clocks"][key] = lk
        return lk


def _cache_get(key, ttl: float):
    if ttl <= 0:
        return None
    with _state["lock"]:
        ent = _state["cache"].get(key)
    if ent and ent[0] > time.time():
        return ent[1]
    return None


def _cache_put(key, resp, ttl: float) -> None:
    if ttl <= 0:
        return
    with _state["lock"]:
        _state["cache"][key] = (time.time() + ttl, resp)


def _pace(host: str, p: dict) -> None:
    with _state["lock"]:
        last = _state["last"].get(host, 0.0)
        wait = max(0.0, (last + p["interval"]) - time.time())
    if p["interval"]:
        wait += random.uniform(0, p["interval"] * p["jitter"])
    if wait > 0:
        time.sleep(wait)
    with _state["lock"]:
        _state["last"][host] = time.time()


def _retry_after(resp, p: dict, attempt: int) -> float:
    """How long to wait after a 429/503. Prefer the server's Retry-After (seconds form); otherwise fall
    back to exponential backoff with jitter. Capped so a hostile header can't stall the hunt for minutes."""
    try:
        ra = getattr(resp, "headers", {}).get("Retry-After")
        if ra is not None:
            secs = float(str(ra).strip())
            if secs >= 0:
                return min(secs, 120.0)
    except (TypeError, ValueError):
        pass   # http-date form or junk -> fall back to backoff
    return p["backoff"] * (2 ** attempt) + random.uniform(0, p["backoff"])


def scanner_flags(tool: str):
    """ARTEX-port B1: low-and-slow CLI flags for `tool` under the active profile, or [] when no profile is
    set / the tool is unknown. The Kali legs call this so their scanners pace themselves to match."""
    prof = _profile()
    if not prof:
        return []
    return list(_SCANNER_FLAGS.get(prof, {}).get((tool or "").lower(), []))


def install() -> bool:
    """Idempotent, env-gated. Returns True if the governor is active after the call. No-op (no patch) when
    AEGIS_NOISE_PROFILE is unset/invalid, so importing/calling this is always safe."""
    if _profile() is None:
        return False
    with _state["lock"]:
        if _state["installed"]:
            return True
        _state["installed"] = True
    try:
        import requests.sessions as _s
    except Exception:
        return False
    if getattr(_s.Session.request, "_aegis_governed", False):
        return True
    orig = _s.Session.request

    def _fetch(self, method, url, a, k, host, p):
        """One upstream request with pacing, UA injection and 429/503 retry (Retry-After aware)."""
        hdrs = dict(k.get("headers") or {})
        if not any(h.lower() == "user-agent" for h in hdrs):
            hdrs["User-Agent"] = _ua()
            k = dict(k, headers=hdrs)
        attempt = 0
        while True:
            _pace(host, p)
            resp = orig(self, method, url, *a, **k)
            sc = getattr(resp, "status_code", 0)
            if sc in (429, 503) and attempt < p["retries"]:
                time.sleep(_retry_after(resp, p, attempt))
                attempt += 1
                continue
            return resp

    def governed(self, method, url=None, *a, **k):
        p = _PROFILES.get(_profile())
        if not p or not url:
            return orig(self, method, url, *a, **k)
        host = _host(url)
        if not _should_pace(host):
            return orig(self, method, url, *a, **k)
        is_get = (method or "").upper() == "GET"
        key = ("GET", url) if is_get else None
        # GET cache: a repeat within the TTL skips the target entirely.
        if key is not None:
            hit = _cache_get(key, p["cache_ttl"])
            if hit is not None:
                return hit
        gsema = _global_sema(p["global"])
        sema = _sema(host, p["inflight"])
        gsema.acquire()
        try:
            sema.acquire()
            try:
                if key is not None:
                    # Coalesce identical concurrent GETs: contenders wait on the per-key lock, then the
                    # cache the winner filled satisfies them without a second upstream request.
                    clk = _clock(key)
                    with clk:
                        hit = _cache_get(key, p["cache_ttl"])
                        if hit is not None:
                            return hit
                        resp = _fetch(self, method, url, a, k, host, p)
                        if 200 <= getattr(resp, "status_code", 0) < 300:
                            _cache_put(key, resp, p["cache_ttl"])
                        return resp
                return _fetch(self, method, url, a, k, host, p)
            finally:
                sema.release()
        finally:
            gsema.release()

    governed._aegis_governed = True
    _s.Session.request = governed
    return True


def status() -> dict:
    return {"profile": _profile(), "installed": _state["installed"], "target_hosts": sorted(_target_hosts()),
            "ua": _ua() if _profile() else None,
            "global_cap": (_PROFILES.get(_profile()) or {}).get("global") if _profile() else None}
