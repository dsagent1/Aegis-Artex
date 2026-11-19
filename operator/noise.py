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

Profile = per-host min interval (s), jitter fraction, max in-flight, backoff base (s), max retries.
"""
from __future__ import annotations
import os, time, threading, random
from urllib.parse import urlsplit

_PROFILES = {
    "quiet":      {"interval": 1.5, "jitter": 0.5, "inflight": 1, "backoff": 5.0, "retries": 4},
    "balanced":   {"interval": 0.4, "jitter": 0.3, "inflight": 3, "backoff": 2.0, "retries": 3},
    "aggressive": {"interval": 0.0, "jitter": 0.1, "inflight": 8, "backoff": 1.0, "retries": 2},
}

_state = {"installed": False, "last": {}, "sema": {}, "lock": threading.Lock()}


def _profile():
    name = (os.environ.get("AEGIS_NOISE_PROFILE") or "").strip().lower()
    return name if name in _PROFILES else None


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

    def governed(self, method, url=None, *a, **k):
        p = _PROFILES.get(_profile())
        if not p or not url:
            return orig(self, method, url, *a, **k)
        host = _host(url)
        if not _should_pace(host):
            return orig(self, method, url, *a, **k)
        sema = _sema(host, p["inflight"])
        sema.acquire()
        try:
            attempt = 0
            while True:
                _pace(host, p)
                resp = orig(self, method, url, *a, **k)
                sc = getattr(resp, "status_code", 0)
                if sc in (429, 503) and attempt < p["retries"]:
                    time.sleep(p["backoff"] * (2 ** attempt) + random.uniform(0, p["backoff"]))
                    attempt += 1
                    continue
                return resp
        finally:
            sema.release()

    governed._aegis_governed = True
    _s.Session.request = governed
    return True


def status() -> dict:
    return {"profile": _profile(), "installed": _state["installed"], "target_hosts": sorted(_target_hosts())}
