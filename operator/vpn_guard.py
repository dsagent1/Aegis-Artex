"""vpn_guard.py -- AUTONOMOUS VPN rotation for the hunt engine (shared by all three run modes:
Operator / ExploitGym / Red-Team).

Why: a hardened target (fail2ban / WAF) BANS the tester's egress IP mid-run (sustained 403/429 or
connection failures). Previously only the co-pilot could rotate (its t_vpn_ctl tool); a bare hunt loop
dead-ended on the ban. This wires the rotation INTO the shared loop so the hunt rotates its OWN egress
country when it detects a ban -- a proper self-driving capability, not a tool a human drives.

Mechanism: drives the existing `vpn-ctl` (VyprVPN/OpenVPN) in Kali -- `list` to enumerate country
configs, `connect "<Country>"` to switch. The hunt picks the next country itself (round-robin over a
shuffled list, optionally constrained by AEGIS_VPN_COUNTRIES).

OPT-IN + FAIL-OPEN: does nothing unless AEGIS_VPN_ROTATE=1; any vpn-ctl error leaves the run untouched
(a VPN problem must never crash a hunt). All three modes import the shared engine, so they all get it.

Env:
  AEGIS_VPN_ROTATE=1            enable (default off -> no-op)
  AEGIS_VPN_COUNTRIES=a,b,c     restrict egress to these country config names (default: all)
  AEGIS_VPN_BAN_THRESHOLD=5     consecutive ban signals before a rotate
  AEGIS_VPN_ROTATE_COOLDOWN=90  min seconds between rotates (avoid thrash)
  AEGIS_KALI_DISTRO=kali-linux  the WSL distro that hosts vpn-ctl
"""
import os, subprocess, threading, time, random

_LOCK = threading.Lock()
_STATE = {"countries": None, "idx": -1, "bans": 0, "last_rotate": 0.0, "connected": False}
_BAN_STATUSES = {"403", "429", "503", "-1", "0", "000", "None", ""}


def _enabled() -> bool:
    return str(os.environ.get("AEGIS_VPN_ROTATE", "")).strip().lower() in ("1", "true", "yes", "on")


def _ctl(args, timeout=180):
    """Run `vpn-ctl <args>` in Kali as root. Returns (rc, combined_output). Never raises."""
    distro = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
    try:
        p = subprocess.run(["wsl", "-d", distro, "-u", "root", "--", "vpn-ctl"] + list(args),
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 1, f"[vpn-ctl error] {e!r}"


def _countries():
    if _STATE["countries"] is None:
        _, out = _ctl(["list"], timeout=30)
        cs = [ln.strip() for ln in out.splitlines()
              if ln.strip() and "error" not in ln.lower() and "usage" not in ln.lower()]
        allow = [c.strip() for c in os.environ.get("AEGIS_VPN_COUNTRIES", "").split(",") if c.strip()]
        if allow:
            cs = [c for c in cs if c in allow] or cs
        random.shuffle(cs)                      # don't start every run from the same country
        _STATE["countries"] = cs
    return _STATE["countries"]


def _connect_next():
    cs = _countries()
    if not cs:
        print("[vpn] no vpn-ctl country configs found -- rotation unavailable", flush=True)
        return False
    _STATE["idx"] = (_STATE["idx"] + 1) % len(cs)
    country = cs[_STATE["idx"]]
    rc, out = _ctl(["connect", country], timeout=200)
    ok = (rc == 0) or ("CONNECT_OK" in out)
    _STATE["connected"] = ok
    _STATE["last_rotate"] = time.time()
    _STATE["bans"] = 0
    tail = out.strip().splitlines()[-1][:160] if out.strip() else ""
    print(f"[vpn] {'CONNECT_OK' if ok else 'CONNECT_FAILED'} -> {country}: {tail}", flush=True)
    return ok


def ensure_connected():
    """Connect the VPN once at hunt start (opt-in, autonomous country pick). Fail-open."""
    if not _enabled():
        return
    with _LOCK:
        if _STATE["connected"]:
            return
        _connect_next()


def note_status(status, host=None):
    """Per-move hook: the hunt feeds every target response status here. On a sustained ban streak
    (403/429/503/connection-failure) the hunt rotates its own egress country. A 2xx/3xx clears the
    streak. Opt-in + fail-open."""
    if not _enabled():
        return
    s = str(status)
    with _LOCK:
        if s in _BAN_STATUSES:
            _STATE["bans"] += 1
        elif s[:1] in ("2", "3"):
            _STATE["bans"] = 0
            return
        else:
            return                               # 4xx other than 403/429 etc: not a ban signal
        try:
            thresh = int(os.environ.get("AEGIS_VPN_BAN_THRESHOLD", "5") or 5)
            cooldown = float(os.environ.get("AEGIS_VPN_ROTATE_COOLDOWN", "90") or 90)
        except Exception:
            thresh, cooldown = 5, 90.0
        if _STATE["bans"] >= thresh and (time.time() - _STATE["last_rotate"]) >= cooldown:
            print(f"[vpn] {_STATE['bans']} consecutive ban signals ({s}) from "
                  f"{host or 'target'} -> rotating egress country", flush=True)
            _connect_next()


def status_line() -> str:
    _, out = _ctl(["status"], timeout=20)
    return out.strip()[:200]
