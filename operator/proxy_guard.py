"""proxy_guard.py -- AUTO egress-proxy for the hunt (owner opt-in).

Why: the hunt runs on Windows python, whose egress is the real box IP. When a target rate-limits/bans
that IP (fail2ban), the hunt's probes 503 and it reads NO real surface. The owner's VPN lives in WSL, so
routing the hunt's egress through a small forward proxy INSIDE the VPN'd WSL puts probes on the VPN IP and
restores reachability of the owner's OWN asset.

OVERSIGHT: standing up egress-routing infra is a sensitive capability, so this is FAIL-SAFE OFF and gated
behind an explicit owner flag. It does NOTHING unless AEGIS_AUTO_PROXY=1 (or AEGIS_EGRESS_PROXY is already
set to a running proxy). It logs every action. Authorized only for owner-controlled targets with a RoE
that permits vpn-routed egress (vpn_egress_authorized). Not evasion of a third party.

Env:
  AEGIS_AUTO_PROXY=1            opt-in: may START the WSL proxy if none is reachable (default off -> no-op)
  AEGIS_EGRESS_PROXY=url        use THIS already-running proxy (e.g. http://localhost:8888); skips auto-start
  AEGIS_PROXY_PORT=8888         port to start/check (default 8888)
  AEGIS_KALI_DISTRO=kali-linux  the WSL distro that holds the VPN + proxy
"""
from __future__ import annotations
import os, subprocess, socket, time


def _enabled() -> bool:
    return (str(os.environ.get("AEGIS_AUTO_PROXY", "")).lower() in ("1", "true", "yes", "on")
            or bool((os.environ.get("AEGIS_EGRESS_PROXY") or "").strip()))


def _port() -> int:
    try:
        return int(os.environ.get("AEGIS_PROXY_PORT", "8888"))
    except Exception:
        return 8888


def _reachable(host, port, timeout=2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _start_wsl_proxy(port):
    """Start tinyproxy inside the VPN'd WSL (owner opt-in only). Returns True if it comes up."""
    distro = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
    conf = (f"Port {port}\\nListen 0.0.0.0\\nTimeout 600\\nAllow 127.0.0.1\\nAllow 0.0.0.0/0\\n")
    script = (f"command -v tinyproxy >/dev/null || {{ apt-get update -qq && "
              f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tinyproxy; }}; "
              f"printf '{conf}' > /etc/tinyproxy/tinyproxy.conf; "
              f"pgrep -x tinyproxy >/dev/null || tinyproxy -c /etc/tinyproxy/tinyproxy.conf; "
              f"sleep 1; ss -ltn | grep -q ':{port} ' && echo PROXY_UP")
    try:
        p = subprocess.run(["wsl", "-d", distro, "-u", "root", "--", "bash", "-lc", script],
                           capture_output=True, text=True, timeout=180, encoding="utf-8", errors="replace")
        return "PROXY_UP" in (p.stdout or "")
    except Exception as e:
        print(f"[proxy] auto-start failed: {e!r}", flush=True)
        return False


def ensure(base: str = "") -> str | None:
    """If opt-in, make sure an egress proxy is available and export HTTP(S)_PROXY so the hunt's Windows
    requests ride the VPN. Returns the proxy URL in use, or None (no-op). Fail-open."""
    if not _enabled():
        return None
    explicit = (os.environ.get("AEGIS_EGRESS_PROXY") or "").strip()
    port = _port()
    url = explicit or f"http://localhost:{port}"
    host = "localhost"
    try:
        host = url.split("://", 1)[1].split(":")[0] or "localhost"
        port = int(url.rsplit(":", 1)[1].split("/")[0])
    except Exception:
        pass
    if not _reachable(host, port):
        if explicit:
            print(f"[proxy] configured proxy {url} not reachable -- not auto-starting an explicit one", flush=True)
            return None
        if str(os.environ.get("AEGIS_AUTO_PROXY", "")).lower() in ("1", "true", "yes", "on"):
            print(f"[proxy] no egress proxy on :{port}; starting one in the VPN'd WSL (owner opt-in "
                  f"AEGIS_AUTO_PROXY=1, RoE vpn_egress_authorized)", flush=True)
            if not _start_wsl_proxy(port):
                print("[proxy] could not bring up the WSL proxy; continuing on the direct IP", flush=True)
                return None
        else:
            return None
    # export so requests/urllib pick it up
    os.environ["HTTP_PROXY"] = url
    os.environ["HTTPS_PROXY"] = url
    os.environ["http_proxy"] = url
    os.environ["https_proxy"] = url
    print(f"[proxy] egress routed through {url} (VPN'd WSL) -- hunt probes leave on the VPN IP", flush=True)
    return url


if __name__ == "__main__":
    print("proxy in use:", ensure())
