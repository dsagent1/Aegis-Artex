"""origin_resolver.py -- AUTONOMOUS WAF/origin resolution for the hunt.

The problem it fixes (self-diagnosing, no human config): when the primary target is behind a CDN/WAF
(e.g. Cloudflare 403s every path) the hunt reads NO real surface and the board HALLUCINATES endpoints
("phantom surface"). A human had to notice the origin was leaked (mail/cpanel subdomain -> non-CDN IP)
and that the origin vhosts on `Host:`. This module does that itself:

  1. probe the front door; if it serves a real app, use it unchanged.
  2. else (WAF/403/challenge/unreachable) ENUMERATE origin candidates -- CT logs + a built-in list of
     origin-leaking subdomains (mail/cpanel/webmail/webdisk/direct/ftp/autodiscover...) -> resolve ->
     keep NON-CDN IPs.
  3. for each candidate IP, fetch https://IP/ with `Host: <domain>`; the one that returns a real app
     (2xx/3xx with substantive, non-challenge HTML that DIFFERS from the WAF page) is the origin.
  4. return (effective_base = scheme://origin_ip, host_header = domain) and set AEGIS_HOST_HEADER so the
     session factory + crawler hit the real vhost. Everything downstream then reads the REAL surface.

Offline-safe + fail-open: any failure returns the original target unchanged (never breaks a run).
Gate AEGIS_AUTO_ORIGIN=0 to disable.
"""
from __future__ import annotations
import os, re, socket, ssl, ipaddress, urllib.request

_CF_NETS = [ipaddress.ip_network(c) for c in (
    "104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18", "141.101.64.0/18",
    "162.158.0.0/15", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22")]
# other big CDN/WAF fronts whose IPs are NOT the origin
_CDN_HINT = ("cloudflare", "akamai", "fastly", "sucuri", "incapsula", "imperva", "stackpath")
_LEAKY_SUBS = ("mail", "cpanel", "webmail", "webdisk", "direct", "origin", "ftp", "autodiscover",
               "cpcalendars", "cpcontacts", "server", "ns1", "ns2", "mx", "smtp", "vps", "host")
_UCTX = ssl._create_unverified_context()


def _enabled():
    return str(os.environ.get("AEGIS_AUTO_ORIGIN", "1")).lower() not in ("0", "false", "no", "off")


def _is_cdn_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _CF_NETS)
    except Exception:
        return False


def _resolve(host: str):
    out = []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
            ip = sa[0]
            if ":" not in ip and ip not in out:   # IPv4 origins only (simpler, usually the leaked one)
                out.append(ip)
    except Exception:
        pass
    return out


def _opener():
    """Opener that HONORS the egress proxy (HTTPS_PROXY/AEGIS_EGRESS_PROXY) explicitly -- the default
    urlopen does not reliably pick it up when a custom SSL context is passed, which silently sent probes
    out the direct (banned) IP."""
    handlers = [urllib.request.HTTPSHandler(context=_UCTX)]
    px = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
          or os.environ.get("AEGIS_EGRESS_PROXY") or "").strip()
    if px:
        handlers.append(urllib.request.ProxyHandler({"http": px, "https": px}))
    return urllib.request.build_opener(*handlers)


def _fetch(url, host_header=None, timeout=12):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        if host_header:
            req.add_header("Host", host_header)
        with _opener().open(req, timeout=timeout) as r:
            body = r.read(60000).decode("utf-8", "replace")
            return r.getcode(), dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), (e.read(20000).decode("utf-8", "replace"))
        except Exception:
            return e.code, {}, ""
    except Exception:
        return 0, {}, ""


def _waf_blocked(status, headers, body) -> bool:
    if status in (0, 401, 403, 406, 429, 503):
        return True
    srv = " ".join(str(v).lower() for v in (headers or {}).values())
    if any(h in srv for h in _CDN_HINT) and status >= 400:
        return True
    # A CHALLENGE page is SMALL and carries a challenge marker. A large, real app page that merely MENTIONS
    # a CDN (because the site sits behind one) is NOT a block -- do not flag it (that false-positive hid the
    # real origin). Only short interstitials with a block/challenge phrase count.
    low = (body or "").lower()
    if len(body or "") < 3000 and any(s in low for s in (
            "attention required", "just a moment", "access denied", "request blocked",
            "captcha", "cf-browser-verification", "challenge-platform", "ddos protection")):
        return True
    return False


def _looks_like_app(status, body) -> bool:
    if status not in (200, 301, 302, 401):
        return False
    low = (body or "").lower()
    return len(body or "") > 400 and ("<html" in low or "<!doctype" in low or "<title" in low
                                      or "wp-content" in low or "set-cookie" in low)


def _ct_subdomains(domain):
    try:
        code, _, body = _fetch(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        names = set(re.findall(r'"name_value":"([^"]+)"', body or ""))
        subs = set()
        for n in names:
            for part in n.replace("\\n", " ").split():
                part = part.strip().lower().lstrip("*.")
                if part.endswith(domain):
                    subs.add(part)
        return subs
    except Exception:
        return set()


def resolve(target: str) -> dict:
    """Return {base, host_header, origin_ip, reason}. On success sets os.environ['AEGIS_HOST_HEADER']."""
    res = {"base": target, "host_header": None, "origin_ip": None, "reason": "front-door ok"}
    if not _enabled() or not target:
        return res
    m = re.match(r"^(https?)://([^/:]+)", target.strip())
    if not m:
        return res
    scheme, domain = m.group(1), m.group(2)
    # 1. front door
    st, hd, body = _fetch(target)
    if not _waf_blocked(st, hd, body) and _looks_like_app(st, body):
        res["reason"] = f"front door serves a real app ({st})"
        return res
    # 2. origin candidates
    cand_hosts = {f"{s}.{domain}" for s in _LEAKY_SUBS} | {domain, f"www.{domain}"}
    cand_hosts |= {h for h in _ct_subdomains(domain)}
    ips = []
    for h in sorted(cand_hosts):
        for ip in _resolve(h):
            if not _is_cdn_ip(ip) and ip not in ips:
                ips.append((ip, h))
    # 3. test each non-CDN IP with Host: domain -> real app?
    for ip, via in ips[:12]:
        for sch in (scheme, "https", "http"):
            st2, hd2, body2 = _fetch(f"{sch}://{ip}/", host_header=domain)
            if _looks_like_app(st2, body2) and not _waf_blocked(st2, hd2, body2):
                os.environ["AEGIS_HOST_HEADER"] = domain
                res.update({"base": f"{sch}://{ip}", "host_header": domain, "origin_ip": ip,
                            "reason": f"WAF on front door; origin {ip} (via {via}) serves the real app "
                                      f"with Host: {domain} ({st2}) -- routing the hunt through it"})
                return res
    res["reason"] = (f"front door looks WAF'd ({st}) but no origin confirmed from "
                     f"{len(ips)} non-CDN candidate(s); staying on the front door")
    return res


if __name__ == "__main__":
    import sys, json
    print(json.dumps(resolve(sys.argv[1] if len(sys.argv) > 1 else "https://chikov.com"), indent=2))
