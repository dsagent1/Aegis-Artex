"""wp_enum.py -- WordPress plugin/theme + REAL-VERSION harvest (version-obfuscation-resistant discovery).

A hardened WP scrubs the core version (generator meta, core ?ver=), but it still LEAKS plugin/theme
versions: every enqueued plugin asset carries `?ver=<plugin version>`, and `/wp-content/plugins/<slug>/
readme.txt` carries `Stable tag:`. Plugins are the real attack surface (most WP CVEs live there), so this
turns the obfuscation's leak into concrete per-plugin version leads -> map each to a public exploit /
patch-diff / CVE.

Discovery only (GETs). Honors the egress proxy (HTTPS_PROXY / AEGIS_EGRESS_PROXY) + AEGIS_HOST_HEADER so it
reads the real origin behind a WAF. Offline-safe: returns {} on failure.
"""
from __future__ import annotations
import os, re, json, ssl, urllib.request

_UCTX = ssl._create_unverified_context()
_PLUGIN_ASSET = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9._-]+)/[^\"'?>]*\?ver=([0-9][0-9.]*)", re.I)
_THEME_ASSET = re.compile(r"/wp-content/themes/([a-z0-9][a-z0-9._-]+)/[^\"'?>]*\?ver=([0-9][0-9.]*)", re.I)
_PLUGIN_REF = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9._-]+)/", re.I)
_THEME_REF = re.compile(r"/wp-content/themes/([a-z0-9][a-z0-9._-]+)/", re.I)
_STABLE = re.compile(r"Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", re.I)
_RVER = re.compile(r"^\s*Version:\s*([0-9][0-9A-Za-z.\-]*)", re.I | re.M)


def _opener():
    handlers = [urllib.request.HTTPSHandler(context=_UCTX)]
    px = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
          or os.environ.get("AEGIS_EGRESS_PROXY") or "").strip()
    if px:
        handlers.append(urllib.request.ProxyHandler({"http": px, "https": px}))
    return urllib.request.build_opener(*handlers)


def _get(base, path, host_header=None, timeout=12):
    try:
        req = urllib.request.Request(base.rstrip("/") + path, headers={"User-Agent": "Mozilla/5.0"})
        if host_header:
            req.add_header("Host", host_header)
        with _opener().open(req, timeout=timeout) as r:
            return r.getcode(), r.read(400000).decode("utf-8", "replace")
    except Exception:
        return 0, ""


def harvest(base, host_header=None):
    host_header = host_header or (os.environ.get("AEGIS_HOST_HEADER") or "").strip() or None
    plugins, themes = {}, {}

    def _note(d, slug, ver, src):
        slug = slug.lower()
        if slug in ("", "index"):
            return
        cur = d.get(slug)
        # prefer a concrete version over none; keep the first concrete one
        if cur is None or (cur.get("version") is None and ver):
            d[slug] = {"slug": slug, "version": ver, "source": src}

    # 1) harvest ?ver= from several pages (home + search + a feed often enqueue different assets)
    for path in ("/", "/?s=a", "/feed/", "/wp-login.php", "/?p=1"):
        st, body = _get(base, path, host_header)
        if st == 0 or not body:
            continue
        for slug, ver in _PLUGIN_ASSET.findall(body):
            _note(plugins, slug, ver, f"?ver= on {path}")
        for slug, ver in _THEME_ASSET.findall(body):
            _note(themes, slug, ver, f"?ver= on {path}")
        for slug in set(_PLUGIN_REF.findall(body)):
            _note(plugins, slug, None, f"ref on {path}")
        for slug in set(_THEME_REF.findall(body)):
            _note(themes, slug, None, f"ref on {path}")

    # 2) confirm/obtain exact versions from readme.txt (plugins) and style.css (themes)
    for slug, info in list(plugins.items())[:40]:
        st, body = _get(base, f"/wp-content/plugins/{slug}/readme.txt", host_header)
        if st == 200 and body:
            m = _STABLE.search(body)
            if m:
                info["version"] = m.group(1)
                info["source"] = "readme.txt Stable tag"
    for slug, info in list(themes.items())[:20]:
        st, body = _get(base, f"/wp-content/themes/{slug}/style.css", host_header)
        if st == 200 and body:
            m = _RVER.search(body)
            if m:
                info["version"] = m.group(1)
                info["source"] = "style.css Version"

    # 3) wp-json surface (real routes -> behavioral probing, version-independent)
    st, body = _get(base, "/wp-json/", host_header)
    routes = sorted(set(re.findall(r'"(/wp/v2/[a-z0-9_\-/{}]+)"', body)))[:30] if st == 200 else []
    st_u, _ = _get(base, "/wp-json/wp/v2/users", host_header)

    return {
        "plugins": sorted(plugins.values(), key=lambda x: x["slug"]),
        "themes": sorted(themes.values(), key=lambda x: x["slug"]),
        "wp_json_routes": routes,
        "user_enum_open": st_u == 200,
    }


def leads(base, host_header=None):
    """Harvest -> per-plugin/theme version leads the code bench / patch_differ can chase (CVE/patch-diff)."""
    h = harvest(base, host_header)
    out = []
    for kind in ("plugins", "themes"):
        for it in h.get(kind, []):
            if it.get("version"):
                out.append({"component": it["slug"], "kind": kind[:-1], "version": it["version"],
                            "surface": f"/wp-content/{kind}/{it['slug']}/", "source": it["source"]})
    return {"leads": out, **h}


if __name__ == "__main__":
    import sys
    b = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(leads(b, os.environ.get("AEGIS_HOST_HEADER", "example.com")), indent=2)[:2500])
