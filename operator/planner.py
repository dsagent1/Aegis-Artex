#!/usr/bin/env python3
"""
planner.py -- THE PLANNER (stage 2): the prior-success Ranker + plan core that runs BEFORE the
iterative-hunt loop (see docs/PLANNER.md). It:

  1. FINGERPRINTS the target (surfaces / stack / roles / task-level).
  2. Queries the ALREADY-BUILT techniques DB (curated + learned + MITRE ATT&CK) via
     rag/technique_search.py for the best PRIOR-SUCCESSFUL (technique, tool) combos -- ranked by the
     DB's keyword x learned-EV scoring, enriched with the learned co-occurrence ("if A worked, also
     try B").
  3. Emits those as ranked MODE-1 anchor `seed_moves` for the 40-attempt loop (so the hunt STARTS from
     what worked before + ATT&CK-informed anchors, then diversifies per the loop's own rules).
  4. On an oracle-VERIFIED success, WRITES BACK the winning technique+tool+scenario to the learned DB
     so the next plan ranks it higher (closed-loop learning).

Read-only DB query (shelled into Kali where /opt/aegis-rag lives) + append-only learn. No target action
happens here -- the Planner only proposes; the loop + oracle + doctrine gates still govern execution.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
RAG_HOME = os.environ.get("AEGIS_RAG_HOME", "/opt/aegis-rag")


def _shell_argv(distro, cmd):
    """Platform shim (see memory nested-wsl-shim): the RAG/techniques DB lives in Kali. On Windows we
    reach it via `wsl -d <distro>`; but when this code ALREADY runs INSIDE the Linux distro (the in-Kali
    hunt path -- sys.platform != 'win32'), there is no wsl.exe, so a bare ['wsl',...] call fails with
    Errno 2 and the Planner silently returns [] (no MITRE/techniques intel reaches the board). Run
    `bash -lc` locally in that case."""
    if sys.platform == "win32":
        return ["wsl", "-d", distro or WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd]
    return ["bash", "-lc", cmd]

# technique class -> which shared vector (vectors.py) an anchor move should use.
_NONWEB = {"recon", "supply_chain", "static", "fuzz", "misconfig", "rag"}
_WEB_FAMILIES = {"authz", "injection", "xss", "ssrf", "ssti", "xxe", "traversal", "auth",
                 "mass_assignment", "race", "csrf", "deserialization", "rate_enum",
                 "business_logic", "info_disclosure"}
# ATT&CK tactic-classes map to a reconnaissance/enumeration starting probe by default.
_ATTACK_RECON = {"reconnaissance", "discovery", "resource_development", "collection",
                 "credential_access", "lateral_movement", "privilege_escalation", "execution",
                 "persistence", "defense_evasion", "command_and_control", "exfiltration", "impact",
                 "initial_access"}


# DISCOVERY-PARITY vectors (operator/discovery.py): technique-class synonym -> discovery leg action.
_DISCOVERY = {
    "ldap": "ldap", "ad": "ldap", "active_directory": "ldap", "kerberos": "ldap", "bloodhound": "ldap",
    "cloud": "cloud", "aws": "cloud", "azure": "cloud", "gcp": "cloud", "container": "cloud",
    "fingerprint": "fingerprint", "portscan": "fingerprint", "port_scan": "fingerprint",
    "network_service_discovery": "fingerprint", "nmap": "fingerprint", "service_discovery": "fingerprint",
    "external": "external", "osint": "external", "subdomain": "external", "attack_surface": "external",
    "cert_transparency": "external", "passive_dns": "external",
    "cred_harvest": "cred_harvest", "smb": "cred_harvest", "share_enum": "cred_harvest", "secrets": "cred_harvest",
    "sbom": "sbom", "supply_chain_source": "sbom", "lockfile": "sbom",
    "rag_infer": "rag_infer", "cross_domain": "rag_infer", "inference": "rag_infer",
    "authz_fuzz": "authz_fuzz", "jwt": "authz_fuzz", "auth_bypass": "authz_fuzz", "token_fuzz": "authz_fuzz",
    "depconf": "depconf", "dependency_confusion": "depconf", "typosquat": "depconf",
    "honeypot": "honeypot", "deception": "honeypot",
    "attackpath": "attackpath", "attack_path": "attackpath", "path_analysis": "attackpath",
}


def _class_to_action(cls: str) -> str:
    c = (cls or "").lower()
    if c in _DISCOVERY:
        return _DISCOVERY[c]
    if c in _NONWEB:
        return c
    if c in _WEB_FAMILIES:
        return "web"
    if c in _ATTACK_RECON:
        return "recon"
    return "web"


_CRAWL_CACHE = {}
def crawl_surfaces(base, cap=None):
    """GENERAL surface discovery -- the engine's missing recon stage. Reads the target's OWN root HTML +
    linked JS bundles + any OpenAPI/Swagger doc and extracts real endpoint paths (/api/.., /rest/..,
    /graphql, ..). TARGET-DRIVEN (the app tells us its endpoints), NOT a hardcoded path list -- so it
    generalises to any web app / SPA instead of guessing /api/auth/login. Offline-safe ([] on any
    failure), same-origin, cached per base. Gate AEGIS_CRAWL=0; caps AEGIS_CRAWL_CAP (150) / AEGIS_CRAWL_JS (12)."""
    if str(os.environ.get("AEGIS_CRAWL", "1")).lower() in ("0", "false", "no", "off"):
        return []
    base = (base or "").rstrip("/")
    if not base:
        return []
    if base in _CRAWL_CACHE:
        return _CRAWL_CACHE[base]
    import re as _re
    cap = int(cap or os.environ.get("AEGIS_CRAWL_CAP", "150")); js_cap = int(os.environ.get("AEGIS_CRAWL_JS", "12"))
    import time as _time
    _tries = int(os.environ.get("AEGIS_CRAWL_RETRIES", "4"))
    def _get1(u):
        try:
            import requests as _rq
            try: _rq.packages.urllib3.disable_warnings()
            except Exception: pass
            r = _rq.get(u, timeout=15, verify=False, headers={"User-Agent": "aegis-crawler"}, allow_redirects=True)
            return r.text, r.status_code
        except Exception:
            try:
                import urllib.request as _u
                with _u.urlopen(_u.Request(u, headers={"User-Agent": "aegis-crawler"}), timeout=15) as rr:
                    return rr.read().decode("utf-8", "replace"), rr.getcode()
            except Exception:
                return "", None
    def _get(u, retry=False):
        # cold WSL2/self-signed targets can reset the FIRST connection -> retry so discovery is reliable,
        # not a coin-flip. Only the critical fetches (root, JS bundles) retry; doc-probes are best-effort.
        body, code = _get1(u)
        if retry:
            n = 1
            while (not body or code is None) and n < _tries:
                _time.sleep(0.6 * n); body, code = _get1(u); n += 1
        return body, code
    found = set()
    html, _ = _get(base + "/", retry=True)
    for m in _re.findall(r'(?:href|action)=["\'](/[^"\'>#?]+)', html or "", _re.I):
        found.add(m)
    scripts = _re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html or "", _re.I)
    PATH = _re.compile(r'["\'`](/(?:rest|api|graphql|socket\.io|b2b|ftp|metrics|redirect|profile|'
                       r'login|signin|user|users|auth|session|account|admin|oauth|token|v\d)'
                       r'[A-Za-z0-9_\-/.{}:%]*)["\'`]')
    for s in scripts[:js_cap]:
        u = s if s.startswith("http") else base + "/" + s.lstrip("/")
        js, _ = _get(u, retry=True)
        if js:
            for m in PATH.findall(js):
                found.add(m.split("?")[0].rstrip("/") or "/")
    for doc in ("/api-docs", "/swagger.json", "/openapi.json", "/v3/api-docs", "/api-docs/swagger.json"):
        body, _ = _get(base + doc)
        if body and body.lstrip().startswith("{"):
            try:
                import json as _json
                for p in (_json.loads(body).get("paths") or {}):
                    found.add(str(p).split("?")[0])
            except Exception:
                pass
    # FIRE THE ENGINE'S REAL CRAWL TOOLS (katana active+JS crawl, hakrawler) via distro_backend -> Kali, so
    # discovery is TOOL-DRIVEN and autonomous (not just the inline regex fallback above). Same-origin paths
    # are merged in. Offline-safe (tools absent / Kali down -> the regex pass still stands). Gate AEGIS_CRAWL_TOOLS=0.
    if str(os.environ.get("AEGIS_CRAWL_TOOLS", "1")).lower() not in ("0", "false", "no", "off"):
        try:
            from urllib.parse import urlsplit as _usplit
            base_host = _usplit(base).netloc
            import compare_recall as _cr
            adapters = [getattr(_cr, n, None) for n in ("adapt_katana", "adapt_hakrawler", "adapt_gospider")]
            for adapt in [a for a in adapters if a]:
                try:
                    items, _summ = adapt(base + "/")
                except Exception:
                    continue
                for s in (items or []):
                    m = _re.search(r'(https?://[^\s"\'<>]+)', str(s))
                    if not m:
                        continue
                    sp = _usplit(m.group(1))
                    if sp.netloc and base_host and sp.netloc != base_host:
                        continue                                   # same-origin only
                    p = (sp.path or "").split("?")[0].rstrip("/") or "/"
                    if p and p != "/":
                        found.add(p)
        except Exception:
            pass
    _JUNK = ("%60", "%28", "%29", "%7c", "%7b", "%7d", "%24", "`", "|", "{", "}", "<", ">")
    _STATIC = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".gif",
               ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".wasm")
    def _ok(p):
        if not p.startswith("/") or len(p) <= 1 or len(p) > 120 or " " in p:
            return False
        pl = p.lower()
        if any(b in pl for b in _JUNK) or pl.endswith(_STATIC):
            return False
        return True
    out = sorted({p.split("#")[0] for p in found if _ok(p.split("#")[0])})[:cap]
    _CRAWL_CACHE[base] = out
    return out


# OBJECTIVE-DRIVEN SURFACE EVALUATION: discovery finds MANY endpoints; with a bounded budget the engine must
# attack the ones MOST LIKELY to achieve the stated objective FIRST, not sweep them alphabetically. This is the
# "evaluate discovered capabilities, then generate moves" stage. Deterministic (no model call, free, fast),
# general heuristic = endpoint-semantics value x objective-alignment, noise down-weighted. Returns surfaces
# HIGHEST-VALUE-FIRST so every downstream [:cap] slice keeps the best. Gate AEGIS_RANK_SURFACES=0.
_SURF_VALUE = {
    "login": 7, "signin": 7, "authenticate": 6, "session": 4, "token": 4, "oauth": 4, "jwt": 4,
    "password": 5, "reset": 4, "whoami": 3, "admin": 7, "account": 5, "role": 5, "privilege": 5,
    "user": 5, "users": 5, "profile": 4,
    "search": 5, "query": 4, "find": 4, "filter": 4, "product": 3, "report": 4, "render": 4,
    "template": 5, "feedback": 4, "complaint": 3, "comment": 4, "memory": 3, "message": 3, "note": 3,
    "upload": 5, "file": 4, "import": 4, "avatar": 3, "photo": 3, "image": 2,
    "order": 4, "payment": 5, "invoice": 4, "wallet": 5, "card": 5, "basket": 4, "deluxe": 4,
    "balance": 4, "coupon": 4, "address": 3, "securityanswer": 5, "securityquestion": 3,
    "redirect": 4, "fetch": 5, "proxy": 4, "callback": 3, "url": 3, "track": 3, "graphql": 5,
}
_SURF_NOISE = ("captcha", "socket.io", "i18n", "assets", "favicon", "robots", "sitemap",
               ".well-known", "metrics", "health", "ping", "video", "web3", "country-mapping",
               "chatbot", "languages")
_OBJ_THEMES = {
    "idor": ("user", "users", "account", "order", "basket", "card", "address", "invoice", "wallet"),
    "access": ("admin", "user", "users", "account", "role", "profile"),
    "auth": ("login", "signin", "authenticate", "password", "reset", "token", "session"),
    "inject": ("search", "query", "find", "filter", "product", "login"),
    "sql": ("search", "login", "product", "query", "find"),
    "xss": ("search", "feedback", "comment", "product", "message", "memory"),
    "ssrf": ("fetch", "url", "proxy", "redirect", "callback", "image"),
    "upload": ("upload", "file", "import", "avatar"),
    "misconfig": ("admin", "metrics", "config", "debug", "api-docs"),
    "redirect": ("redirect", "url", "callback"),
}
def rank_surfaces(surfaces, objective="", stack=None):
    uniq = list(dict.fromkeys(s for s in (surfaces or []) if s))
    if str(os.environ.get("AEGIS_RANK_SURFACES", "1")).lower() in ("0", "false", "no", "off"):
        return uniq
    obj = (objective or "").lower()
    def score(s):
        sl = s.lower(); sc = 0.0
        for tok, w in _SURF_VALUE.items():
            if tok in sl:
                sc += w
        if any(n in sl for n in _SURF_NOISE):
            sc -= 8
        for theme, toks in _OBJ_THEMES.items():          # the stated goal steers the ranking
            if theme in obj and any(t in sl for t in toks):
                sc += 3
        if sl.startswith(("/api/", "/rest/")):
            sc += 1
        sc -= 0.3 * sl.count("/")                         # prefer shallow collections over deep/templated
        return sc
    return sorted(uniq, key=lambda s: (-score(s), s))


def _seed_priority(move, objective=""):
    """Objective-value of a seed MOVE (higher = scheduled earlier). The budget is small; the loop must
    START with the moves most likely to achieve the objective (auth-bypass / SQLi / IDOR / XSS) rather than
    sweep low-value classes and never reach them. Move-level analog of rank_surfaces -> together they make
    the whole discover -> evaluate -> attack pipeline objective-driven. Gate AEGIS_RANK_SEEDS=0."""
    if not isinstance(move, dict):
        return 0.0
    blob = " ".join(str(move.get(k) or "") for k in ("vuln_class", "action", "technique", "angle")).lower()
    sc = 0.0
    W = {"auth_bypass": 9, "sql_raw": 9, "sql": 8, "broken-authentication": 7, "injection": 5,
         "idor": 6, "broken-access": 6, "access-control": 6, "xss": 6, "cross-site-scripting": 6,
         "ssrf": 5, "mass-assign": 5, "mass_assign": 5, "file-upload": 5, "file_upload": 5,
         "nuclei": 4, "known-vuln": 4, "security-misconfig": 4, "misconfig": 4, "nested-write": 4,
         "security_headers": 2, "rate": 3, "csrf": 3, "open-redirect": 3, "open_redirect": 3}
    for k, w in W.items():
        if k in blob:
            sc += w
    sc += {"high": 3, "medium": 1, "low": 0}.get((move.get("severity") or "").lower(), 0)
    if move.get("auth_bypass"):
        sc += 4
    obj = (objective or "").lower()
    for kw in ("idor", "access", "auth", "inject", "sql", "xss", "ssrf", "upload", "redirect", "misconfig"):
        if kw in obj and kw[:3] in blob:
            sc += 2
    return sc


# CANDIDATE-PLAN SCENARIOS (stage 3): each varies technique ORDER, novel-probe budget, surface
# priority. `fit` weights which scenario leads per task-level (fact-finding favours covert/thorough;
# a pentest favours fast-track). The board can still devise novel moves inside every scenario.
_SCENARIOS = [
    {"name": "fast-track",
     "desc": "highest-impact injection/authz/logic classes first, few novel probes -- reach a foothold fast",
     "emphasis": ["injection", "sql", "authz", "auth", "business_logic", "idor", "command"],
     "novel": 2, "fit": {"pentest": 3, "envelope-pushing": 2, "fact-finding": 1}},
    {"name": "thorough",
     "desc": "full breadth across every relevant class plus the most board-novel approaches",
     "emphasis": [],
     "novel": 5, "fit": {"pentest": 2, "envelope-pushing": 3, "fact-finding": 2}},
    {"name": "covert",
     "desc": "low-noise recon / misconfig / info-disclosure weighting -- map before you push",
     "emphasis": ["recon", "misconfig", "supply_chain", "information disclosure",
                  "info_disclosure", "discovery", "collection"],
     "novel": 3, "fit": {"pentest": 1, "envelope-pushing": 2, "fact-finding": 3}},
]


class Planner:
    def __init__(self, kali_distro: str = None, rag_home: str = None):
        self.distro = kali_distro or WSL_DISTRO
        self.rag_home = rag_home or RAG_HOME
        # Drive Kali up front: the RAG DB + toolset live inside it, so every RAG query / tool check
        # below needs it running. Boots a stopped distro (fail-safe; AEGIS_KALI_AUTOSTART=0 to skip).
        self.kali_up = ensure_kali(self.distro)

    # ---- techniques-DB query (shelled into Kali, JSON) ----
    def _ts(self, query: str, cls: str = None, limit: int = 12) -> list:
        cmd = f"cd {self.rag_home} && python3 technique_search.py --json --limit {int(limit)}"
        if cls:
            cmd += f" --class {cls}"
        cmd += f" {json.dumps(query)}"          # quoted query
        try:
            p = subprocess.run(_shell_argv(self.distro, cmd),
                               capture_output=True, text=True, timeout=120)
            out = (p.stdout or "").strip()
            i = out.find("[")
            return json.loads(out[i:]) if i >= 0 else []
        except Exception:
            return []

    def _cooccur(self, cls: str, limit: int = 6) -> list:
        cmd = (f"cd {self.rag_home} && python3 technique_search.py --json --cooccur {cls} "
               f"--limit {int(limit)}")
        try:
            p = subprocess.run(_shell_argv(self.distro, cmd),
                               capture_output=True, text=True, timeout=60)
            out = (p.stdout or "").strip()
            i = out.find("{")
            return (json.loads(out[i:]).get("related_techniques", []) if i >= 0 else [])
        except Exception:
            return []

    # ---- plan building ----
    # ---- RECON auto-detect: derive the ACTUAL stack from the live target (so relevance is data-driven) ----
    # Signal -> stack-term maps. Kept small + high-signal; extend as needed.
    _RECON_SERVER = {"caddy": ["caddy"], "nginx": ["nginx"], "apache": ["apache"],
                     "werkzeug": ["python", "flask"], "gunicorn": ["python"], "uvicorn": ["python", "asgi"],
                     "express": ["node", "express"], "kestrel": ["dotnet"], "iis": ["dotnet", "windows"]}
    _RECON_XPB = {"express": ["node", "express"], "php": ["php"], "asp.net": ["dotnet"],
                  "next.js": ["node", "nextjs", "react"], "servlet": ["java"]}
    _RECON_COOKIE = {"connect.sid": ["node", "express"], "laravel_session": ["php", "laravel"],
                     "jsessionid": ["java"], "phpsessid": ["php"], "csrftoken": ["python", "django"],
                     "sessionid": ["python", "django"], "_rails": ["ruby", "rails"]}
    _RECON_BODY = {"__next_data__": ["node", "nextjs", "react"], "/_next/": ["node", "nextjs", "react"],
                   "ng-version": ["angular"], "data-reactroot": ["react"], "id=\"root\"": ["spa"],
                   "wp-content": ["php", "wordpress"], "csrfmiddlewaretoken": ["python", "django"],
                   "prisma": ["node", "prisma"], "fielderrors": ["node", "zod"], "/assets/index-": ["vite"]}

    def _detect_stack(self, base: str, timeout: int = 5) -> list:
        """Infer the target's stack from live HTTP signals (Server / X-Powered-By / Set-Cookie / body).
        In-process (portable: Windows or inside Kali). Fail-safe: any error -> [] (fall back to generic
        terms). Disable with AEGIS_PLANNER_RECON=0."""
        if not base or os.environ.get("AEGIS_PLANNER_RECON", "1") == "0":
            return []
        if not str(base).lower().startswith("http"):
            base = "https://" + str(base)
        try:
            import requests
            try:
                requests.packages.urllib3.disable_warnings()
            except Exception:
                pass
        except Exception:
            return []
        found = set()
        for path in ("/", "/api", "/api/auth/login"):
            try:
                r = requests.get(base.rstrip("/") + path, verify=False, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            srv = (r.headers.get("Server") or "").lower()
            for k, v in self._RECON_SERVER.items():
                if k in srv:
                    found.update([k] + v)
            xpb = (r.headers.get("X-Powered-By") or "").lower()
            for k, v in self._RECON_XPB.items():
                if k in xpb:
                    found.update(v)
            sc = (r.headers.get("Set-Cookie") or "").lower()
            for k, v in self._RECON_COOKIE.items():
                if k in sc:
                    found.update(v)
            ct = (r.headers.get("Content-Type") or "").lower()
            if "json" in ct:
                found.update(["api", "json"])
            body = (r.text or "")[:20000].lower()
            for k, v in self._RECON_BODY.items():
                if k in body:
                    found.update(v)
        return sorted(found)

    def fingerprint(self, target: str, surfaces=None, roles=None, stack=None,
                    task_level: str = "fact-finding", objective: str = "") -> dict:
        # RELEVANCE IS DATA-DRIVEN: if the caller didn't pin a stack, auto-detect it from the live target
        # (recon), then MERGE with anything passed -- so ranked techniques + board novelty stay ON-STACK.
        detected = self._detect_stack(target)
        stk = sorted(set(list(stack or [])) | set(detected))
        # SURFACE DISCOVERY (general recon): if the caller didn't pin surfaces, crawl the live target for its
        # OWN endpoints -- so every surface-driven seed (frontdoor/rate/idor/breadth/sqli) targets REAL routes
        # instead of hardcoded fallbacks like /api/auth/login. Same data-driven posture as stack auto-detect.
        passed = list(surfaces or [])
        crawled = passed if passed else crawl_surfaces(target)
        # EVALUATE discovered surfaces against the objective and store HIGHEST-VALUE-FIRST, so the bounded
        # budget's capped seeds attack the most promising endpoints first instead of alphabetically.
        surf = rank_surfaces(passed or crawled, objective, stk)
        return {"target": target, "surfaces": surf, "roles": roles or ["owner"],
                "stack": stk, "stack_detected": detected, "task_level": task_level,
                "crawled_surfaces": surf, "objective": objective,
                "terms": " ".join([task_level] + stk + list(surf)[:8])}

    def rank(self, fp: dict, limit: int = 12) -> list:
        """Ranked prior-successful techniques for the fingerprint. DB order (keyword x learned-EV) is
        kept; co-occurring techniques for the top class are appended as 'test-next' anchors."""
        seen, ranked = set(), []
        # a query per surface (falls back to the fingerprint terms) surfaces the most relevant techniques
        queries = [fp["terms"]] + [f"{fp['terms']} {s}" for s in (fp.get("surfaces") or [])]
        for q in queries:
            for t in self._ts(q, limit=limit):
                tid = t.get("id")
                if tid and tid not in seen:
                    seen.add(tid); ranked.append(t)
        # enrich: if the top technique's class has learned co-occurrence, pull those techniques too
        if ranked:
            for t in self._cooccur(ranked[0].get("class", ""), limit=4):
                tid = t.get("id")
                if tid and tid not in seen:
                    seen.add(tid); t["_via"] = "cooccurrence"; ranked.append(t)
        return ranked[:max(limit, 12)]

    # ---- RELEVANCE: not every DB/ATT&CK technique applies to THIS environment ----
    _STACK_PLATFORMS = {
        "linux": "Linux", "ubuntu": "Linux", "debian": "Linux", "kali": "Linux", "nginx": "Linux",
        "windows": "Windows", "iis": "Windows", ".net": "Windows", "active directory": "Windows",
        "ad": "Windows", "macos": "macOS", "docker": "Containers", "kubernetes": "Containers",
        "k8s": "Containers", "container": "Containers", "aws": "IaaS", "gcp": "IaaS", "azure": "IaaS",
        "web": "Web", "http": "Web", "api": "Web", "node": "Linux", "django": "Linux", "flask": "Linux",
        "php": "Linux", "symfony": "Linux", "postgres": "Linux", "mysql": "Linux",
    }

    def _target_platforms(self, fp: dict) -> set:
        """Best-effort ATT&CK platforms for the target from its stack/surfaces. Empty => unknown
        (then we DON'T deterministically drop -- we let the board decide)."""
        plats = set()
        for term in (fp.get("stack") or []) + (fp.get("surfaces") or []) + [fp.get("target", "")]:
            for k, v in self._STACK_PLATFORMS.items():
                if k in str(term).lower():
                    plats.add(v)
        return plats

    def _platform_ok(self, t: dict, plats: set) -> bool:
        ap = set(t.get("applies_to") or [])
        if not ap or not plats:
            return True                                # no constraint / unknown target -> keep
        return bool(ap & plats)                        # keep only if platforms overlap

    def _board(self, sysp: str, user: str, max_tokens: int = 1400) -> str:
        import sys as _s
        _s.path.insert(0, HERE)
        try:
            import remediation_board as RB
            ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
            return RB._post_openai_style(ep + "/chat/completions", os.environ.get("AEGIS_LLM_API_KEY", ""),
                                         os.environ.get("AEGIS_BOARD_MODEL", "deepseek-v4-flash"),
                                         sysp, user, max_tokens, think=False) or ""
        except Exception:
            return ""

    def select(self, ranked: list, fp: dict, board: bool = True, keep: int = 12) -> list:
        """Filter DB candidates down to what's RELEVANT to this environment: a deterministic platform
        pre-filter, then the BOARD picks the applicable techniques (drops e.g. Windows/AD techniques on a
        Linux web app). Offline-safe: if the board is unavailable, keep the platform-filtered set."""
        plats = self._target_platforms(fp)
        cands = [t for t in ranked if self._platform_ok(t, plats)]
        if not board or not cands:
            return cands[:keep]
        brief = [{"id": t.get("id"), "class": t.get("class"), "platforms": t.get("applies_to"),
                  "tactics": t.get("mitre_tactics"), "desc": (t.get("desc", "") or "")[:120]} for t in cands]
        sysp = ("You are the Planner's RELEVANCE FILTER on an AUTHORIZED, contained assessment. Given the "
                "TARGET ENVIRONMENT and CANDIDATE techniques (from the techniques DB + MITRE ATT&CK), select "
                "ONLY techniques that are APPLICABLE to THIS environment -- platform/stack/surface + task "
                "level must fit. DROP anything irrelevant (e.g. Windows/Active-Directory or mobile/cloud "
                "techniques against a Linux web app, or techniques whose platform doesn't match). Output "
                "ONLY a JSON array, best-first: [{\"id\":\"..\",\"reason\":\"<=12 words why it applies here\"}]. "
                "No prose, no fenced block.")
        raw = self._board(sysp, json.dumps({"environment": fp, "candidates": brief})[:8000])
        chosen = {}
        try:
            i, j = raw.find("["), raw.rfind("]")
            for it in (json.loads(raw[i:j + 1]) if i >= 0 and j > i else []):
                if isinstance(it, dict) and it.get("id"):
                    chosen[it["id"]] = it.get("reason", "")
        except Exception:
            chosen = {}
        if not chosen:                                 # board unavailable/unparseable -> platform set
            return cands[:keep]
        by_id = {t.get("id"): t for t in cands}
        out = []
        for tid, reason in chosen.items():             # board order = relevance order
            t = by_id.get(tid)
            if t:
                out.append({**t, "_relevance": reason})
        return out[:keep]

    def board_novel(self, fp: dict, known_ids: list, n: int = 4) -> list:
        """The DB never CAGES the board. Beyond the known/DB+ATT&CK techniques, the board devises NOVEL
        approaches for THIS environment -- a new technique, a creative MIX of existing ones, or a NEW
        TOOL / new code -- IN ADDITION to the accepted approach. These become anchor seed_moves too, and
        a novel approach that later verifies is written back to the learned DB (so it stops being novel)."""
        sysp = ("You are the Planner's CREATIVE strategist on an AUTHORIZED, contained assessment. The "
                "techniques DB + MITRE ATT&CK already proposed the KNOWN techniques listed. Propose up to "
                f"{n} NOVEL approaches to try IN ADDITION -- nothing in the DB constrains you: a novel "
                "technique, a creative MIX of existing approaches, or a NEW TOOL / NEW CODE you would "
                "write -- each tailored to THIS environment (stack/surfaces) and the task level. Output "
                "ONLY a JSON array: [{\"approach\":\"short name\",\"vuln_class\":\"..\",\"mechanism\":\"how "
                "it works\",\"surface\":\"/..\",\"tool_or_code\":\"an existing tool OR 'new-code: <what to "
                "build>'\",\"expected_oracle\":\"the observable that proves it\",\"why_novel\":\"why this "
                "is new/creative here\"}]. Concrete, no prose, no fenced block.")
        raw = self._board(sysp, json.dumps({"environment": fp, "known_techniques": known_ids})[:6000])
        moves = []
        try:
            i, j = raw.find("["), raw.rfind("]")
            arr = json.loads(raw[i:j + 1]) if i >= 0 and j > i else []
        except Exception:
            arr = []
        roles = fp.get("roles") or ["owner"]
        for k, m in enumerate(arr):
            if not isinstance(m, dict):
                continue
            cls = (m.get("vuln_class") or "novel").lower().strip()
            toc = str(m.get("tool_or_code") or "")
            is_code = toc.lower().startswith("new-code")
            surface = m.get("surface") or "/"
            moves.append({
                "action": _class_to_action(cls),
                "surface": surface, "path": surface if _class_to_action(cls) == "web" else None,
                "vuln_class": cls, "mechanism": m.get("mechanism", "")[:80],
                "technique": "novel:" + (m.get("approach") or f"n{k}").lower().replace(" ", "-")[:32],
                "tool": ("" if is_code else toc), "new_code": ([toc] if is_code else []),
                "role": roles[k % len(roles)], "trust": roles[k % len(roles)],
                "expected_oracle": m.get("expected_oracle", "confirm the observable"),
                "why_novel": "board-novel: " + (m.get("why_novel") or m.get("approach") or "new approach")[:100],
                "seed": "planner:novel",
            })
        return moves

    # ---- CVE x technique FUSION + agent EXTENSION (relevancy-filtered: appropriate tooling only) ----
    def _rag_cve(self, terms: str, limit: int = 8) -> list:
        """Best-effort offline CVE-RAG query (shelled into the RAG home). Returns [] if unavailable."""
        cmd = f"cd {self.rag_home} && python3 rag_query.py --json --k {int(limit)} {json.dumps(terms)}"
        try:
            p = subprocess.run(_shell_argv(self.distro, cmd), capture_output=True, text=True, timeout=60)
            out = (p.stdout or "").strip(); i = out.find("[")
            return json.loads(out[i:]) if i >= 0 else []
        except Exception:
            return []

    def cve_gaps(self, fp: dict, limit: int = 8) -> list:
        """The target's RELEVANT CVE gaps -- matched to the FINGERPRINTED stack ONLY (the survey IS the
        filter, so an unrelated CVE never appears). Sources: known_vulns already on the fingerprint, plus a
        best-effort offline CVE-RAG query keyed on the stack terms. Flags KEV / high-EPSS / exploit-available.
        Returns [] if the RAG is unavailable -- never fatal."""
        try:
            lim = int(os.environ.get("AEGIS_SYNTH_CVE_LIMIT", str(limit)))
        except Exception:
            lim = limit
        gaps, seen = [], set()
        def _add(cve, comp, kev, epss, exploit, note):
            cve = (cve or "").strip()
            if cve and cve not in seen:
                seen.add(cve)
                gaps.append({"cve": cve, "component": comp or "", "kev": bool(kev), "epss": epss,
                             "has_exploit": bool(exploit), "note": (note or "")[:120]})
        for kv in (fp.get("known_vulns") or []):
            if isinstance(kv, dict):
                _add(kv.get("cve") or kv.get("id"), kv.get("component"), kv.get("kev"), kv.get("epss"),
                     kv.get("exploit") or kv.get("edb") or kv.get("msf"), kv.get("note") or kv.get("desc"))
        if len(gaps) < lim:
            terms = fp.get("terms") or " ".join(fp.get("stack") or []) or " ".join((fp.get("surfaces") or [])[:3])
            for r in (self._rag_cve(terms, lim) if terms else []):
                if isinstance(r, dict):
                    _add(r.get("cve") or r.get("id"), r.get("component") or r.get("cpe"),
                         r.get("kev"), r.get("epss"), r.get("exploitdb") or r.get("msf") or r.get("nuclei"),
                         r.get("desc") or r.get("summary") or r.get("text"))
        return gaps[:lim]

    def board_synthesize(self, fp: dict, known_ids: list, cve_gaps: list, n: int = 4) -> list:
        """FUSION: COMBINE the target's RELEVANT CVE gaps with the known technique toolset into NOVEL
        COMPOSED approaches for THIS environment. The fingerprint is a HARD FILTER -- only approaches
        grounded in a fingerprinted surface/component with APPROPRIATE tooling (no random tools/CVEs/code).
        Returns anchor seed_moves (tag planner:synth). No-op without env-matched CVE gaps."""
        if not cve_gaps:
            return []
        sysp = ("You are the Planner's FUSION strategist on an AUTHORIZED, contained assessment. COMBINE the "
                "target's PRESENT CVE gaps with the known techniques into up to %d NOVEL COMPOSED approaches. "
                "HARD RULES: (1) RELEVANCE -- use ONLY CVEs/tools/techniques that APPLY to THIS environment "
                "(the fingerprint is the filter); never propose a tool/CVE/code for a component or platform "
                "NOT present. (2) Each approach must be a COMBINATION: a CVE chained with a technique, two "
                "CVEs bridged by a precondition, or a technique primitive reused on an uncovered surface. "
                "(3) Pick the APPROPRIATE tool for the stack, or 'new-code' only when no existing tool fits "
                "-- no random tool waste. Output ONLY a JSON array: [{\"approach\":\"short name\",\"combines\":"
                "[\"CVE-.. or technique-id\",\"..\"],\"vuln_class\":\"..\",\"surface\":\"/.. (a fingerprinted "
                "surface)\",\"mechanism\":\"how the combination works\",\"tool_or_code\":\"an applicable tool "
                "OR 'new-code: <what>'\",\"expected_oracle\":\"the observable that proves it\",\"why\":\"why "
                "this combination fits THIS target\"}]. No prose, no fenced block." % int(n))
        raw = self._board(sysp, json.dumps({"environment": fp, "known_techniques": known_ids,
                                            "cve_gaps": cve_gaps})[:7000])
        return self._fuse_moves(raw, fp, "planner:synth", "board-synth")

    def board_extend(self, fp: dict, proposals: list, n: int = 3) -> list:
        """AGENT EXTENSION: push each composed/novel proposal FURTHER -- add a chaining hop, a deeper oracle,
        or a scoped NON-DESTRUCTIVE variant a real attacker would try next -- STILL relevancy-filtered to THIS
        environment. Returns extra anchor seed_moves (tag planner:extend)."""
        if not proposals:
            return []
        brief = [{"approach": m.get("technique") or m.get("why_novel"), "surface": m.get("surface"),
                  "vuln_class": m.get("vuln_class"), "mechanism": m.get("mechanism")} for m in proposals[:6]]
        sysp = ("You are the Planner's EXTENSION strategist on an AUTHORIZED, contained assessment. Take each "
                "PROPOSAL and push it FURTHER into up to %d stronger follow-ons: a chaining hop, a deeper "
                "oracle, or a scoped NON-DESTRUCTIVE variant. HARD RULE: stay RELEVANT to THIS environment -- "
                "only surfaces/tools that apply here, no random additions. Output ONLY a JSON array with the "
                "same fields as a fusion approach (approach, combines, vuln_class, surface (fingerprinted), "
                "mechanism, tool_or_code, expected_oracle, why). No prose, no fenced block." % int(n))
        raw = self._board(sysp, json.dumps({"environment": fp, "proposals": brief})[:7000])
        return self._fuse_moves(raw, fp, "planner:extend", "board-extend")

    def _fuse_moves(self, raw: str, fp: dict, seed: str, why_prefix: str) -> list:
        """Parse a fusion/extension reply into anchor moves + apply the deterministic RELEVANCY FILTER: drop
        any proposal whose surface is not grounded in the fingerprint (so no random/off-target moves survive
        even if the model proposes one). If no surface map exists yet, the prompt-level filter still binds."""
        try:
            i, j = raw.find("["), raw.rfind("]")
            arr = json.loads(raw[i:j + 1]) if i >= 0 and j > i else []
        except Exception:
            arr = []
        fp_surfaces = {str(s).rstrip("/").lower() for s in
                       ((fp.get("surfaces") or []) + (fp.get("crawled_surfaces") or [])) if s}
        roles = fp.get("roles") or ["owner"]
        moves = []
        for k, m in enumerate(arr):
            if not isinstance(m, dict):
                continue
            surface = (m.get("surface") or "/").strip()
            s_norm = surface.rstrip("/").lower()
            if fp_surfaces and not (s_norm in fp_surfaces
                                    or any(s_norm.startswith(s) or s.startswith(s_norm) for s in fp_surfaces)):
                continue   # RELEVANCY FILTER: off-survey surface -> dropped (no random tool/target waste)
            cls = (m.get("vuln_class") or "novel").lower().strip()
            toc = str(m.get("tool_or_code") or "")
            is_code = toc.lower().startswith("new-code")
            moves.append({
                "action": _class_to_action(cls),
                "surface": surface, "path": surface if _class_to_action(cls) == "web" else None,
                "vuln_class": cls, "mechanism": (m.get("mechanism", "") or "")[:80],
                "technique": seed.split(":")[1] + ":" + (m.get("approach") or f"x{k}").lower().replace(" ", "-")[:32],
                "tool": ("" if is_code else toc), "new_code": ([toc] if is_code else []),
                "role": roles[k % len(roles)], "trust": roles[k % len(roles)],
                "combines": m.get("combines") or [],
                "expected_oracle": m.get("expected_oracle", "confirm the observable"),
                "why_novel": why_prefix + ": " + (m.get("why") or m.get("approach") or "composed approach")[:100],
                "seed": seed,
            })
        return moves

    def seed_moves(self, ranked: list, base: str, roles=None, mode: str = "operator") -> list:
        """Turn ranked techniques into MODE-1 anchor moves for iterative_hunt (one per technique)."""
        roles = roles or ["owner"]
        moves = []
        for i, t in enumerate(ranked):
            cls = t.get("class", "") or "web"
            action = _class_to_action(cls)
            tools = t.get("kali_tools") or []
            surface = (t.get("applies_to") or ["/"])[0] if action != "web" else "/"
            moves.append({
                "action": action,
                "surface": surface,
                "path": surface if action == "web" else None,
                "vuln_class": cls,
                "mechanism": (t.get("mitre_id") or t.get("id") or t.get("desc", "")[:40]),
                "technique": t.get("id", ""),
                "tool": (tools[0] if tools else ""),
                "role": roles[i % len(roles)],
                "trust": roles[i % len(roles)],
                "expected_oracle": t.get("oracle", "confirm the technique's observable"),
                "why_novel": f"planner anchor: {t.get('id','')} [{cls}]"
                             + (f" via {t['_via']}" if t.get("_via") else "")
                             + (f" -- {t['_relevance']}" if t.get("_relevance") else "")
                             + (f" (prior-success/EV)" if t.get("learned") else ""),
                "seed": "planner",
                "mitre_id": t.get("mitre_id", ""),
                "planner_rank": i,
            })
        return moves

    def plan(self, objective: str, target: str, surfaces=None, roles=None, stack=None,
             task_level: str = "fact-finding", base: str = None, limit: int = 12, board: bool = True,
             novel: int = 4) -> dict:
        fp = self.fingerprint(target, surfaces, roles, stack, task_level, objective=objective)
        ranked = self.rank(fp, limit=limit * 2)                     # over-fetch candidates
        relevant = self.select(ranked, fp, board=board, keep=limit)  # board keeps only what applies here
        seeds = self.seed_moves(relevant, base or target, roles=roles)   # DB/ATT&CK-known anchors
        novel_moves = self.board_novel(fp, [t.get("id") for t in relevant], n=novel) if (board and novel) else []
        return {"objective": objective, "fingerprint": fp, "candidates": len(ranked),
                "relevant": relevant, "novel_moves": novel_moves,
                "seed_moves": seeds + novel_moves}          # known + board-novel, both feed the loop

    # ---- multi-scenario candidate plans (stage 3): several genuinely different plans, re-open queue ---
    @staticmethod
    def _emphasis_sort(relevant: list, emphasis: list) -> list:
        """Stable-sort the relevant techniques so an emphasis scenario's classes float to the front
        (fast-track = injection/logic first; covert = recon/misconfig first). Empty emphasis = as-is."""
        if not emphasis:
            return list(relevant)
        def key(t):
            cls = (t.get("class", "") or "").lower()
            for i, e in enumerate(emphasis):
                if e in cls or cls in e:
                    return (0, i)
            return (1, 0)
        return sorted(relevant, key=key)

    def stateful_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """AUTO-SEED stateful probes (no hand-seeding): instantiate the stateful TEMPLATE library against
        the target. CODE templates (replay/idempotency/invariant on money paths) are high-value defaults;
        SCAFFOLD templates (resource persistence) seed when a keyword matches the objective/surfaces/stack.
        Budget-capped (AEGIS_STATEFUL_SEED_CAP, default 4). Gate: AEGIS_STATEFUL_SEED=0. Offline-safe."""
        if str(os.environ.get("AEGIS_STATEFUL_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        try:
            import copy as _copy, stateful_templates as _st
            tmpls = _st.templates(base, roles)
        except Exception:
            return []
        fp = fp or {}
        hay = " ".join([str(objective or ""), str(fp.get("terms", "")),
                        " ".join(fp.get("surfaces") or []), " ".join(fp.get("stack") or [])]).lower()
        picked = []
        for t in tmpls:
            applies = [a.lower() for a in (t.get("applies") or [])]
            matched = any(a in hay for a in applies)
            # CODE templates seed by default (high-value + self-validating); SCAFFOLD needs a keyword hit.
            if matched or t.get("layer") == "code":
                m = _copy.deepcopy({k: v for k, v in t.items() if k != "applies"})
                m.setdefault("seed", "planner")
                picked.append(m)
        cap = int(os.environ.get("AEGIS_STATEFUL_SEED_CAP", "4"))
        return picked[:cap]

    def idor_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """COMMERCIAL-PARITY: auto-seed IDOR/BOLA object-level authz sweeps for REST COLLECTION surfaces
        (a /api/<plural> that lists objects). For each, the idor leg enumerates ids as the owner role then
        cross-tests them as lower-privileged roles (reads-only -> non-destructive). Collections come from
        the fingerprint's surfaces (collection-shaped) + AEGIS_IDOR_COLLECTIONS; capped (AEGIS_IDOR_SEED_CAP,
        default 6). Gate: AEGIS_IDOR_SEED=0. Offline-safe."""
        if str(os.environ.get("AEGIS_IDOR_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        import re as _re
        fp = fp or {}
        surfaces = [str(s) for s in (fp.get("surfaces") or [])]
        # a REST collection = /api/<word(s)> with NO trailing {id}/param and not an obvious action verb
        colls = [s for s in surfaces if _re.match(r"^/api/[a-z0-9\-_/]+$", s or "", _re.I)
                 and not _re.search(r"\{|:|/(login|logout|refresh|search|export|report)$", s or "", _re.I)]
        env_colls = [c.strip() for c in (os.environ.get("AEGIS_IDOR_COLLECTIONS", "").split(",")) if c.strip()]
        colls = list(dict.fromkeys(env_colls + colls))                       # de-dup, env first
        if not colls:
            colls = ["/api/invoices", "/api/customers", "/api/jobs", "/api/payments", "/api/credit-notes"]
        owner = (roles or ["owner"])[0]
        attackers = [r for r in (roles or []) if r != owner][:2] or ["technician", "warehouse"]
        attackers = list(dict.fromkeys(attackers + ["anon"]))
        cap = int(os.environ.get("AEGIS_IDOR_SEED_CAP", "6"))
        out = []
        for c in colls[:cap]:
            out.append({"action": "idor", "collection": c, "surface": c, "owner_role": owner,
                        "attacker_roles": attackers, "sample": int(os.environ.get("AEGIS_IDOR_SAMPLE", "5")),
                        "vuln_class": "broken-object-level-authz", "technique": "idor.sweep", "layer": "code",
                        "severity": "high", "seed": "planner",
                        "why_novel": f"IDOR/BOLA: sweep {c} object ids across roles (object-level authz)."})
        return out

    def rate_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """COMMERCIAL-PARITY: seed a bounded, non-destructive RATE-LIMIT probe for auth-SENSITIVE
        surfaces (login/reset/OTP) discovered in the fingerprint (+ AEGIS_RATE_SURFACES). Gate:
        AEGIS_RATE_SEED=0. Uses a nonexistent identity so no real account locks."""
        if str(os.environ.get("AEGIS_RATE_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        import re as _re
        fp = fp or {}
        surfaces = [str(x) for x in (fp.get("surfaces") or [])]
        sens = [x for x in surfaces if _re.search(r"login|auth|reset|otp|verify|token|signin|sign-in", x or "", _re.I)]
        env = [c.strip() for c in os.environ.get("AEGIS_RATE_SURFACES", "").split(",") if c.strip()]
        sens = list(dict.fromkeys(env + sens)) or ["/api/auth/login"]
        cap = int(os.environ.get("AEGIS_RATE_SEED_CAP", "3"))
        return [{"action": "rate", "surface": x, "method": "POST", "n": int(os.environ.get("AEGIS_RATE_N", "15")),
                 "vuln_class": "improper-anti-automation", "technique": "rate.probe", "layer": "code",
                 "severity": "medium", "seed": "planner",
                 "why_novel": f"rate-limit/anti-automation probe on {x} (brute-force feasibility)."}
                for x in sens[:cap]]

    def surface_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """G52 COVERAGE-CLOSING: seed one AUTHZ reachability probe for EVERY crawler-discovered surface, so the
        hunt actually EXERCISES the whole attack surface (not just the class-keyword-matched subset) -- this is
        what turns the coverage_gate from INCOMPLETE toward COVERED. Each move records a candidate tagged
        `surface:<path>` and runs the SPA-200-guarded AuthzOracle as the neutral (non-privileged) role, so a
        real broken-access-control over-reach is caught and a legitimate access is a clean, recorded probe (not
        a finding). Templated /{id} paths seed their parent collection (can't GET a template). Gate:
        AEGIS_SURFACE_SEED=0; cap AEGIS_SURFACE_CAP (default 30)."""
        if str(os.environ.get("AEGIS_SURFACE_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        fp = fp or {}
        role = os.environ.get("AEGIS_NEUTRAL_ROLE", "technician")
        # prefer the CRAWLER-discovered surface (ground truth); fall back to the merged fingerprint surfaces
        raw = list(fp.get("crawled_surfaces") or fp.get("surfaces") or [])
        cols = []
        for s in raw:
            s = str(s).split("?")[0]
            if not s.startswith("/api"):
                continue
            if "{" in s:                      # /api/jobs/{id} -> probe the collection /api/jobs
                s = s.split("/{")[0]
            if s and s not in cols:
                cols.append(s)
        cap = int(os.environ.get("AEGIS_SURFACE_CAP", "30"))
        return [{"action": "authz", "surface": s, "path": s, "method": "GET", "role": role,
                 "vuln_class": "broken-access-control", "technique": "surface-coverage-authz", "layer": "code",
                 "severity": "medium", "seed": "planner", "coverage_seed": True,   # G52-fix: own per-surface angle
                 "why_novel": f"baseline authz/reachability probe on discovered surface {s} (coverage + BAC)"}
                for s in cols[:cap]]

    def breadth_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """G55 breadth-closing seeds: fire the 4 new oracles (field_leak/nested_write/filter_injection/sql_raw)
        as the NEUTRAL role against discovered SENSITIVE surfaces. Each carries breadth_seed=True so angle_of
        gives it a per-(class,surface) angle (else the angle cap collapses the sweep). Gate AEGIS_BREADTH_SEED=0."""
        if str(os.environ.get("AEGIS_BREADTH_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        fp = fp or {}
        role = os.environ.get("AEGIS_NEUTRAL_ROLE", "technician")
        _money = ("invoice", "credit-note", "creditnote", "payment", "estimate", "expense", "supplier-bill", "purchase-order")
        _owner = ("customer", "job", "part", "vehicle", "appliance", "technician", "user")
        surfaces = [str(s).split("?")[0] for s in (fp.get("crawled_surfaces") or fp.get("surfaces") or []) if str(s).startswith("/api")]
        sensitive = [s for s in dict.fromkeys(surfaces) if any(k in s.lower() for k in _money + _owner)]
        cap = int(os.environ.get("AEGIS_BREADTH_CAP", "8"))
        seeds = []
        for s in sensitive[:cap]:                       # field-leak + filter-injection on sensitive reads
            seeds.append({"action": "field_leak", "surface": s, "role": role, "layer": "code", "severity": "high",
                          "seed": "planner", "breadth_seed": True, "vuln_class": "sensitive-data-exposure",
                          "technique": "field-leak", "why_novel": f"field-level over-exposure on {s}"})
            seeds.append({"action": "filter_injection", "surface": s, "role": role, "layer": "code", "severity": "high",
                          "seed": "planner", "breadth_seed": True, "vuln_class": "filter-injection",
                          "technique": "filter-injection", "inject_query": "?take=1000&skip=0",
                          "why_novel": f"where/orderBy scope-widening on {s}"})
        # nested-write over-post on the known money create routes (foreign relation FK)
        for path, lst, fk in (("/api/invoices", "/api/jobs", "jobId"),
                              ("/api/credit-notes", "/api/invoices", "invoiceId"),
                              ("/api/payments/deposit", "/api/customers", "customerId")):
            seeds.append({"action": "nested_write", "surface": path, "role": role, "layer": "code",
                          "severity": "high", "seed": "planner", "breadth_seed": True,
                          "vuln_class": "nested-write-over-post", "technique": "nested-write",
                          "create": {"method": "POST", "path": path, "body": {}},
                          "ref": {"list": lst, "id_field": "id", "as": fk}, "inject_field": fk,
                          "why_novel": f"nested relation over-post ({fk}) on {path}"})
        # sql_raw only where the app is known to use $queryRaw (rare on Prisma) -- opt-in via env
        for s in [c.strip() for c in os.environ.get("AEGIS_SQLRAW_SURFACES", "").split(",") if c.strip()]:
            seeds.append({"action": "sql_raw", "surface": s, "role": role, "layer": "code", "severity": "high",
                          "seed": "planner", "breadth_seed": True, "vuln_class": "sql-injection",
                          "technique": "sql-raw", "param": os.environ.get("AEGIS_SQLRAW_PARAM", "q"),
                          "why_novel": f"$queryRaw boolean-differential on {s}"})
        return seeds

    def breadth_grid_seeds(self, base, roles=None, campaign=None, fp=None, objective="") -> list:
        """C7: seed the hunt from the BREADTH DEMAND GRID (breadth_audit), not just crawled surfaces. Every
        (route x required-class) cell that is SEEDED_NOT_EXERCISED / HAVE_ORACLE_NO_SEED becomes a targeted
        seed so the loop's budget lands on the REAL demand (the 474-route grid) instead of the handful of
        crawled/hardcoded surfaces -- the fix for the '0% exercised, 1 crawled surface' run. Money surfaces
        first. Offline / mirror-down -> [] (graceful, never raises). Gate AEGIS_BREADTH_GRID_SEED=0;
        cap AEGIS_BREADTH_GRID_CAP (default 40)."""
        if str(os.environ.get("AEGIS_BREADTH_GRID_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        try:
            import breadth_audit
            a = breadth_audit.audit(campaign or os.environ.get("AEGIS_CAMPAIGN"), base)
            cells = [c for c in (a.get("cells") or [])
                     if c.get("state") in ("SEEDED_NOT_EXERCISED", "HAVE_ORACLE_NO_SEED")]
        except Exception:
            return []
        if not cells:
            return []
        role = os.environ.get("AEGIS_NEUTRAL_ROLE", "technician")
        _money = ("invoice", "credit-note", "creditnote", "payment", "estimate", "expense",
                  "supplier-bill", "purchase-order")
        cells.sort(key=lambda c: 0 if any(k in str(c.get("surface", "")).lower() for k in _money) else 1)
        # breadth class -> the loop vector that exercises it (verified_findings/vectors action names)
        C2A = {"authz": "idor", "idor": "idor", "field_leak": "field_leak", "filter_injection": "filter_injection",
               "sql_raw": "sql_raw", "nested_write": "nested_write", "mass_assign": "mass_assign",
               "invariant": "stateful", "idempotency": "stateful", "session_fixation": "session_fixation",
               "rate_limit": "rate", "csrf": "csrf", "security_headers": "security_headers",
               "open_redirect": "open_redirect", "ssrf": "ssrf", "xss": "xss", "file_upload": "file_upload"}
        cap = int(os.environ.get("AEGIS_BREADTH_GRID_CAP", "40"))
        seeds = []
        for c in cells[:cap]:
            cls = c.get("class"); surf = c.get("surface"); act = C2A.get(cls)
            if not act or not surf:
                continue
            seeds.append({"action": act, "surface": surf, "role": role, "layer": "code", "severity": "medium",
                          "seed": "planner-grid", "breadth_seed": True, "vuln_class": cls,
                          "technique": str(cls).replace("_", "-"),
                          "why_novel": f"breadth-grid cell {cls} on {surf} (was SEEDED_NOT_EXERCISED)"})
        return seeds

    def inject_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """#5: seed the injection battery (SSTI / cmdi-OOB / time-blind) on surfaces that take free-text /
        template-ish / command-ish input. Gate AEGIS_INJECT_SEED=0."""
        if str(os.environ.get("AEGIS_INJECT_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        fp = fp or {}
        cand = [x for x in (fp.get("surfaces") or fp.get("crawled_surfaces") or [])
                if any(k in str(x).lower() for k in ("search", "template", "message", "note", "render",
                                                     "preview", "export", "report", "name", "filename", "import"))]
        surfaces = list(dict.fromkeys(cand))[:int(os.environ.get("AEGIS_INJECT_CAP", "6"))] or ["/"]
        return [{"action": "inject", "surface": s, "layer": "code", "severity": "high", "seed": "planner",
                 "vuln_class": "injection", "technique": "ssti-cmdi-timeblind",
                 "why_novel": f"SSTI/cmdi/time-blind injection battery on {s}"} for s in surfaces]

    def frontdoor_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """D8: seed the FRONT-DOOR battery (BruteForceFeasibility / UserEnumeration / PinPolicy) against the
        login/auth surface, so attack-feasibility is part of the hunt (not just standalone oracles). Passive
        by default (PinPolicy + status/body enum); the active rate/timing arms are gated IN the vector by
        AEGIS_ACTIVE_AUTH. Gate AEGIS_FRONTDOOR_SEED=0."""
        if str(os.environ.get("AEGIS_FRONTDOOR_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        fp = fp or {}
        cand = [x for x in (fp.get("surfaces") or fp.get("crawled_surfaces") or [])
                if any(k in str(x).lower() for k in ("login", "signin", "auth"))]
        surface = cand[0] if cand else "/api/auth/login"
        return [{"action": "front_door", "surface": surface, "layer": "code", "severity": "high",
                 "seed": "planner", "vuln_class": "broken-authentication", "technique": "front-door",
                 "valid_name": os.environ.get("AEGIS_VALID_NAME"),
                 "pin_length": int(os.environ.get("AEGIS_PIN_LENGTH", "6")),
                 "why_novel": "front-door: brute-force feasibility + user-enumeration + PIN policy"}]

    def synth_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """MECH 3: AUTO-SEED a few DETERMINISTIC synthetic techniques (cross-products of known classes:
        replay-as-another-identity, TOCTOU-on-invariant, double-effect race, privilege-field-back-door).
        No LLM in the path. Anchored on the stateful-template surfaces at plan time (no confirmed foothold
        yet); the loop re-composes on confirmed footholds later. Capped (AEGIS_SYNTH_SEED_CAP, default 3)
        so it never crowds out breadth. Gate: AEGIS_SYNTH_SEED=0. Offline-safe."""
        if str(os.environ.get("AEGIS_SYNTH_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        try:
            import technique_synth as _ts, stateful_templates as _st
            tmpls = _st.templates(base, roles)
            cap = int(os.environ.get("AEGIS_SYNTH_SEED_CAP", "3"))
            return _ts.synthesize(templates=tmpls, fp=fp, limit=cap)
        except Exception:
            return []

    def candidate_plans(self, objective: str, target: str, surfaces=None, roles=None, stack=None,
                        task_level: str = "fact-finding", base: str = None, n_scenarios: int = 3,
                        limit: int = 12, board: bool = True, novel: int = 4) -> list:
        """Generate N CANDIDATE PLANS (scenarios) that vary technique ORDER, novel-probe budget and
        surface priority -- e.g. fast-track / thorough / covert (PLANNER.md component 4). The DB rank +
        board relevance filter run ONCE (shared); each scenario then re-orders that relevant set by its
        emphasis and draws its OWN fresh batch of board-novel approaches, so the plans are genuinely
        different, not re-labels. Scored `scenario_fit(task_level) + emphasis_coverage + novelty + breadth`
        and returned best-first: plans[0] seeds the run, the rest are the mid-run RE-OPEN queue.
        Offline-safe: board off/unreachable -> scenarios still differ by emphasis ordering."""
        fp = self.fingerprint(target, surfaces, roles, stack, task_level, objective=objective)
        # ACTIVE CRAWL (commercial-parity): discover the REAL surface (the SPA's live XHR/API endpoints) as
        # each role and MERGE it into the fingerprint, so every oracle (idor/xss/rate/mass-assign/secrets)
        # seeds against discovered endpoints -- not just guessed paths (the false-parity trap). One crawl
        # per plan; gate AEGIS_CRAWL=0; offline-safe (no browser -> unchanged).
        try:
            import crawler, session_factory
            _neutral = [r for r in (roles or []) if str(r).lower() not in ('owner','admin')] or None
            _cr = crawler.crawl(base or target, session_for_role=session_factory.from_env(base or target),
                                roles=_neutral)   # NEUTRALITY: crawl as non-privileged roles only
            _disc = _cr.get("surfaces") or []
            if _disc:
                merged = list(dict.fromkeys((fp.get("surfaces") or []) + _disc))
                fp["surfaces"] = merged
                fp["crawled_surfaces"] = _disc
                fp["crawled_by_role"] = _cr.get("by_role")   # per-trust-level surface delta (anon vs authed)
        except Exception:
            pass
        ranked = self.rank(fp, limit=limit * 2)
        relevant = self.select(ranked, fp, board=board, keep=limit)
        known_ids = [t.get("id") for t in relevant]
        # DYNAMIC discovery survey: SEE the env -> SURVEY techniques+tools live (MITRE/RAG) -> CHECK/ACQUIRE
        # (install-on-demand) or WRITE a probe (code-on-demand) -> phase-1 discovery seed moves. The board
        # then decides/mixes/escalates downstream. Not statically bound. AEGIS_DISCOVERY_SURVEY=0 to skip.
        disco_seeds = []
        if str(os.environ.get("AEGIS_DISCOVERY_SURVEY", "1")).lower() not in ("0", "false", "no", "off"):
            try:
                import discovery as _disco
                disco_seeds = _disco.survey(base or target, roles=roles, fp=fp).get("seed_moves", [])
            except Exception:
                disco_seeds = []
        sc_seeds = self.surface_seeds(base or target, roles=roles, fp=fp, objective=objective)  # G52 coverage-closing
        bo_seeds = self.breadth_seeds(base or target, roles=roles, fp=fp, objective=objective)  # G55 breadth-closing
        bg_seeds = self.breadth_grid_seeds(base or target, roles=roles, fp=fp, objective=objective)  # C7 demand-grid
        fd_seeds = self.frontdoor_seeds(base or target, roles=roles, fp=fp, objective=objective)     # D8 front-door
        in_seeds = self.inject_seeds(base or target, roles=roles, fp=fp, objective=objective)         # #5 injection
        st_seeds = self.stateful_seeds(base or target, roles=roles, fp=fp, objective=objective)
        sy_seeds = self.synth_seeds(base or target, roles=roles, fp=fp, objective=objective)
        id_seeds = self.idor_seeds(base or target, roles=roles, fp=fp, objective=objective)
        rt_seeds = self.rate_seeds(base or target, roles=roles, fp=fp, objective=objective)
        # one passive cookie/security-header probe per run (commercial-parity); gate AEGIS_SECHEADERS_SEED=0
        sh_seeds = ([] if str(os.environ.get('AEGIS_SECHEADERS_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'security_headers','surface':'/','vuln_class':'security-misconfiguration',
                           'technique':'security-headers','layer':'scaffold','severity':'low','seed':'planner',
                           'why_novel':'cookie flags + security response headers (passive)'}])
        # G56: one OWASP ZAP mature-DAST sweep per run (oracle-gated lead source). Off by default on the
        # target mirror to save 8GB RAM; enable with AEGIS_ZAP_SEED=1 (juice-shop / generality runs).
        zap_seed = ([{'action':'zap','surface':'/','vuln_class':'dast','technique':'zap-baseline','layer':'scaffold',
                      'severity':'medium','seed':'planner','why_novel':'OWASP ZAP spider+scan -> oracle-gated leads'}]
                    if str(os.environ.get('AEGIS_ZAP_SEED','0')).lower() in ('1','true','yes','on') else [])
        sfx_seeds = ([] if str(os.environ.get('AEGIS_SESSFIX_SEED','1')).lower() in ('0','false','no','off')
                     else [{'action':'session_fixation','surface':'/api/auth/login','vuln_class':'broken-authentication',
                            'technique':'session-fixation','layer':'code','severity':'high','seed':'planner',
                            'why_novel':'session id rotation on login (fixation)'}])
        or_surfaces = ['/','/login','/api/auth/login'] + [x for x in (fp.get('surfaces') or [])
                       if any(k in str(x).lower() for k in ('login','redirect','oauth','sso','callback','logout','return'))]
        up_surfaces = [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in
                       ('upload','photo','file','document','attachment','image','signature','avatar','media'))]
        up_seeds = ([] if (str(os.environ.get('AEGIS_UPLOAD_SEED','1')).lower() in ('0','false','no','off') or not up_surfaces)
                    else [{'action':'file_upload','surface':u,'vuln_class':'unrestricted-file-upload',
                           'technique':'file-upload','layer':'code','severity':'high','seed':'planner',
                           'why_novel':f'active-content upload probe on {u}'} for u in list(dict.fromkeys(up_surfaces))[:int(os.environ.get('AEGIS_UPLOAD_CAP','3'))]])
        xss_surfaces = ['/'] + [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in
                        ('search','q','list','view','detail','profile','comment','message','note','report'))]
        xss_seeds = ([] if str(os.environ.get('AEGIS_XSS_SEED','1')).lower() in ('0','false','no','off')
                     else [{'action':'xss','surface':u,'vuln_class':'cross-site-scripting',
                            'technique':'xss-headless','layer':'code','severity':'high','seed':'planner','headless':True,
                            'why_novel':f'DOM/reflected XSS (headless) on {u}'} for u in list(dict.fromkeys(xss_surfaces))[:int(os.environ.get('AEGIS_XSS_CAP','3'))]])
        ss_surfaces = ['/'] + [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in
                       ('fetch','url','image','webhook','proxy','import','preview','avatar','route','geometry','callback'))]
        ss_seeds = ([] if str(os.environ.get('AEGIS_SSRF_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'ssrf','surface':u,'vuln_class':'server-side-request-forgery',
                           'technique':'ssrf-canary','layer':'code','severity':'high','seed':'planner',
                           'why_novel':f'SSRF OOB canary probe on {u}'} for u in list(dict.fromkeys(ss_surfaces))[:int(os.environ.get('AEGIS_SSRF_CAP','3'))]])
        cs_seeds = ([] if str(os.environ.get('AEGIS_CSRF_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'csrf','surface':'/','vuln_class':'cross-site-request-forgery',
                           'technique':'csrf-posture','layer':'code','severity':'medium','seed':'planner',
                           'why_novel':'CSRF posture (SameSite + anti-CSRF token)'}])
        or_seeds = ([] if str(os.environ.get('AEGIS_OPENREDIR_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'open_redirect','surface':u,'vuln_class':'unvalidated-redirect',
                           'technique':'open-redirect','layer':'code','severity':'medium','seed':'planner',
                           'why_novel':f'open-redirect probe on {u}'} for u in list(dict.fromkeys(or_surfaces))[:int(os.environ.get('AEGIS_OPENREDIR_CAP','3'))]])
        ma_seeds = ([] if str(os.environ.get('AEGIS_MASSASSIGN_SEED','1')).lower() in ('0','false','no','off') else [
            {'action':'mass_assign','role':os.environ.get('AEGIS_NEUTRAL_ROLE','technician'),'surface':'/api/payments/deposit','layer':'code',
             'create':{'method':'POST','path':'/api/payments/deposit','body':{'amount':50,'method':'CARD'}},
             'ref':{'list':'/api/customers','id_field':'id','as':'customerId'},
             'inject':{'status':'CLEARED','approved':True,'balance':999999,'id':'aegis-forced'},
             'vuln_class':'mass-assignment','technique':'mass-assign','severity':'high','seed':'planner',
             'why_novel':'inject privileged fields into a deposit create (mass assignment)'},
            {'action':'mass_assign','role':os.environ.get('AEGIS_NEUTRAL_ROLE','technician'),'surface':'/api/invoices','layer':'code',
             'create':{'method':'POST','path':'/api/invoices','body':{}},
             'ref':{'list':'/api/jobs','id_field':'id','as':'jobId'},
             'inject':{'status':'PAID','total':0.01,'approved':True,'id':'aegis-forced'},
             'vuln_class':'mass-assignment','technique':'mass-assign','severity':'high','seed':'planner',
             'why_novel':'inject privileged fields into an invoice create (mass assignment)'}])
        # SQLi battery (GAP-2 FIX): login auth-bypass (' OR 1=1--) via the purpose-built sql_raw leg
        # (SqlAuthBypassOracle) + boolean-diff on search-ish read handlers. There was NO sql_raw seed before,
        # so the leg was never scheduled; the dispatch normalizer resolves the REAL login endpoint. Gate AEGIS_SQLI_SEED=0.
        _sqli_login = [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in ('login','signin','auth'))]
        # prefer an API-ish login endpoint (contains rest/api/auth) over a bare SPA route like /login, so the
        # auth-bypass anchor hits the real handler even without the dispatch normalizer's behaviour-probe.
        _sqli_login.sort(key=lambda c: (0 if any(k in c.lower() for k in ('rest','api','/auth')) else 1, len(c)))
        _sqli_read = [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in ('search','q=','list','product','find','query'))]
        sqli_seeds = ([] if str(os.environ.get('AEGIS_SQLI_SEED','1')).lower() in ('0','false','no','off') else (
            [{'action':'sql_raw','auth_bypass':True,'surface':(_sqli_login[0] if _sqli_login else '/login'),
              'vuln_class':'sql-injection','technique':'sqlraw.authbypass','layer':'code','severity':'high','seed':'planner',
              'why_novel':"SQLi auth-bypass on the login endpoint (' OR 1=1--)"}]
            + [{'action':'sql_raw','surface':u,'param':'q','value':'1','vuln_class':'sql-injection',
                'technique':'sqlraw.boolean','layer':'code','severity':'high','seed':'planner',
                'why_novel':f'boolean-diff SQLi on {u}'} for u in list(dict.fromkeys(_sqli_read))[:int(os.environ.get('AEGIS_SQLI_CAP','2'))]]))
        # nuclei enrichment (the leg exists but no action:nuclei move was ever emitted). One info-move ->
        # matches are leads the oracle chases. Gate AEGIS_NUCLEI_SEED=0 (AEGIS_NUCLEI=0 kills the leg itself).
        nuclei_seed = ([] if str(os.environ.get('AEGIS_NUCLEI_SEED','1')).lower() in ('0','false','no','off') else
                       [{'action':'nuclei','surface':'/','vuln_class':'known-vuln','technique':'nuclei-enrich',
                         'layer':'scaffold','severity':'medium','seed':'planner',
                         'why_novel':'nuclei template sweep (severity>=medium, on-stack) -> oracle-gated leads'}])
        import copy as _copy
        plans = []
        # CVE x technique FUSION + agent extension, computed ONCE (relevancy-filtered; appropriate tooling
        # only; bounded to one synth + one extend board call). Env-gated AEGIS_SYNTH; no-op without env CVEs.
        _synth = []
        if board and os.environ.get("AEGIS_SYNTH", "1") != "0":
            _gaps = self.cve_gaps(fp)
            if _gaps:
                _sm = self.board_synthesize(fp, known_ids, _gaps, n=4)
                _synth = _sm + self.board_extend(fp, _sm, n=2)
        for prof in _SCENARIOS[:max(1, n_scenarios)]:
            ordered = self._emphasis_sort(relevant, prof["emphasis"])
            # EVALUATE-THEN-ATTACK: recon anchors (disco) first to establish the target, then the attack
            # seeds ORDERED BY OBJECTIVE-VALUE (auth-bypass/SQLi/IDOR/XSS lead) so a small budget starts with
            # the moves most likely to achieve the goal instead of sweeping low-value classes. Gate AEGIS_RANK_SEEDS=0.
            _attack = (_copy.deepcopy(zap_seed) + _copy.deepcopy(sc_seeds) + _copy.deepcopy(bo_seeds) + _copy.deepcopy(bg_seeds) + _copy.deepcopy(fd_seeds) + _copy.deepcopy(in_seeds) + _copy.deepcopy(st_seeds) + _copy.deepcopy(sy_seeds)
                       + _copy.deepcopy(id_seeds) + _copy.deepcopy(rt_seeds) + _copy.deepcopy(sh_seeds)
                       + _copy.deepcopy(sfx_seeds) + _copy.deepcopy(or_seeds) + _copy.deepcopy(ma_seeds)
                       + _copy.deepcopy(cs_seeds) + _copy.deepcopy(ss_seeds) + _copy.deepcopy(xss_seeds)
                       + _copy.deepcopy(up_seeds) + _copy.deepcopy(sqli_seeds) + _copy.deepcopy(nuclei_seed))
            if str(os.environ.get("AEGIS_RANK_SEEDS", "1")).lower() not in ("0", "false", "no", "off"):
                _attack = sorted(_attack, key=lambda m: -_seed_priority(m, objective))
            seeds = (disco_seeds + _attack + self.seed_moves(ordered, base or target, roles=roles))
            nmoves = (self.board_novel(fp, known_ids, n=prof["novel"]) if (board and prof["novel"]) else []) + _copy.deepcopy(_synth)
            for m in seeds + nmoves:                      # tag scenario for the audit/report
                m["scenario"] = prof["name"]
            emphasis_hit = sum(1 for t in ordered
                               if any(e in (t.get("class", "") or "").lower() for e in prof["emphasis"]))
            score = (prof["fit"].get(task_level, 1) * 3.0 + emphasis_hit
                     + len(nmoves) * 1.0 + len(ordered) * 0.25)
            plans.append({"name": prof["name"], "desc": prof["desc"], "score": round(score, 2),
                          "seed_moves": seeds + nmoves, "relevant": ordered, "novel_moves": nmoves,
                          "fingerprint": fp})           # carry the stack/surface fp so the board keeps novelty ON-STACK
        plans.sort(key=lambda pl: -pl["score"])
        return plans

    # ---- closed-loop learning: write a verified win back to the learned DB ----
    def record_success(self, technique_id: str, tool: str, scenario: str, target_fp: str,
                       cls: str = "", desc: str = "") -> dict:
        """Append a learned technique entry (technique + tool + scenario + target fingerprint) to
        learned_techniques.json on the box, so the ranker boosts this combo next run. Idempotent-ish:
        merges a new _wins record onto an existing id."""
        entry = {"id": technique_id, "class": cls, "desc": desc or technique_id, "learned": True,
                 "kali_tools": ([tool] if tool else []),
                 "real_world_basis": f"verified on this stack ({scenario})",
                 "_win": {"scenario": scenario, "target": target_fp, "tool": tool,
                          "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
        payload = json.dumps(entry)
        # merge into learned_techniques.json inside Kali (where the DB lives), atomically
        py = (
            "import json,os,sys;"
            "p=os.path.join('" + self.rag_home + "','learned_techniques.json');"
            "d=json.load(open(p,encoding='utf-8')) if os.path.exists(p) else {'techniques':[]};"
            "d.setdefault('techniques',[]);"
            "e=json.loads(sys.argv[1]);"
            "cur=next((x for x in d['techniques'] if x.get('id')==e['id']),None);"
            "(cur.setdefault('_wins',[]).append(e['_win']) or cur.__setitem__('kali_tools',sorted(set((cur.get('kali_tools') or [])+e['kali_tools']))))"
            " if cur else d['techniques'].append(dict(e,_wins=[e.pop('_win')]));"
            "json.dump(d,open(p+'.tmp','w',encoding='utf-8'));os.replace(p+'.tmp',p);"
            "print('learned',e['id'])"
        )
        try:
            p = subprocess.run(_shell_argv(self.distro,
                                f"cd {self.rag_home} && python3 -c {json.dumps(py)} {json.dumps(payload)}"),
                               capture_output=True, text=True, timeout=60)
            return {"ok": p.returncode == 0, "out": (p.stdout or p.stderr).strip()[:200]}
        except Exception as e:
            return {"ok": False, "error": str(e)[:160]}


def ensure_kali(distro=None, timeout=60):
    """DRIVE KALI: ensure the distro is RUNNING before the Planner queries the RAG or checks the toolset
    -- the techniques/ATT&CK DB (/opt/aegis-rag) AND the offensive toolset both live inside Kali, and the
    resolver for anything missing is there too. A `wsl` command auto-starts a stopped distro; we issue a
    bounded readiness probe so a cold boot completes before the first RAG call (rather than that call
    timing out). Idempotent + fail-safe: any error -> False and callers degrade to offline planning.
    Disable with AEGIS_KALI_AUTOSTART=0."""
    if os.environ.get("AEGIS_KALI_AUTOSTART", "1") == "0":
        return False
    try:
        p = subprocess.run(_shell_argv(distro, "echo aegis-kali-ready"),
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return "aegis-kali-ready" in (p.stdout or "")
    except Exception:
        return False


def _kali_present(tools, distro=None, timeout=15):
    """OBSERVATORY: which of `tools` (DB `kali_tools` entries) are actually INSTALLED in Kali -- so the
    board composes novel approaches from tools that EXIST here (else it writes a custom probe). One
    bounded `command -v` sweep; fail-safe: Kali unreachable / disabled -> [] (unknown; the board still
    has the tool NAMES from the ATT&CK toolset). Disable with AEGIS_KALI_TOOLCHECK=0."""
    import re as _re
    bins = sorted({(t or "").strip().split()[0] for t in (tools or []) if (t or "").strip()})
    bins = [b for b in bins if _re.fullmatch(r"[A-Za-z0-9._-]{1,40}", b)]      # trusted-ish, but sanitize
    if not bins or os.environ.get("AEGIS_KALI_TOOLCHECK", "1") == "0":
        return []
    inner = "; ".join(f"command -v {b} >/dev/null 2>&1 && echo {b}" for b in bins)
    try:
        p = subprocess.run(_shell_argv(distro, inner),
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
    except Exception:
        return []


class PlannerSession:
    """Holds the ranked candidate plans (scenarios) for ONE run. plans[0] seeds the 40-attempt loop;
    on a mid-run stall the loop's `reopen` callback pops the NEXT scenario's moves (the Planner
    loop-back, PLANNER.md component 6). The loop itself filters those to whatever is still novel and
    bounds how many re-opens can happen (max_reopens), so re-planning can never thrash the budget."""
    def __init__(self, plans):
        self.plans = plans or []
        self.i = 0                      # index of the scenario currently in play (0 = initial)
        self.log = []                   # [{scenario, why, score}] per re-open (audit/report)
        self._kali_present_cache = None # cached "which ranked tools are installed in Kali" (observatory)

    # OBSERVATORY ROLE AT THE DISCOVERY STAGE: the Planner EXECUTES only its DETERMINISTIC anchors
    # (prior-successful / ATT&CK-ranked replays, tag "planner"). Its board_novel speculation
    # (tag "planner:novel") was frozen at plan time against ONLY the fingerprint -- executing it blind
    # mid-run is what produced unmoored moves; instead it becomes ADVISORY `intel()` the LIVE board
    # reads each round (the board, seeing deltas + footholds, chooses the actual moves).
    @staticmethod
    def _anchors(plan):
        return [m for m in (plan.get("seed_moves") or []) if m.get("seed") != "planner:novel"]

    def initial_seeds(self):
        return self._anchors(self.plans[0]) if self.plans else []

    def initial_name(self):
        return self.plans[0]["name"] if self.plans else ""

    def scenario_names(self):
        return [p["name"] for p in self.plans]

    def intel(self, context=None):
        """OBSERVATORY-ONLY context for the live board: the current scenario's FACTUAL ranked
        technique classes (from the curated + learned + ATT&CK DB) -- knowledge, not moves. NOVELTY
        at the discovery stage is the LIVE BOARD's job (it sees the deltas + footholds); the Planner
        deliberately supplies NO novel approaches here -- its `board_novel` (frozen at plan time
        against only the fingerprint) is intentionally omitted. Injected as `planner_intel` in the
        loop's board context. Empty when no plan (offline-safe)."""
        if not self.plans:
            return {}
        p = self.plans[self.i]
        # Hand the board the RICH, COMBINABLE ATT&CK / technique-DB material the Planner already
        # retrieved + ranked for this fingerprint (RAG: curated + learned + MITRE ATT&CK): each entry's
        # tools, how-to-test, tactics and platforms -- so the board can COMBINE / CHAIN / adapt them into
        # novel approaches (not just see a label). This is the raw material for the board's novelty;
        # the Planner supplies it (observe/retrieve), the board composes it (create).
        toolset = [{"id": t.get("id"), "class": t.get("class") or t.get("cls"),
                    "desc": (t.get("desc") or "")[:120],
                    "tools": (t.get("kali_tools") or [])[:6],
                    "how_to_test": (t.get("how_to_test") or "")[:140],
                    "mitre_tactics": t.get("mitre_tactics") or t.get("tactics") or [],
                    "mitre_id": t.get("mitre_id") or "",
                    "applies_to": (t.get("applies_to") or [])[:4],
                    "learned": bool(t.get("learned"))}
                   for t in (p.get("relevant") or [])[:10]]
        # OBSERVATORY: check ONCE which of the ranked tools are installed in Kali (cached; fail-safe).
        if self._kali_present_cache is None:
            self._kali_present_cache = _kali_present(
                [tt for t in (p.get("relevant") or [])[:10] for tt in (t.get("kali_tools") or [])])
        fp = p.get("fingerprint") or {}
        stack = {"stack": fp.get("stack") or [], "surfaces": fp.get("surfaces") or [],
                 "roles": fp.get("roles") or []}
        return {"planner_scenario": p.get("name"),
                "target_stack": stack,                 # the ACTUAL code/stack -> keep novelty RELEVANT
                "attack_toolset": toolset,
                "kali_tools_present": self._kali_present_cache,
                "note": ("MITRE ATT&CK / technique-DB material (from the RAG), already relevance-filtered "
                         "and ranked for THIS target's stack (`target_stack`), plus which of their tools are "
                         "INSTALLED here (`kali_tools_present`). Propose ONLY approaches RELEVANT to this "
                         "actual code/stack -- no off-stack techniques. COMBINE and CHAIN the toolset (mix "
                         "techniques, chain tactics, compose/adapt their tools) into NOVEL approaches; when "
                         "no installed tool fits, write a custom probe (`new_code`) that targets a gap in "
                         "THIS code's behaviour (a zero-day-style hypothesis). Go beyond the DB with new "
                         "ideas too. Ground everything in the live oracle deltas + confirmed footholds; "
                         "raw material, NOT moves to run verbatim.")}

    def reopen(self, context=None, why=""):
        """Return the NEXT candidate scenario's DETERMINISTIC anchors (novel speculation stays in
        intel(), not executed). [] when the queue is exhausted."""
        self.i += 1
        if self.i < len(self.plans):
            p = self.plans[self.i]
            self.log.append({"scenario": p["name"], "why": why, "score": p["score"]})
            return self._anchors(p)
        return []


def plan_session(objective, target, *, roles=None, surfaces=None, stack=None,
                 task_level="fact-finding", mode="operator", base=None, limit=12,
                 board=True, novel=4, n_scenarios=3):
    """OFFLINE-SAFE factory: build the multi-scenario PlannerSession for a run, or None. None => the
    runner falls back to plan_seed_moves (single plan) or the board brainstorm alone. Every failure
    (planner error, Kali/DB unreachable, board offline) yields None -- it can never block a run.
    Opt-out with AEGIS_PLANNER=0."""
    if os.environ.get("AEGIS_PLANNER", "1") == "0":
        return None
    try:
        plans = Planner().candidate_plans(objective, target, surfaces=surfaces, roles=roles,
                                          stack=stack, task_level=task_level, base=base, limit=limit,
                                          board=board, novel=novel, n_scenarios=n_scenarios)
        for pl in plans:
            for m in pl["seed_moves"]:
                m.setdefault("_planner_mode", mode)
        # PRE-FLIGHT tool provisioning (board-converged): tools the plan needs that are MISSING in Kali are
        # provisioned in the BLACKARCH container up front (prebuilt via pacman -- not ported into Kali), so a
        # probe never stalls mid-run to fetch a tool. Offline-safe + opt-out (AEGIS_TOOL_PREFLIGHT=0); a
        # no-op when every needed tool is already in Kali; NEVER blocks a run.
        if plans and os.environ.get("AEGIS_TOOL_PREFLIGHT", "1") != "0":
            try:
                tools = set()
                for pl in plans:
                    for m in pl.get("seed_moves", []):
                        t = str(m.get("tool") or "").strip()
                        if t and not t.lower().startswith("new-code") and not m.get("new_code"):
                            tools.add(t)
                if tools:
                    import distro_backend
                    distro_backend.preflight(sorted(tools))
            except Exception:
                pass
        return PlannerSession(plans) if plans else None
    except Exception:
        return None


def plan_seed_moves(objective, target, *, roles=None, surfaces=None, stack=None,
                    task_level="fact-finding", mode="operator", base=None, limit=12,
                    board=True, novel=4):
    """OFFLINE-SAFE bridge from the Planner into the 40-attempt iterative-hunt loop: returns the
    merged MODE-1 anchor `seed_moves` -- DB/ATT&CK prior-successful anchors PLUS the board-devised
    NOVEL approaches (novel technique / mix / new-code) -- to hand IterativeHunt(seed_moves=...).
    So the "retry / try-again / what-else-can-be-done" loop STARTS already carrying the novel board
    ideas, then diversifies per its own rules. NEVER raises and never blocks a run: on any failure
    (planner error, Kali/DB unreachable, board offline) it returns [] and the loop just starts from
    the board's own brainstorm as before. Opt-out with AEGIS_PLANNER=0."""
    if os.environ.get("AEGIS_PLANNER", "1") == "0":
        return []
    try:
        plan = Planner().plan(objective, target, surfaces=surfaces, roles=roles, stack=stack,
                              task_level=task_level, base=base, limit=limit, board=board, novel=novel)
        moves = plan.get("seed_moves") or []
        for m in moves:
            m.setdefault("_planner_mode", mode)
        return moves
    except Exception:
        return []


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Planner: rank prior-successful techniques + emit seed_moves.")
    ap.add_argument("objective")
    ap.add_argument("--target", required=True)
    ap.add_argument("--surfaces", nargs="*", default=None)
    ap.add_argument("--roles", nargs="*", default=None)
    ap.add_argument("--stack", nargs="*", default=None)
    ap.add_argument("--task-level", default="fact-finding")
    ap.add_argument("--limit", type=int, default=12)
    ap.add_argument("--no-board", action="store_true", help="skip board relevance filter (platform pre-filter only)")
    ap.add_argument("--novel", type=int, default=4, help="how many NOVEL board approaches to add (0 = none)")
    ap.add_argument("--scenarios", type=int, default=1,
                    help="emit N candidate plans (fast-track/thorough/covert) -- the mid-run RE-OPEN queue")
    a = ap.parse_args()
    if a.scenarios > 1:
        plans = Planner().candidate_plans(a.objective, a.target, a.surfaces, a.roles, a.stack,
                                          a.task_level, n_scenarios=a.scenarios, limit=a.limit,
                                          board=not a.no_board, novel=a.novel)
        print(json.dumps([{"name": pl["name"], "score": pl["score"], "desc": pl["desc"],
                           "seed_count": len(pl["seed_moves"]),
                           "novel": [m["technique"] for m in pl["novel_moves"]]} for pl in plans],
                         indent=2))
        return
    plan = Planner().plan(a.objective, a.target, a.surfaces, a.roles, a.stack, a.task_level,
                          limit=a.limit, board=not a.no_board, novel=a.novel)
    print(json.dumps({"fingerprint": plan["fingerprint"], "candidates_considered": plan["candidates"],
                      "relevant": [{"id": t.get("id"), "class": t.get("class"),
                                    "tools": t.get("kali_tools"), "mitre": t.get("mitre_id"),
                                    "relevance": t.get("_relevance")} for t in plan["relevant"]],
                      "novel_moves": [{"technique": m["technique"], "vuln_class": m["vuln_class"],
                                       "tool": m.get("tool"), "new_code": m.get("new_code"),
                                       "why": m["why_novel"]} for m in plan["novel_moves"]],
                      "seed_count": len(plan["seed_moves"])}, indent=2))


if __name__ == "__main__":
    main()
