"""patch_differ.py -- n-day / patch-diffing capability for the code bench (STANDALONE, unwired).

Implements the owner's exploit-discovery ladder for a fingerprinted component+version:

  1. PUBLIC EXPLOIT   -- is there a public exploit for this component/version/CVE? (searchsploit/RAG/gh).
                         If yes -> use/adapt it (mode="public_exploit").
  2. FETCH RELEASES   -- if not, resolve the last-VULNERABLE ref and the target (patched) ref in the
  3. DIFF             -- component's public repo, and diff them (GitHub compare API; git-clone fallback).
  4. BUILD-FROM-DIFF  -- extract the SECURITY-relevant hunks (the fix reveals the bug) and hand them to the
                         code bench to synthesize a probe against the patched function (mode="patch_diff").
  5. NOVEL            -- if the target function is fully patched OR no probing approach is findable from the
                         diff, fall through to novel-code discovery (mode="novel").

Pure helper: it RETURNS a structured plan; it does not run exploits. Wire plan()/security_hunks() into
code_driver as a 'patch_diff' direction later. Offline-safe: every network step degrades to a lower rung.
"""
from __future__ import annotations
import json, os, re, subprocess, shutil, tempfile, urllib.request, hashlib, ssl, socket

# component (lowercased fingerprint token) -> public source repo "owner/name"
COMPONENT_REPOS = {
    "cyberpanel": "usmannasir/cyberpanel",
    "wordpress": "WordPress/WordPress",
    "woocommerce": "woocommerce/woocommerce",
    "litespeed-cache": "litespeedtech/lscache_wp",
    "gitlab": "gitlabhq/gitlabhq",
    "nextcloud": "nextcloud/server",
    "grafana": "grafana/grafana",
    "elementor": "elementor/elementor",                       # major WP plugin, public on GitHub (diffable)
    "akismet": "Automattic/akismet",
    "jetpack": "Automattic/jetpack",
}

# hunk lines that touch a security-relevant surface (the patch usually tightens one of these)
_SEC_PATTERNS = re.compile(
    r"(auth|login|session|token|csrf|nonce|permission|is_admin|privilege|sanitiz|escap|validat|"
    r"subprocess|os\.system|popen|shell_?exec|eval\(|exec\(|pickle|yaml\.load|deseriali|"
    r"sql|query|execute\(|request\.(get|post|args|form|json)|\.\./|path.?traversal|"
    r"secret|password|command|cmd|whitelist|allowlist|denylist|verify)", re.I)


def _run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", repr(e)


def _gh_json(path):
    """GitHub API via the gh CLI (authed) -> parsed JSON, or None."""
    if not shutil.which("gh"):
        return None
    rc, out, _ = _run(["gh", "api", path], timeout=40)
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


# ---------------------------------------------------------------- step 1 ---
def check_public_exploit(component: str, version: str = "") -> list:
    """Step 1: public-exploit lookup. searchsploit (offline Exploit-DB) first; returns [{title,url,path}]."""
    hits = []
    distro = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
    if shutil.which("wsl"):
        rc, out, _ = _run(["wsl", "-d", distro, "--", "bash", "-lc",
                           f"searchsploit --json {component} 2>/dev/null"], timeout=40)
        if rc == 0 and out.strip():
            try:
                for e in (json.loads(out).get("RESULTS_EXPLOIT") or []):
                    hits.append({"title": e.get("Title"), "path": e.get("Path"),
                                 "url": e.get("Codes") or e.get("Path")})
            except Exception:
                pass
    return hits


def _exploit_targets_newer(hits: list, version: str) -> bool:
    """True if a public exploit targets a version >= the live version (i.e. likely still applies)."""
    lv = _vtuple(version)
    for h in hits:
        for m in re.findall(r"(\d+\.\d+(?:\.\d+)?)", h.get("title", "")):
            if _vtuple(m) >= lv:
                return True
    return False


# ---------------------------------------------------------------- refs ---
def _vtuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


def list_refs(repo: str) -> list:
    """All candidate refs (tags) with their version tuples, newest first."""
    tags = _gh_json(f"repos/{repo}/tags?per_page=100") or []
    refs = []
    for t in tags:
        name = t.get("name", "")
        if re.search(r"\d+\.\d+", name):
            refs.append({"name": name, "v": _vtuple(name), "sha": (t.get("commit") or {}).get("sha")})
    refs.sort(key=lambda r: r["v"], reverse=True)
    return refs


def resolve_ref(repo: str, version: str):
    """Best git ref for a version: exact-ish tag, else nearest tag, else a commit near the version date."""
    want = _vtuple(version)
    refs = list_refs(repo)
    for r in refs:                                   # exact or prefix match
        if r["v"][:len(want)] == want:
            return r["name"]
    below = [r for r in refs if r["v"] <= want]      # nearest at-or-below
    if below:
        return below[0]["name"]
    return refs[-1]["name"] if refs else None        # oldest as last resort


def last_vulnerable_version(component: str, patched_version: str, public_hits: list) -> str:
    """The version to diff AGAINST: the highest version named in a public exploit that is < the patched
    version (the last known-vulnerable), else one minor below the patched version."""
    pv = _vtuple(patched_version)
    cands = []
    for h in public_hits:
        for m in re.findall(r"(\d+\.\d+(?:\.\d+)?)", h.get("title", "")):
            if _vtuple(m) < pv:
                cands.append(m)
    if cands:
        return max(cands, key=_vtuple)
    maj, mn = (pv + (0, 0))[:2]
    return f"{maj}.{max(mn-1,0)}"


# ------------------------------------------------------------ step 2-3 ---
def diff_versions(repo: str, base_ref: str, head_ref: str, path_substrings=None) -> dict:
    """GitHub compare API base...head -> {files:[{filename,status,patch}], truncated}. Filtered to files
    whose path contains any of path_substrings (if given). git-clone fallback if the API is unavailable."""
    data = _gh_json(f"repos/{repo}/compare/{base_ref}...{head_ref}")
    files = []
    if data and isinstance(data.get("files"), list):
        for f in data["files"]:
            fn = f.get("filename", "")
            if path_substrings and not any(s in fn for s in path_substrings):
                continue
            if f.get("patch"):
                files.append({"filename": fn, "status": f.get("status"), "patch": f["patch"]})
        return {"files": files, "commits": data.get("total_commits"), "source": "gh-compare"}
    # fallback: shallow clone + git diff (bounded)
    return _diff_via_clone(repo, base_ref, head_ref, path_substrings)


def _diff_via_clone(repo, base_ref, head_ref, path_substrings):
    tmp = tempfile.mkdtemp(prefix="aegis_pd_")
    try:
        url = f"https://github.com/{repo}.git"
        if _run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", url, tmp], timeout=180)[0] != 0:
            return {"files": [], "error": "clone failed", "source": "clone"}
        for ref in (base_ref, head_ref):
            _run(["git", "-C", tmp, "fetch", "--quiet", "--depth", "1", "origin", ref], timeout=120)
        rc, out, err = _run(["git", "-C", tmp, "diff", base_ref, head_ref], timeout=90)
        files = []
        if rc == 0 and out:
            for block in re.split(r"(?=^diff --git )", out, flags=re.M):
                m = re.search(r"b/(\S+)", block)
                fn = m.group(1) if m else "?"
                if path_substrings and not any(s in fn for s in path_substrings):
                    continue
                if block.strip():
                    files.append({"filename": fn, "status": "modified", "patch": block[:8000]})
        return {"files": files, "source": "clone"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------ step 4 ---
def security_hunks(diff: dict, max_hunks=12) -> list:
    """Keep only the patch hunks that touch a security-relevant surface -- these are the candidate
    bug-fix sites the code bench should build a probe against. Returns [{filename, signals, hunk}]."""
    out = []
    for f in diff.get("files", []):
        for hunk in re.split(r"(?=^@@ )", f.get("patch", ""), flags=re.M):
            added = [l for l in hunk.splitlines() if l.startswith("+") and not l.startswith("+++")]
            removed = [l for l in hunk.splitlines() if l.startswith("-") and not l.startswith("---")]
            sig = sorted({m.group(0).lower() for l in (added + removed)
                          for m in [_SEC_PATTERNS.search(l)] if m})
            if sig:
                out.append({"filename": f["filename"], "signals": sig, "hunk": hunk[:1600]})
            if len(out) >= max_hunks:
                return out
    return out


# ------------------------------------------ fingerprint-trust gate (anti-spoof) ---
# A hardened target can POISON fingerprinting: fake Server/x-powered-by headers, serve a convincing
# facade, even mislabel the version. Patch-diff/commit-mine against a LIED-ABOUT version misses every
# time. So before trusting a version for a diff, CONFIRM it with signals a facade can't cheaply fake:
#   (1) CONTENT AUTHENTICITY -- fetch a version-pinned static asset from the LIVE target and the SAME
#       asset from the component's public source at the claimed version; the bytes must match. Fake
#       headers are free; serving the exact genuine asset bytes is not. Match => real code (whatever the
#       header says); mismatch-but-both-present => POISONED; can't fetch => UNCONFIRMED.
#   (2) TLS/JARM -- the server's TLS handshake fingerprints the real web stack, independent of HTTP.
# A stable, version-pinned asset per component (present in the public repo, served by the live app):
_ASSET_PROBE = {
    "wordpress": "wp-includes/js/wp-embed.min.js",
    "woocommerce": "assets/js/frontend/woocommerce.min.js",
    "cyberpanel": "static/baseTemplate/assets/css/cyberPanel.css",
    "grafana": "public/build/runtime.js",
}
_UNVERIFIED_CTX = ssl._create_unverified_context()


def _fetch_bytes(url, timeout=12, host_header=None):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        if host_header:
            req.add_header("Host", host_header)
        with urllib.request.urlopen(req, timeout=timeout, context=_UNVERIFIED_CTX) as r:
            return r.read(2_000_000)
    except Exception:
        return None


def _sha(b):
    return hashlib.sha256(b).hexdigest() if b else ""


def _jarm(host, port=443):
    """TLS/JARM-style fingerprint via a Kali tool if available (jarm), else an openssl handshake summary.
    Ground truth on the real server stack, independent of spoofable HTTP headers."""
    distro = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
    if shutil.which("wsl"):
        rc, out, _ = _run(["wsl", "-d", distro, "--", "bash", "-lc",
                           f"command -v jarm >/dev/null && jarm {host} -p {port} 2>/dev/null | tail -1 || "
                           f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null "
                           f"| grep -iE 'Protocol|Cipher|subject=|issuer=' | head -4"], timeout=30)
        if rc == 0 and out.strip():
            return out.strip()[:400]
    return ""


def confirm_fingerprint(base_url: str, component: str, version: str, host_header: str = None) -> dict:
    """Spoof-resistant version confirmation. Returns {trusted, poisoned, signals}. `trusted` is True only
    when the live app serves the GENUINE bytes of a version-pinned asset. `poisoned` is True when the
    target serves an asset that does NOT match the claimed version (active deception)."""
    component = (component or "").lower().strip()
    repo = COMPONENT_REPOS.get(component)
    out = {"base": base_url, "component": component, "claimed_version": version,
           "trusted": False, "poisoned": False, "signals": {}}
    host = re.sub(r"^https?://", "", (base_url or "")).split("/")[0].split(":")[0]
    # (2) TLS/JARM -- always useful, header-independent
    out["signals"]["tls"] = _jarm(host) or "unavailable"
    # (1) content authenticity
    asset = _ASSET_PROBE.get(component)
    if asset and repo and base_url:
        live = _fetch_bytes(base_url.rstrip("/") + "/" + asset, host_header=host_header)
        ref_candidates = []
        rref = resolve_ref(repo, version) or "master"
        for branch in (rref, "master", "stable", "main", "v" + version):
            b = _fetch_bytes(f"https://raw.githubusercontent.com/{repo}/{branch}/{asset}")
            if b:
                ref_candidates.append((branch, b)); break
        if live is None:
            out["signals"]["asset"] = {"asset": asset, "verdict": "live asset unreachable (banned/WAF) -- UNCONFIRMED"}
        elif not ref_candidates:
            out["signals"]["asset"] = {"asset": asset, "verdict": "reference asset unavailable -- UNCONFIRMED"}
        else:
            br, ref = ref_candidates[0]
            match = _sha(live) == _sha(ref)
            out["signals"]["asset"] = {"asset": asset, "ref_branch": br, "match": match,
                                       "live_sha": _sha(live)[:12], "ref_sha": _sha(ref)[:12]}
            out["trusted"] = match
            out["poisoned"] = (not match)  # both present but bytes differ => claimed identity is not the served code
    else:
        out["signals"]["asset"] = {"verdict": "no version-pinned asset known for this component -- UNCONFIRMED"}
    return out


# ------------------------------------------------------------ ladder ---
def plan(component: str, version: str, repo: str = None, prev_version: str = None,
         base_url: str = None, host_header: str = None, confirm: bool = True) -> dict:
    """Run the full ladder for one component+version. Returns a plan dict with `mode` in
    {public_exploit, patch_diff, novel, behavioral} plus the artifacts the code bench needs.

    When base_url is given and confirm=True, a FINGERPRINT-TRUST gate runs first: if the live app does
    NOT serve the genuine bytes of the claimed version (poisoned/unconfirmed fingerprint), the
    version-dependent rungs (patch-diff/commit-mine) are SKIPPED and the plan routes to behavioral/novel,
    because diffing a lied-about version is worthless."""
    component = (component or "").lower().strip()
    repo = repo or COMPONENT_REPOS.get(component)
    res = {"component": component, "version": version, "repo": repo}

    # fingerprint-trust gate -- do not diff a poisoned/unconfirmed version
    if base_url and confirm:
        fp = confirm_fingerprint(base_url, component, version, host_header=host_header)
        res["fingerprint"] = fp
        if fp.get("poisoned"):
            res["mode"] = "behavioral"
            res["note"] = ("fingerprint POISONED -- served asset bytes do not match the claimed version; "
                           "version-dependent rungs skipped. Probe version-independently (authz-matrix, "
                           "IDOR, auth-bypass on the real login behavior, spec-inference).")
            return res
        if not fp.get("trusted"):
            res["mode"] = "behavioral"
            res["note"] = ("fingerprint UNCONFIRMED -- could not verify the claimed version from genuine "
                           "served bytes (banned/WAF/unknown asset). Not trusting the version for a diff; "
                           "probe behaviorally + fall to novel-code. Re-confirm once a live asset is reachable.")
            return res

    # step 1
    hits = check_public_exploit(component, version)
    res["public_exploits"] = hits
    if hits and _exploit_targets_newer(hits, version):
        res["mode"] = "public_exploit"
        res["note"] = "a public exploit targets this version or newer -- adapt it directly"
        return res

    if not repo:
        res["mode"] = "novel"
        res["note"] = "no source repo known for this component -> novel-code direction"
        return res

    # step 2-3
    base = prev_version or last_vulnerable_version(component, version, hits)
    base_ref = resolve_ref(repo, base)
    head_ref = resolve_ref(repo, version)
    res.update({"diff_base": base, "base_ref": base_ref, "head_ref": head_ref})
    if not base_ref or not head_ref or base_ref == head_ref:
        res["mode"] = "novel"
        res["note"] = f"could not resolve two distinct refs ({base_ref}..{head_ref}) -> novel"
        return res
    paths = ["wp-includes", "wp-admin", ".py", "views", "api", "auth"] if component in ("wordpress", "cyberpanel") else None
    diff = diff_versions(repo, base_ref, head_ref, path_substrings=paths)
    hunks = security_hunks(diff)
    res["diff_files"] = len(diff.get("files", []))

    # step 4 / step 5
    if hunks:
        res["mode"] = "patch_diff"
        res["security_hunks"] = hunks
        res["note"] = (f"{len(hunks)} security-relevant hunk(s) between {base_ref} and {head_ref}; "
                       "hand to the code bench to synthesize a probe against the changed surface")
    else:
        res["mode"] = "novel"
        res["note"] = ("no security-relevant diff hunks found (fully patched / no approach findable) "
                       "-> novel-code direction")
    return res


if __name__ == "__main__":
    import sys
    comp = sys.argv[1] if len(sys.argv) > 1 else "cyberpanel"
    ver = sys.argv[2] if len(sys.argv) > 2 else "2.5.5"
    p = plan(comp, ver)
    p.pop("security_hunks", None)  # keep the CLI summary short
    print(json.dumps(p, indent=2, default=str))
