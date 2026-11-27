"""tool_forge.py -- self-extending tooling at runtime (ARTEX-port #6).

On a hard target the blocker is frequently "the one tool/parser/exploit we don't have." Instead of
abandoning the route, the agent FORGES a small tool (shell command / python script / http request),
registers it, and keeps going -- and because it's persisted, every later run reuses it (compounding
capability). A skill_gaps log records tools the agent needed but the platform lacked (evidence-backed
backlog). Reuses Aegis's execution substrate (Kali driver + egress proxy) and is scope/non-destructive
gated. Gate AEGIS_TOOL_FORGE=0.

  create_tool(name, kind, spec)   kind: command | script | http
  call_tool(name, params)         run a registered tool, return its output
  note_gap(name, why)             log a missing capability
"""
import os, json, time, shlex, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_REG = os.path.join(HERE, "forged_tools.json")
_GAPS = os.path.join(HERE, "skill_gaps.jsonl")
# never forge a tool whose body does destructive things (doctrine: plant/read for proof, never erase)
_DESTRUCTIVE = ("rm -rf", "mkfs", "dd if=", "drop table", "drop database", "truncate ", "> /dev/sd",
                ":(){", "shutdown", "reboot", "deltree", "format ")


def _enabled():
    return str(os.environ.get("AEGIS_TOOL_FORGE", "1")).lower() not in ("0", "false", "no", "off")


def _load():
    try:
        return json.load(open(_REG, encoding="utf-8"))
    except Exception:
        return {}


def _save(d):
    tmp = _REG + ".tmp"
    json.dump(d, open(tmp, "w", encoding="utf-8"), indent=2)
    os.replace(tmp, _REG)


def _safe(spec_text):
    low = (spec_text or "").lower()
    return not any(d in low for d in _DESTRUCTIVE)


def create_tool(name, kind, spec, description="") -> dict:
    """Register a reusable tool. kind: command (a bash template with {param} slots), script (python source,
    params via stdin JSON), http (a request template {method,url,headers,body}). Non-destructive only."""
    if not _enabled():
        return {"ok": False, "error": "tool-forge disabled"}
    name = "".join(c for c in (name or "") if c.isalnum() or c in "-_")[:48]
    if not name or kind not in ("command", "script", "http"):
        return {"ok": False, "error": "bad name/kind"}
    body = spec if isinstance(spec, str) else json.dumps(spec)
    if not _safe(body):
        return {"ok": False, "error": "refused: spec contains a destructive operation"}
    reg = _load()
    reg[name] = {"kind": kind, "spec": spec, "description": description, "created": time.time(),
                 "uses": reg.get(name, {}).get("uses", 0)}
    _save(reg)
    return {"ok": True, "name": name, "kind": kind}


def _run_cmd(cmd, timeout=120):
    """Run a shell command in Kali (through the Kali driver choke point if available, else local wsl)."""
    try:
        import vectors
        return vectors._route_line("sh", cmd, timeout)        # Kali/BlackArch router + tool-concurrency gate
    except Exception:
        try:
            distro = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
            p = subprocess.run(["wsl", "-d", distro, "--", "bash", "-lc", cmd],
                               capture_output=True, text=True, timeout=timeout, errors="replace")
            return (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return f"[forge error] {e!r}"


def call_tool(name, params=None) -> dict:
    reg = _load()
    t = reg.get(name)
    if not t:
        return {"ok": False, "error": f"no forged tool {name!r}"}
    params = params or {}
    kind, spec = t["kind"], t["spec"]
    out = ""
    try:
        if kind == "command":
            cmd = spec
            for k, v in params.items():
                cmd = cmd.replace("{%s}" % k, shlex.quote(str(v)))
            if not _safe(cmd):
                return {"ok": False, "error": "refused: resolved command is destructive"}
            out = _run_cmd(cmd)
        elif kind == "script":
            fd, path = tempfile.mkstemp(suffix=".py", prefix="forge_")
            os.write(fd, (spec if isinstance(spec, str) else "").encode()); os.close(fd)
            try:
                p = subprocess.run(["python", "-I", path], input=json.dumps(params),
                                   capture_output=True, text=True, timeout=120, errors="replace")
                out = (p.stdout or "") + (p.stderr or "")
            finally:
                os.remove(path)
        elif kind == "http":
            import requests as _rq
            s = spec if isinstance(spec, dict) else json.loads(spec)
            px = os.environ.get("HTTPS_PROXY") or os.environ.get("AEGIS_EGRESS_PROXY")
            proxies = {"http": px, "https": px} if px else None
            r = _rq.request(s.get("method", "GET"), s.get("url", "").format(**params),
                            headers=s.get("headers"), data=s.get("body"), timeout=30,
                            verify=False, proxies=proxies, allow_redirects=False)
            out = f"HTTP {r.status_code}\n" + (r.text or "")[:4000]
        reg[name]["uses"] = reg[name].get("uses", 0) + 1
        _save(reg)
        return {"ok": True, "name": name, "output": out[:8000]}
    except Exception as e:
        return {"ok": False, "error": repr(e)[:200]}


def list_tools():
    return {k: {"kind": v["kind"], "uses": v.get("uses", 0), "desc": v.get("description", "")}
            for k, v in _load().items()}


def note_gap(name, why=""):
    try:
        with open(_GAPS, "a", encoding="utf-8") as f:
            f.write(json.dumps({"name": name, "why": why, "ts": time.time()}) + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    import sys
    print(json.dumps(list_tools() if "--list" in sys.argv else {"forge": "ready", "tools": len(_load())}, indent=2))
