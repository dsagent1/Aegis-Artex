#!/usr/bin/env python3
"""executor_registry.py -- the MISSING MECHANISM: turn per-executor reachability into an executor DECISION.

Background (the gap this closes): preflight probed the target from the Windows host only, and the AutoLoop
computed reachability={windows,kali} (G4) but never ACTED on it. So when the Windows->WSL localhost:8443
forward was flaky (000/502) while the mirror was perfectly healthy INSIDE Kali, the orchestrator kept
firing target-facing stages at a dead forward and logged infra-blocked 'inconclusive' -- with no awareness
that a reachable executor (Kali) was sitting right there.

This module is what DS reads and acts on:
  - executors.json is the OPERATIONAL MEMORY: the ordered list of executors and how each reaches the target.
  - select(base) probes each executor's reachability to the target NOW and returns the first that answers,
    with the target address to use from there and (for a non-local executor) the launch command.
  - the decision is persisted to executor_state.json so the rest of the run -- and a later resume, and a
    deep_consult -- can read 'which executor can reach the target and why' without re-probing.

Doctrine unchanged: contained mirror only, non-destructive, oracle-verified findings only.
"""
import os, json, time

_HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(_HERE, "executors.json")
STATE = os.path.join(_HERE, "executor_state.json")


def _load_registry():
    with open(REGISTRY, encoding="utf-8") as f:
        return json.load(f)


def _probe(addr, kali, timeout=8):
    """HTTP-reachability of `addr` from an executor. Returns (ok, http_code). Uses the supervised _sh so a
    hung curl can't wedge preflight."""
    try:
        import ds_orchestrator as DSO
        _sh = DSO._sh
    except Exception:
        import subprocess
        def _sh(cmd, timeout=60, kali=False):
            argv = (["wsl", "-d", os.environ.get("AEGIS_KALI_DISTRO", "kali-linux"), "-u", "root", "--",
                     "bash", "-lc", cmd] if kali else cmd)
            try:
                p = subprocess.run(argv, shell=not kali, capture_output=True, text=True, timeout=timeout)
                return p.returncode, (p.stdout or "") + (p.stderr or "")
            except Exception as e:
                return 1, str(e)
    curl = "curl.exe" if (os.name == "nt" and not kali) else "curl"
    devnull = "NUL" if (os.name == "nt" and not kali) else "/dev/null"
    rc, out = _sh(f'{curl} -sk -o {devnull} -w "%{{http_code}}" --max-time {timeout} {addr}/',
                  kali=kali, timeout=timeout + 12)
    code = "".join(ch for ch in (out or "") if ch.isdigit())[-3:] or "000"
    ok = (rc == 0) and code not in ("000", "502", "503", "504")
    return ok, code


def select(base=None, *, persist=True, probe=True):
    """Resolve the run executor + diagnose reachability. Returns a decision dict:
        {executor, target_addr, reachability:{name:code}, wsl_idle_suspected, reason, at}
    The chosen executor is ALWAYS the working route (windows-host / WSL localhost:8443); diagnostic_only
    executors (Kali) are probed as SENSORS, never selected to run work. A host-down + Kali-up reading is
    flagged as WSL idle-shutdown (fix: hold WSL up), not a reason to re-platform. `base` overrides the
    host target_addr. probe=False returns the route without probing."""
    reg = _load_registry()
    execs = reg["executors"]
    reach = {}
    host = next((e for e in execs if not e.get("kali")), execs[0])
    host_addr = base if base else host["target_addr"]
    sensors = [e for e in execs if e.get("diagnostic_only")]
    if not probe:
        return {"executor": host["name"], "target_addr": host_addr, "reachability": {},
                "wsl_idle_suspected": False, "reason": "route (no probe)", "at": int(time.time())}
    host_ok, host_code = _probe(host_addr, False)
    reach[host["name"]] = host_code
    sensor_up = False
    for s in sensors:
        ok, code = _probe(s["target_addr"], True)
        reach[s["name"]] = code
        sensor_up = sensor_up or ok
    wsl_idle = (not host_ok) and sensor_up
    if host_ok:
        reason = "host WSL route reaches the target"
    elif wsl_idle:
        reason = ("host route DOWN but Kali sees the mirror UP -> WSL idle-shutdown dropped the forward; "
                  "fix = hold WSL up (AutoLoop._wsl_hold), NOT re-platform")
    else:
        reason = f"target unreachable from host and Kali (codes {reach}); mirror likely down"
    decision = {
        "executor": host["name"],
        "target_addr": host_addr,
        "reachability": reach,
        "wsl_idle_suspected": wsl_idle,
        "reason": reason,
        "at": int(time.time()),
    }
    if persist:
        try:
            with open(STATE, "w", encoding="utf-8") as f:
                json.dump(decision, f, indent=2)
        except Exception:
            pass
    return decision


def last_decision():
    """Read the persisted executor decision (operational memory), or None. Lets a resume / deep_consult
    know which executor was chosen without re-probing."""
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def apply_env(decision):
    """Make the chosen (host) target address the one the engine uses this run."""
    if decision.get("target_addr"):
        os.environ["AEGIS_TARGET"] = decision["target_addr"]
    os.environ["AEGIS_EXECUTOR"] = decision.get("executor", "windows-host")
    return decision


if __name__ == "__main__":
    import sys
    base = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AEGIS_TARGET")
    d = select(base)
    print(json.dumps(d, indent=2))
    print(f"\n-> route: {d['executor']} at {d['target_addr']}")
    if d["wsl_idle_suspected"]:
        print("-> WSL idle-shutdown suspected: hold WSL up (wsl -d kali-linux -- sleep 86400)")
