#!/usr/bin/env python3
"""intervene.py -- signature classifier + Tier-A verb playbook (board build-order step 3).

Rule-first, LLM-second: a human recognizes EACCES / "address already in use" / a password prompt
instantly -- don't pay a model round-trip for a known signature. This module turns a mishap's output
(and optional process state) into a KNOWN signature and a Tier-A structured VERB PLAN (a closed
vocabulary, no free-form shell). The AutoLoop applies the plan behind the allowlist/guard and verifies;
anything unclassified returns escalate=True so the loop routes it to the direct Support line (Claude CLI).

Verbs (closed set): kill_and_retry, kill_port_holder, restart_service, elevate_context, re_platform,
batch_noninteractive, fence_and_skip. Each plan is data, applied by the caller -- see AutoLoop.
"""
import re

# name, compiled regex over the output tail, verb, one-line note. Order = priority (first match wins).
_SIGNATURES = [
    ("file_lock",     r"being used by another process|ERROR_SHARING_VIOLATION|locked by another|"
                      r"resource temporarily unavailable|text file busy|resource busy",
     "fence_and_skip", "resource held by another process -- do NOT retry on the same host (today's zombie)"),
    ("permission",    r"permission denied|EACCES|operation not permitted|\bpermission\b.*denied",
     "elevate_context", "re-run in a privileged/root executor (e.g. kali root) or a narrow capability"),
    ("addr_in_use",   r"address already in use|EADDRINUSE|bind:? address|port is already allocated",
     "kill_port_holder", "a stale process holds the port -- free it, then retry"),
    ("docker_down",   r"cannot connect to the docker daemon|docker daemon socket|is the docker daemon running",
     "restart_service", "docker daemon down -- start it, then retry"),
    ("prompt_wait",   r"password:|passphrase|enter passphrase|\[y/n\]|yes/no|are you sure|press any key",
     "batch_noninteractive", "blocked on an interactive prompt -- re-run noninteractive/batch"),
    ("conn_refused",  r"connection refused|ECONNREFUSED|could not connect|failed to connect|actively refused",
     "restart_service", "the service the step needs is down -- restart it, then retry"),
    ("unreachable",   r"could not resolve|name or service not known|no route to host|network is unreachable|"
                      r"could not be resolved|timed out|timeout|HTTP 000",
     "re_platform", "target unreachable from this executor -- re-issue from one that can reach it"),
]
_COMPILED = [(n, re.compile(rx, re.I), v, note) for (n, rx, v, note) in _SIGNATURES]


def classify(output, proc_state=None):
    """Return {name, verb, note} for the first matching signature, else None. proc_state 'D'/'Z' (a
    force-kill-resistant / zombie process) overrides to fence_and_skip -- never retry it on the host."""
    if proc_state in ("D", "Z"):
        return {"name": "dstate", "verb": "fence_and_skip",
                "note": f"process in '{proc_state}' state -- unkillable I/O wait; fence + skip/re-platform"}
    text = output or ""
    for name, rx, verb, note in _COMPILED:
        if rx.search(text):
            return {"name": name, "verb": verb, "note": note}
    return None


def plan(signature, ctx=None):
    """Turn a classified signature into a Tier-A VERB PLAN the caller applies. ctx may carry: port,
    base, kali, service, compose_dir. Returns a dict:
      {verb, action, cmd?, kali?, retriable, terminal_hint?, note}
    action in {retry, retry_kali, run, skip}. `cmd` (if any) is allowlisted+guarded by the caller."""
    ctx = ctx or {}
    v = signature["verb"]
    base = {"verb": v, "note": signature.get("note", "")}
    if v == "fence_and_skip":
        return {**base, "action": "skip", "retriable": False, "terminal_hint": "fenced"}
    if v == "elevate_context":
        return {**base, "action": "retry_kali", "retriable": True}
    if v == "re_platform":
        return {**base, "action": "retry_kali", "retriable": True}
    if v == "batch_noninteractive":
        # supervisor already runs stdin=DEVNULL + noninteractive env; a plain retry is usually enough
        return {**base, "action": "retry", "retriable": True}
    if v == "kill_port_holder":
        port = ctx.get("port")
        cmd = (f"fuser -k {port}/tcp" if port else None)
        return {**base, "action": ("run" if cmd else "retry"), "cmd": cmd, "kali": ctx.get("kali", False),
                "retriable": True}
    if v == "restart_service":
        # prefer a configured service/compose restart; else generic docker up in the compose dir
        if ctx.get("service") == "docker":
            cmd = "service docker start"
        elif ctx.get("compose_dir"):
            cmd = f'cd "{ctx["compose_dir"]}" && docker compose up -d'
        else:
            cmd = "docker compose up -d"
        return {**base, "action": "run", "cmd": cmd, "kali": ctx.get("kali", True), "retriable": True}
    if v == "kill_and_retry":
        return {**base, "action": "retry", "retriable": True}
    return {**base, "action": "retry", "retriable": True}


def handle(output, ctx=None, proc_state=None):
    """Convenience: classify + plan in one call. Returns (signature, plan) or (None, None) -> escalate."""
    sig = classify(output, proc_state=proc_state)
    if not sig:
        return None, None
    return sig, plan(sig, ctx)


if __name__ == "__main__":
    # quick self-test of the classifier against today's real signatures
    cases = {
        "The process cannot access the file because it is being used by another process": "fence_and_skip",
        "dial unix /var/run/docker.sock: connect: permission denied": "elevate_context",
        "bind: address already in use": "kill_port_holder",
        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock": "restart_service",
        "sudo: a password is required\npassword:": "batch_noninteractive",
        "curl: (7) Failed to connect to localhost port 8443: Connection refused": "restart_service",
        "curl HTTP 000 could not resolve host": "re_platform",
        "some totally novel error nobody has seen": None,
    }
    ok = 0
    for text, want in cases.items():
        sig = classify(text)
        got = sig["verb"] if sig else None
        flag = "OK " if got == want else "XX "
        ok += got == want
        print(f"{flag}{got!s:<20} <- {text[:60]}")
    print(f"\n{ok}/{len(cases)} classified as expected")
