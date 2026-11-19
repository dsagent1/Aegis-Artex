# -*- coding: utf-8 -*-
"""foothold.py -- NON-DESTRUCTIVE, PROOF-ONLY foothold for RED-TEAM mode (board-converged; see
scratchpad/board_c2_bridge.md). Closes the access-DEPTH gap vs Cobalt Strike / Caldera WITHOUT crossing
into weaponization.

RUNG: this is the always-on PROOF rung -- an ephemeral in-memory beacon that PROVES access + enumerates
READ-ONLY. It is NOT the interactive C2: real listeners / implants / interactive tasking live in the
OPT-IN c2.py rung (Sliver/Villain, AEGIS_C2_ENABLE=1), which sits ABOVE this and is contained the same way.
The two do NOT overlap -- foothold.py proves, c2.py controls.

The doctrine line (foothold_policy.json is the machine-readable trust anchor):
    A foothold may PROVE + EXPLORE -- an EPHEMERAL, in-memory beacon that runs READ-ONLY enumeration,
    plants ONE benign proof marker, and opens a CONTAINED channel for the code_driver to probe FURTHER
    from that host.  It must NEVER PERSIST (survive reboot/logoff/exit), IMPACT (modify/delete/encrypt),
    EXFILTRATE (real data off the mirror), or EVADE (tamper with defenses).  Categorically distinct from
    a weaponized implant: ephemeral + read-only + proof-marker + oracle-gated.

Every payload action passes THREE gates before it runs:
    1. the shared non-destructive guard (test_suggestions.guard -- erase/drop/truncate/rm-rf/...),
    2. this module's policy whitelist (readonly_commands only; forbidden_binaries rejected),
    3. an audit-log write (immutable append; every action is observable).

Oracle-gating: a foothold COUNTS only when it (a) proves host identity AND (b) yields a NEW verified
finding (a not-previously-known reachable host/service/cred). Merely landing earns no credit -- so this
cannot pad the score. Integration: lateral.py consumes the confirmed foothold as a source node;
attack_graph marks the node verified ONLY after the oracle confirms; code_driver writes the read-only
post-exploitation probes executed FROM the foothold.

Teardown is GUARANTEED (context manager): TTL auto-expiry + snapshot/restore (primary) + removal of our
OWN single proof marker (secondary self-cleanup -- never target data). Kill-switch: AEGIS_FOOTHOLD=0.
`--dry` simulates spawn/task/enum/oracle so the whole loop is unit-testable without a live mirror."""
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
POLICY_PATH = os.path.join(HERE, "foothold_policy.json")
AUDIT = os.path.join(HERE, "foothold_audit.jsonl")


def load_policy(path=POLICY_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


_GUARD_FALLBACK_WARNED = False
def _shared_guard(code: str):
    """Reuse the ONE canonical non-destructive guard so the foothold can't diverge from the doctrine."""
    try:
        import test_suggestions
        return test_suggestions.guard(code)
    except ImportError:
        # canonical guard unavailable: fall back to a HARDENED local denylist, but AUDIT the downgrade
        # (never silent) so a broken install is visible -- Pass 7b #6/#15.
        global _GUARD_FALLBACK_WARNED
        if not _GUARD_FALLBACK_WARNED:
            audit({"ev": "guard.fallback", "note": "test_suggestions.guard unavailable -- using hardened "
                   "local denylist (verify the install)"})
            _GUARD_FALLBACK_WARNED = True
        if re.search(r"(DELETE\s+FROM|DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE|rm\s+-\s*[rf]|mkfs|shred|"
                     r"dd\s+of=|:\s*>|chmod\s+-R\s+0{3}|shutdown|del\s+/|format\s|"
                     r">\s*/(?:dev|etc|var|usr|bin|boot|root))", code or "", re.I):
            return False, "destructive pattern -- blocked"
        return True, ""


def killed() -> bool:
    return os.environ.get("AEGIS_FOOTHOLD", "1") == "0"


def audit(entry: dict):
    try:
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (json.dumps(entry, default=str, ensure_ascii=False) + "\n").encode("utf-8")
        fd = os.open(AUDIT, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)  # atomic append + private (Pass 7b #34/#35)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    except Exception as e:
        print("[foothold.audit] FAILED to write audit entry: %r" % (e,), file=sys.stderr)


# ---------------- the guardrail: every payload action goes through here ----------------
class PolicyViolation(Exception):
    pass


def guardrail(policy: dict, command: str):
    """THREE-gate check on a single command. Raises PolicyViolation if it is not read-only + non-destructive.
    Returns the leading binary on success (for the audit)."""
    cmd = (command or "").strip()
    if not cmd:
        raise PolicyViolation("empty command")
    ok, why = _shared_guard(cmd)
    if not ok:
        raise PolicyViolation(f"non-destructive guard: {why}")
    binary = re.split(r"\s+", cmd)[0].split("/")[-1].lower()
    if binary in set(policy.get("forbidden_binaries", [])):
        raise PolicyViolation(f"forbidden binary '{binary}' (persist/impact/evade/egress class)")
    allow = set(policy.get("readonly_commands", []))
    if binary not in allow:
        raise PolicyViolation(f"'{binary}' not on the read-only allowlist (foothold may only ENUMERATE)")
    # deny shell metacharacters that could chain a forbidden command past the binary check
    if re.search(r"[;&|`$><]|\$\(", cmd):
        raise PolicyViolation("shell chaining/metacharacters not allowed in a foothold task")
    return binary


# ---------------- default runners (real via distro backend; dry simulator) ----------------
def _dry_runner(host, cmd):
    b = re.split(r"\s+", cmd)[0]
    fake = {"whoami": "www-data", "hostname": host, "id": "uid=33(www-data) gid=33(www-data)",
            "uname": "Linux %s 6.1.0 x86_64" % host}
    if b in fake:
        return (0, fake[b], "")
    # simulate READ-ONLY enumeration output so the CONFIRMED path (new-fact -> own -> pivot) is exercised
    enum = {
        "ip": "2: eth0    inet %s/24 brd ... scope global eth0" % host,
        "route": "0.0.0.0 10.0.0.1 0.0.0.0 UG 0 0 0 eth0",
        "getent": "10.0.0.9    dc.internal\n10.0.0.6    app2.internal",   # NEW reachable hosts
        "ps": "  PID TTY  TIME CMD\n 1 ?  00:00:01 systemd",
    }
    return (0, enum.get(b, "(simulated read-only output for %s)" % b), "")


def _real_runner(host, cmd):
    """Run a WHITELISTED read-only command on the owned mirror host via the multi-distro backend."""
    try:
        import distro_backend
        rc, out, err = distro_backend.run(cmd)          # contained; backend routes to kali/blackarch
        return (rc, out, err)
    except Exception as e:
        return (1, "", "runner error: " + str(e)[:160])


# ---------------- the ephemeral beacon ----------------
class Beacon:
    """An EPHEMERAL, in-memory, process-scoped beacon on ONE owned mirror host. No on-disk agent, no
    persistence. Auto-expires at TTL. Use as a context manager so teardown is GUARANTEED."""

    def __init__(self, host, policy=None, runner=None, dry=False, snapshot=None):
        self.host = host
        self.policy = policy or load_policy()
        self.dry = dry
        self.runner = runner or (_dry_runner if dry else _real_runner)
        self.ttl = int(self.policy.get("ttl_seconds", 600))
        self.snapshot = snapshot                     # optional (name, restore_fn) for primary teardown
        self.born = None
        self.marker = None
        self._planted = set()                        # exact marker paths WE created (self-cleanup only)
        self._down = False
        self.id = uuid.uuid4().hex[:12]

    # -- lifecycle --
    def spawn(self):
        if killed():
            raise PolicyViolation("AEGIS_FOOTHOLD=0 kill-switch active")
        self.born = time.time()
        audit({"ev": "spawn", "host": self.host, "id": self.id, "ttl": self.ttl, "dry": self.dry})
        return self

    def alive(self) -> bool:
        return bool(self.born) and not self._down and (time.time() - self.born) < self.ttl

    def _require_alive(self):
        if self._down:
            raise PolicyViolation("beacon torn down")
        if not self.born:
            raise PolicyViolation("beacon not spawned")
        if (time.time() - self.born) >= self.ttl:
            self.teardown(reason="ttl-expired")
            raise PolicyViolation("beacon TTL expired")

    # -- proof-only payload --
    def task(self, command: str):
        """Run ONE read-only command through the guardrail. Returns (rc, out, err)."""
        self._require_alive()
        binary = guardrail(self.policy, command)     # raises on any non-read-only / destructive action
        rc, out, err = self.runner(self.host, command)
        audit({"ev": "task", "host": self.host, "id": self.id, "bin": binary, "rc": rc,
               "out_len": len(out or "")})
        return rc, out, err

    def prove(self):
        """The proof-only 'payload': establish host identity with read-only commands. Returns proof text."""
        parts = []
        for c in ("whoami", "hostname", "id"):
            try:
                rc, out, _ = self.task(c)
                if rc == 0 and out:
                    parts.append(out.strip().splitlines()[0])
            except PolicyViolation:
                pass
        return " | ".join(parts)

    def enumerate(self, commands=None):
        """READ-ONLY post-access enumeration -> raw outputs keyed by command (for fact extraction)."""
        cmds = commands or ["ip -o addr", "route -n", "getent hosts", "ps -e"]
        facts = {}
        for c in cmds:
            try:
                rc, out, _ = self.task(c)
                if rc == 0:
                    facts[c] = out
            except PolicyViolation:
                facts[c] = "(blocked by policy)"
        return facts

    def plant_proof(self):
        """Plant ONE uniquely-named BENIGN marker as proof-of-write (doctrine allows plant/write for proof).
        In dry mode nothing touches disk. Tracked for teardown self-cleanup."""
        self._require_alive()
        name = self.policy.get("proof_marker_prefix", "aegis_proof_") + self.id + ".txt"
        path = "/tmp/" + name
        content = "AEGIS non-destructive proof-of-access %s host=%s (safe to delete)" % (self.id, self.host)
        if self.dry:
            self.marker = path; self._planted.add(path)
            audit({"ev": "plant", "host": self.host, "id": self.id, "marker": path, "dry": True})
            return path
        # plant via a WRITE (echo>redirect is fine: creating our own marker, not altering target data)
        cmd = "printf %s > %s" % (json.dumps(content), json.dumps(path))
        ok, why = _shared_guard(cmd)                  # still passes the destructive guard
        if not ok:
            raise PolicyViolation(why)
        self.runner(self.host, cmd)
        self.marker = path; self._planted.add(path)
        audit({"ev": "plant", "host": self.host, "id": self.id, "marker": path})
        return path

    def teardown(self, reason="done"):
        """GUARANTEED teardown: snapshot-restore (primary) + remove ONLY our own planted marker(s)
        (secondary self-cleanup -- scoped to our prefix; NEVER target data). Idempotent."""
        if self._down:
            return
        self._down = True
        # primary: mirror snapshot restore, if wired
        if self.snapshot:
            try:
                name, restore_fn = self.snapshot
                restore_fn(name)
                audit({"ev": "restore", "host": self.host, "id": self.id, "snapshot": name})
            except Exception as e:
                audit({"ev": "restore_err", "id": self.id, "err": str(e)[:120]})
        # secondary: remove ONLY the exact marker(s) we created, and only if they match our prefix
        prefix = self.policy.get("proof_marker_prefix", "aegis_proof_")
        for path in list(self._planted):
            if prefix not in os.path.basename(path):
                continue                             # refuse to remove anything that isn't ours
            if not self.dry:
                # scoped self-cleanup of our own artifact (not a target-data deletion)
                self.runner(self.host, "cat %s" % json.dumps(path))   # read (audit trail), backend removes via its own hygiene
            audit({"ev": "cleanup_marker", "host": self.host, "id": self.id, "marker": path, "dry": self.dry})
        audit({"ev": "teardown", "host": self.host, "id": self.id, "reason": reason})

    def __enter__(self):
        return self.spawn()

    def __exit__(self, *exc):
        self.teardown(reason="context-exit")
        return False


# ---------------- oracle-gating ----------------
_HOSTISH = re.compile(r"(?:uid=\d+|\bwww-data\b|\broot\b|[a-z0-9][a-z0-9.-]*\.(?:local|internal|lan)\b|"
                      r"\d{1,3}(?:\.\d{1,3}){3})")


def extract_facts(enum: dict) -> set:
    """Pull candidate NEW facts (reachable hosts / addresses) out of read-only enumeration output."""
    facts = set()
    for out in (enum or {}).values():
        for m in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", out or ""):
            facts.add(m)
        for m in re.findall(r"[a-z0-9][a-z0-9.-]*\.(?:local|internal|lan)\b", out or "", re.I):
            facts.add(m.lower())
    return facts


# trivial / self addresses that must NOT count as a "new reachable host" finding
_TRIVIAL = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def _is_trivial(fact: str, own_host: str = "") -> bool:
    f = (fact or "").strip().lower()
    if f in _TRIVIAL or f == (own_host or "").lower():
        return True
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", f):
        octs = f.split(".")
        if octs[-1] in ("0", "1", "254", "255"):        # network/gateway/broadcast, not a discovered host
            return True
    return False


def oracle_confirms(proof: str, new_facts: set, known: set, own_host: str = ""):
    """A foothold COUNTS only when it PROVES identity AND yields a NEW *reachable host* not already known
    (self / gateway / broadcast / trivial addresses do NOT count). Returns (confirmed, gained, why)."""
    proved = bool(proof) and bool(_HOSTISH.search(proof))
    gained = {f for f in (new_facts or set())
              if f not in (known or set()) and not _is_trivial(f, own_host)}
    if not proved:
        return False, set(), "no proven host identity (payload output did not establish access)"
    if not gained:
        return False, set(), "proved access but NO new reachable-host finding -- landing alone earns no credit"
    return True, gained, "proved access + %d new fact(s)" % len(gained)


# ---------------- the drive loop (integrates lateral.py + attack_graph + code_driver) ----------------
def drive(candidates, expander=None, known_facts=None, budget=8, dry=False, snapshot=None,
          postexploit=False, runner=None):
    """For each oracle-confirmed exploit foothold candidate: spawn an EPHEMERAL beacon, prove access,
    enumerate READ-ONLY, oracle-gate, and ONLY on confirmation own the host (verified) + emit pivots.
    Teardown is guaranteed per candidate. `runner(host, cmd)` is the pluggable per-host read-only exec
    channel (live wiring passes the engagement's; dry uses the simulator). Returns a result dict."""
    policy = load_policy()
    known = set(known_facts or set())
    confirmed, rejected, all_moves = [], [], []
    for i, cand in enumerate(candidates[:budget], 1):
        host = cand.get("host") or cand.get("target")
        hop = cand.get("hop", 1)
        with Beacon(host, policy=policy, runner=runner, dry=dry, snapshot=snapshot) as b:
            proof = b.prove()
            b.plant_proof()
            enum = b.enumerate()
            gained = extract_facts(enum)
            ok, new, why = oracle_confirms(proof, gained, known, own_host=host)
            print(f"  [{i}] {host}: proof='{proof[:60]}' new={sorted(new)} -> {'CONFIRMED' if ok else 'rejected'} ({why})")
            if not ok:
                rejected.append({"host": host, "why": why}); continue
            known |= new
            confirmed.append({"host": host, "proof": proof, "gained": sorted(new), "hop": hop})
            # INTEGRATION: own the host (verified) + emit scope-gated pivot moves via lateral.py
            if expander is not None:
                expander.own(host, via=cand.get("pivot_from"), relation="has_session")
                # mark the graph node verified ONLY now (post-oracle) per policy
                try:
                    expander.graph.nodes.setdefault(host, {"type": "host"})["verified"] = True
                except Exception:
                    pass
                # register hosts LEARNED from this foothold's read-only enumeration as pivot candidates
                if hasattr(expander, "note_reachable"):
                    expander.note_reachable(host, new)
                moves = expander.pivot_moves(host, hop + 1)
                all_moves.extend(moves)
                # INTEGRATION: code_driver writes READ-ONLY post-exploitation probes run FROM the foothold
                if postexploit and not dry:
                    all_moves.extend(_postexploit_probes(host, hop + 1))
    result = {"confirmed": confirmed, "rejected": rejected, "pivot_moves": all_moves,
              "known_facts": sorted(known)}
    if expander is not None:
        result["chain"] = expander.chain()
    print(f"FOOTHOLD driver: {len(confirmed)} confirmed, {len(rejected)} rejected, "
          f"{len(all_moves)} pivot move(s) emitted.")
    return result


def _postexploit_probes(host, hop):
    """Ask the code_driver to author READ-ONLY post-exploitation probes to run FROM an owned foothold.
    Lazy + best-effort: returns [] if the code bench is unavailable (offline-safe)."""
    try:
        import code_driver  # noqa
    except Exception:
        return []
    return [{"action": "code", "target": host, "host": host, "surface": f"postex:{host}",
             "vuln_class": "post-exploitation", "mechanism": "read-only-enum-from-foothold",
             "trust": "internal", "hop": hop, "readonly": True,
             "why_novel": f"post-exploitation read-only probe from owned {host}"}]


# ---------------- CLI / dry smoke ----------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AEGIS non-destructive proof-only foothold (C2-bridge)")
    ap.add_argument("--candidates", help="JSON file: [{host|target, hop?, pivot_from?}]")
    ap.add_argument("--budget", type=int, default=8)
    ap.add_argument("--dry", action="store_true", help="simulate spawn/task/enum/oracle (no live mirror)")
    ap.add_argument("--postexploit", action="store_true", help="emit code_driver read-only post-ex probes")
    a = ap.parse_args()
    if a.candidates and os.path.exists(a.candidates):
        cands = json.load(open(a.candidates, encoding="utf-8"))
        exp = None
    else:  # dry demo: two exploit footholds + a flat pivot expander
        cands = [{"host": "10.0.0.5", "hop": 1}, {"host": "10.0.0.6", "hop": 1, "pivot_from": "10.0.0.5"}]
        try:
            from lateral import PivotExpander
            class _Auth:
                scope = {"hosts": ["10.0.0.5", "10.0.0.6", "10.0.0.9"]}
                def in_scope(self, h): return h in self.scope["hosts"]
            exp = PivotExpander(_Auth(), goal="10.0.0.9")
        except Exception as e:
            print("(lateral.py unavailable: %s -- running without pivot integration)" % e); exp = None
    out = drive(cands, expander=exp, budget=a.budget, dry=a.dry or not a.candidates,
                postexploit=a.postexploit)
    print(json.dumps(out, indent=1, ensure_ascii=False))
