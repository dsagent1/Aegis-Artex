#!/usr/bin/env python3
"""autoloop.py -- AUTO MODE: the campaign controller (board build-order steps 5-7).

The strategic loop that runs the WHOLE framework end-to-end, unattended, the way a live operator does:
observe -> orient -> decide -> act, picking its own next step, running each stage as a SUPERVISED KILLABLE
CHILD (step_runner + supervisor), classifying + intervening on mishaps (intervene, Tier-A verbs), paging
the direct Support line (Claude CLI) when stuck, gating harness-boundary crossings to the human (fail-safe
= stick to the harness), and terminating with one of five explicit outcomes. State/learning via autostate.

Two controllers, one seam: AUTO (here) is strategic; the supervisor is the tactical step controller.
Scheduler is sequential in v1 (PRIMARY slot); concurrent PROBE/CONSULT slots are the documented next
hardening (see docs/DESIGN_auto_mode.md).
"""
import os, sys, json, time, subprocess, shutil, tempfile, threading
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import supervisor as SUP
import intervene as INT
import autostate as ST
import executor_registry as EXR

# reuse the guard + env-diagnostic helpers already built + tested in ds_orchestrator
import ds_orchestrator as DSO

# stages that make up the pipeline, in order
PHASES = ["BRINGUP", "DISCOVER", "ESCALATE", "REDTEAM", "REMEDIATE", "REPORT", "DONE"]
PHASE_KIND = {"DISCOVER": "operator", "ESCALATE": "exploitgym", "REDTEAM": "redteam", "REMEDIATE": "remediation"}
# commands the Support line / repairs may auto-run (allowlist; board: allowlist beats the denylist)
_ALLOW_VERBS = ("docker", "systemctl", "service", "kill", "pkill", "fuser", "lsof", "ss", "netstat",
                "curl", "wsl", "sleep", "echo", "ls", "cat", "grep", "ps", "compose")


def _allowlisted(cmd):
    if not cmd:
        return False
    s = cmd.strip()
    # Reject shell metacharacters that could smuggle a SECOND command past the allowlist (Pass 5a #2):
    # `curl http://x | bash`, `x ; rm -rf`, `$(...)`, backticks, `&` background. `&&` is intentionally
    # allowed for the "cd X && <verb>" repair shape, so neutralize it before the metachar scan.
    probe = s.replace("&&", "  ")
    if any(m in probe for m in (";", "|", "`", "$(", "&")):
        return False
    # Check the ACTUAL leading verb of EACH && segment -- not merely that SOME token matches an
    # allow-verb (the old any-token test passed `curl http://x | bash` because `curl` matched).
    for seg in s.split("&&"):
        seg = seg.strip().lstrip("(").strip()
        if not seg:
            continue
        verb = seg.split()[0].split("/")[-1].lower()
        if verb == "cd":                       # navigation only; the real verb is the next segment
            continue
        if not any(verb == v or verb.startswith(v) for v in _ALLOW_VERBS):
            return False
    return DSO._guard(cmd)


class AutoLoop:
    def __init__(self, *, base, role="dispatcher", campaign=None, per_leg_budget=8, auth=None,
                 dry=False, gate_timeout=0.0, budget=None, tick_max=60, inject=None):
        self.base = base
        self.role = role
        self.campaign = campaign or f"auto-{int(time.time())}"
        self.per_leg_budget = per_leg_budget
        self.auth = auth
        self.dry = dry
        self.gate_timeout = gate_timeout       # 0 = unattended -> gate fail-safes immediately to STICK
        self.budget = budget or ST.Budget()
        self.tick_max = tick_max               # safety cap on loop iterations
        self.inject = inject or {}             # {phase: "output text"} to force an incident (tests)
        self.state = ST.load_progress(self.campaign) or ST.new_autostate(self.campaign, phase="BRINGUP")
        self._store = os.path.join(HERE, "campaigns", self.campaign, "findings.jsonl")
        self.state.setdefault("coverage_omissions", [])
        self._compose_dir_cache = None    # discovered lazily in Kali for a targeted restart_service
        self._wsl_hold_proc = None        # long-lived attached WSL session that pins the distro up
        # G16: campaign-scoped target lease + health -- daemons keep the mirror alive and watch the exact
        # executor->target route the whole run, so a stage's probes are never silently infra-blocked.
        self._distro = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
        self._health = {"up": True, "fails": 0, "epoch": 0, "restarts": 0}
        self._health_lock = threading.Lock()
        self._stop_daemons = threading.Event()
        self._daemons = []
        self.log = []

    def _compose_dir_kali(self):
        """Discover (once, cached) the mirror's compose dir in Kali, so restart_service targets the REAL
        stack instead of a generic `docker compose up` in root's home (G11/compose-dir wiring)."""
        if self._compose_dir_cache is None:
            rc, out = DSO._sh('f=$(find /root /home -maxdepth 5 -iname "docker-compose*.y*ml" 2>/dev/null '
                              '| grep -i mirror | head -1); [ -n "$f" ] && dirname "$f"', kali=True, timeout=30)
            cand = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
            self._compose_dir_cache = cand if cand and cand not in (".", "/") else ""
        return self._compose_dir_cache or None

    # ---------- G16: target lease keepalive + health monitor (daemons in THIS process) ----------
    def _target_up(self):
        """Probe the EXACT executor->target route; up iff a real HTTP code (not 000/refused/timeout)."""
        if not self.base:
            return True
        curl = "curl.exe" if os.name == "nt" else "curl"
        devnull = "NUL" if os.name == "nt" else "/dev/null"
        rc, out = DSO._sh(f'{curl} -sk -o {devnull} -w "%{{http_code}}" --max-time 6 {self.base}/', timeout=15)
        return rc == 0 and out.strip()[-3:].isdigit() and "000" not in (out or "")

    def _restart_target(self):
        """Idempotently bring the mirror back up in Kali (targeted compose up, else start target containers)."""
        cd = self._compose_dir_kali()
        if cd:
            DSO._sh(f'cd "{cd}" && docker compose up -d', kali=True, timeout=120)
        else:
            DSO._sh("service docker start >/dev/null 2>&1; "
                    "docker start $(docker ps -aq --filter name=aegis-mirror) 2>/dev/null", kali=True, timeout=60)

    def _wsl_hold_start(self):
        """Pin the WSL distro UP for the whole run with a LONG-LIVED attached session. This is the real fix
        for the '000' seen earlier: WSL idle-shuts seconds after its last attached session ends and drops
        the mirror's localhost:8443 forward + containers. A 30s poll of instant `wsl -- true` commands does
        NOT hold it (each returns immediately, and the forward can drop between ticks). A held `sleep` does.
        The process is owned by the AutoLoop (not a stage child) so a leg's kill_tree can't tear it down."""
        if self._wsl_hold_proc and self._wsl_hold_proc.poll() is None:
            return
        try:
            self._wsl_hold_proc = subprocess.Popen(
                ["wsl", "-d", self._distro, "-u", "root", "--", "sleep", "86400"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            self._say(f"WSL hold started (pins {self._distro} up for the run)")
        except Exception as e:
            self._say(f"WSL hold failed to start ({str(e)[:60]}) -- host route may drop on idle")

    def _keepalive_loop(self):
        """Daemon: keep the WSL hold alive (respawn if it dies) so the localhost forward never drops. The
        held session is what prevents idle-shutdown; this loop only makes it self-healing."""
        while not self._stop_daemons.is_set():
            try:
                if not self._wsl_hold_proc or self._wsl_hold_proc.poll() is not None:
                    self._wsl_hold_start()
            except Exception:
                pass
            self._stop_daemons.wait(30)

    def _health_loop(self):
        """Daemon: watch the executor->target route with hysteresis; 2 consecutive fails -> mark DOWN +
        restart + bump epoch; recovery -> UP. Publishes self._health for the stage abort_check."""
        while not self._stop_daemons.is_set():
            up = self._target_up()
            with self._health_lock:
                if up:
                    if not self._health["up"]:
                        self._say("target health: RECOVERED")
                    self._health["up"] = True; self._health["fails"] = 0
                else:
                    self._health["fails"] += 1
                    if self._health["fails"] >= 2 and self._health["up"]:
                        self._health["up"] = False; self._health["epoch"] += 1
                        self._say(f"target health: DOWN (epoch {self._health['epoch']}) -> restarting mirror")
                        self._restart_target(); self._health["restarts"] += 1
            self._stop_daemons.wait(8)

    def _target_down(self):
        with self._health_lock:
            return not self._health["up"]

    def _start_daemons(self):
        if self.base and not self.dry and not self._daemons:
            self._wsl_hold_start()      # pin WSL up FIRST -- the actual fix for the host-route 000
            for fn in (self._keepalive_loop, self._health_loop):
                t = threading.Thread(target=fn, daemon=True); t.start(); self._daemons.append(t)
            self._say("G16 daemons started (WSL hold + keepalive + health monitor)")

    def _await_health(self, timeout=120):
        """Block (bounded) until the target is healthy again after a down; True if recovered."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self._target_down():
                return True
            time.sleep(4)
        return not self._target_down()

    def _stop_all_daemons(self):
        self._stop_daemons.set()
        if self._wsl_hold_proc and self._wsl_hold_proc.poll() is None:
            try:
                self._wsl_hold_proc.terminate()
            except Exception:
                pass

    def _say(self, m):
        line = f"[auto] {m}"
        self.log.append(line)
        print(line, file=sys.stderr, flush=True)

    # ---------- step 6: harness-boundary gate ----------
    def harness_check(self, action):
        """ALLOW inside limits; GATE a policy-exceptable crossing (over-budget continue, out-of-strict-scope);
        DENY the non-exceptionable. Stages are normally ALLOW; GATE fires on a needed over-budget continue."""
        if action.get("destructive"):
            return "DENY", "destructive action"
        if action.get("over_budget"):
            return "GATE", "would exceed the global budget"
        if action.get("out_of_scope"):
            return "GATE", "target/host outside strict scope"
        return "ALLOW", "within harness"

    def _gate(self, action, reason):
        """Ask the human 'stick to the harness, or go over it?'. Fail-safe = STICK (deny) when unattended.
        Approval is single-use, scoped to this one action, and audited to gate.jsonl."""
        req = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "campaign": self.campaign,
               "action": action.get("kind"), "reason": reason, "risk": action.get("risk", reason),
               "scope": "this action only"}
        ST.record_intervention(self.campaign, {"step_id": action.get("kind"), "signature": "harness_gate",
                                               "action": "ask_human", "outcome": "pending", **req})
        # authenticated decision channel: a signed/attended decision dropped at campaigns/<c>/gate_decision.json
        dec_path = os.path.join(ST._camp_dir(self.campaign), "gate_decision.json")
        deadline = time.time() + self.gate_timeout
        while time.time() < deadline:
            try:
                d = json.load(open(dec_path, encoding="utf-8"))
                if d.get("action") == action.get("kind") and d.get("decision") in ("approve", "deny"):
                    ST.record_intervention(self.campaign, {"step_id": action.get("kind"),
                        "signature": "harness_gate", "action": "human_decision",
                        "outcome": d["decision"], "approved_by": d.get("by")})
                    return d["decision"] == "approve"
            except Exception:
                pass
            time.sleep(1.0)
        # timeout / unattended -> FAIL SAFE: stick to the harness
        ST.record_intervention(self.campaign, {"step_id": action.get("kind"), "signature": "harness_gate",
            "action": "fail_safe_stick", "outcome": "deferred", "reason": "no human decision"})
        self._say(f"harness gate on '{action.get('kind')}' ({reason}) -> FAIL-SAFE: stick to harness")
        return False

    # ---------- step 7: direct Support line (Claude CLI) ----------
    def _rescue_cli(self, incident):
        """DIRECT 1:1 line to the Claude CLI support agent (NOT the board). 'I'm stuck, here's everything.'
        Returns (who, proposal_cmd|None). If the CLI is absent, the line is down -> None (caller escalates)."""
        exe = shutil.which(os.environ.get("ASKBOARD_CLAUDE_BIN") or "claude")
        if not exe:
            self._say("Support line DOWN (no claude CLI) -> escalate to human")
            return ("none", None)
        prior = ST.last_incidents(self.campaign, 5)
        sysp = ("You are the on-call SUPPORT operator for an autonomous security-test framework. It is STUCK. "
                "Reply with ONE non-destructive shell command to unstick the FRAMEWORK (restart a service, "
                "free a port, re-platform), or exactly NONE. No prose.")
        usr = (f"Incident on step '{incident.get('step_id')}': {incident.get('signature')}\n"
               f"Output:\n{(incident.get('output') or '')[:800]}\nPrior fixes tried: {json.dumps(prior)[:400]}")
        try:
            with tempfile.TemporaryDirectory(prefix="auto-rescue-") as cwd:
                p = subprocess.run([exe, "-p", "--max-turns", "1", "--allowed-tools", ""],
                                   input=f"{sysp}\n\n{usr}", capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=300, cwd=cwd)
            cmd = DSO._extract_cmd(p.stdout or "") if p.returncode == 0 else ""
            return ("claude", cmd or None)
        except Exception as e:
            self._say(f"Support line error ({str(e)[:60]}) -> escalate to human")
            return ("none", None)

    # ---------- act: run one stage as a supervised child, then handle incidents ----------
    def _run_stage(self, kind):
        # Stages run on the Windows host against the mirror over the WSL localhost:8443 route. That route
        # is reliable as long as WSL is HELD UP for the run (see _wsl_hold) -- the earlier 000s were WSL
        # idle-shutdown dropping the forward, NOT a flaky forward or memory pressure.
        py = sys.executable
        cmd = (f'"{py}" "{os.path.join(HERE, "step_runner.py")}" --kind {kind} --campaign {self.campaign} '
               f'--role {self.role} --budget {self.per_leg_budget}')
        if self.base:
            cmd += f' --base {self.base}'
        if self.auth and kind == "redteam":
            cmd += f' --auth "{self.auth}"'
        if self.dry:
            cmd += ' --dry'
        def _prog():                       # G2: progress clock = findings ledger growth
            try:
                return sum(1 for _ in open(self._store, encoding="utf-8"))
            except Exception:
                return 0
        # G13: a real hunt leg legitimately goes QUIET during long internal DS/board calls -- a tight
        # output-silence timeout false-kills it (and the kill then mislabels as 'unknown'). Silence is
        # generous; the true stall guards for a stage are progress-delta (findings growth) + hard_timeout.
        r = SUP.supervise(cmd, hard_timeout=max(300, self.per_leg_budget * 90),
                          silence_timeout=max(600, self.per_leg_budget * 45),
                          progress_fn=_prog, progress_timeout=max(600, self.per_leg_budget * 120),
                          abort_check=self._target_down, retries=0)   # G16: kill if the mirror drops mid-stage
        # test/chaos hook: force an incident signature into this stage's output, ONE-SHOT (popped) so an
        # injected mishap can be RECOVERED from on the re-run -- exercising detect->intervene->verify.
        forced = self.inject.pop(kind, None)
        text = (forced or r.output)
        outcome = {"status": "error", "confirmed": 0, "output": text, "reason": r.termination_reason}
        for ln in (r.stdout_tail or "").splitlines():
            if ln.startswith("__OUTCOME__ "):
                try:
                    outcome.update(json.loads(ln[len("__OUTCOME__ "):]))
                except Exception:
                    pass
        if r.termination_reason != "exit":
            outcome["status"] = "error"
            outcome["output"] = f"[supervised {r.termination_reason}] " + (text or "")
        if forced:
            outcome["status"] = "error"; outcome["output"] = forced
        return outcome

    def _handle_incident(self, kind, outcome):
        """Classify -> Tier-A plan -> apply (never-repeat + allowlist/guard) -> verify by re-running the
        stage once. Unresolved -> direct Support line -> still stuck -> return False (caller decides)."""
        # G12: always log WHAT we're handling (the classifier input) so a failure is never invisible.
        self._say(f"incident on {kind}: reason={outcome.get('reason')} "
                  f"output[:160]={(outcome.get('output') or '')[:160]!r}")
        # G14: a SUPERVISED kill (timeout/silence/no-progress) is a wedged/slow stage, not an app error --
        # classify it explicitly (don't feed "[supervised ...]" to the classifier as 'unknown' and burn
        # the Support line). Retry once with more headroom; then fence/skip.
        reason = outcome.get("reason")
        if reason in ("output_silence", "hard_timeout", "no_progress"):
            if ST.never_repeated(self.campaign, kind, reason, "retry"):
                self._say(f"incident on {kind}: supervised {reason} -> retry once with more headroom")
                re_out = self._run_stage(kind)
                ok = re_out.get("status") == "ok"
                ST.record_intervention(self.campaign, {"step_id": kind, "signature": reason,
                    "action": "retry", "outcome": ("cleared" if ok else "failed"), "attempt": 1})
                if ok:
                    return re_out
            self._say(f"  supervised {reason} on {kind} persists -> fence/skip")
            ST.record_intervention(self.campaign, {"step_id": kind, "signature": reason,
                "action": "skip", "outcome": "skipped"})
            return "skipped" if kind != "operator" else "unresolved"
        sig, plan = INT.handle(outcome.get("output"), ctx={"base": self.base, "kali": False,
                                                           "compose_dir": self._compose_dir_kali()})
        if not sig:
            # unknown mishap -> escalate straight to the Support line
            return self._support_rescue(kind, {"step_id": kind, "signature": "unknown",
                                               "output": outcome.get("output")})
        self._say(f"incident on {kind}: {sig['name']} -> Tier-A {plan['verb']} ({plan['action']})")
        if not ST.never_repeated(self.campaign, kind, sig["name"], plan["action"]):
            self._say(f"  already tried {plan['action']} for {sig['name']} and it failed -> escalate")
            return self._support_rescue(kind, {"step_id": kind, "signature": sig["name"],
                                               "output": outcome.get("output")})
        applied = "ran"
        if plan["action"] == "run" and plan.get("cmd"):
            if _allowlisted(plan["cmd"]) and self.budget.can("repairs"):
                self.budget.consume("repairs")
                rc, out = DSO._sh(plan["cmd"], kali=plan.get("kali", False), timeout=120)
                applied = f"run rc={rc}"
            else:
                applied = "blocked (allowlist/budget)"
        elif plan["action"] == "skip":
            ST.record_intervention(self.campaign, {"step_id": kind, "signature": sig["name"],
                "action": "skip", "outcome": "skipped", "note": plan.get("note")})
            self._say(f"  fenced+skipped {kind} (non-retriable)")
            return "skipped"
        # verify: re-run the stage once (retriable verbs)
        if plan.get("retriable"):
            re_kali = plan["action"] in ("retry_kali",)
            self._say(f"  verifying: re-run {kind}" + (" (re-platform kali)" if re_kali else ""))
            re_out = self._run_stage(kind)  # (v1 re-platform is a plain re-run; kali executor is a later tier)
            ok = re_out.get("status") == "ok"
            ST.record_intervention(self.campaign, {"step_id": kind, "signature": sig["name"],
                "action": plan["action"], "cmd": plan.get("cmd"), "applied": applied,
                "outcome": ("cleared" if ok else "failed"), "attempt": 1})
            if ok:
                return re_out
        ST.record_intervention(self.campaign, {"step_id": kind, "signature": sig["name"],
            "action": plan["action"], "cmd": plan.get("cmd"), "applied": applied, "outcome": "failed"})
        return self._support_rescue(kind, {"step_id": kind, "signature": sig["name"],
                                           "output": outcome.get("output")})

    def _support_rescue(self, kind, incident):
        who, cmd = self._rescue_cli(incident)
        self._say(f"  Support line ({who}): {'proposed '+cmd[:60] if cmd else 'no usable proposal'}")
        if cmd and _allowlisted(cmd) and self.budget.can("repairs"):
            self.budget.consume("repairs")
            rc, out = DSO._sh(cmd, timeout=120)
            re_out = self._run_stage(kind)
            ok = re_out.get("status") == "ok"
            ST.record_intervention(self.campaign, {"step_id": kind, "signature": incident.get("signature"),
                "action": "rescue", "cmd": cmd, "by": who, "outcome": ("cleared" if ok else "failed")})
            if ok:
                self._say(f"  Support ({who}) unstuck {kind}")
                return re_out
        elif cmd:
            ST.record_intervention(self.campaign, {"step_id": kind, "signature": incident.get("signature"),
                "action": "rescue", "cmd": cmd, "by": who, "outcome": "blocked_by_allowlist"})
        else:
            # G10: always log the Support-line outcome, even when it yields nothing to act on
            ST.record_intervention(self.campaign, {"step_id": kind, "signature": incident.get("signature"),
                "action": "rescue", "cmd": None, "by": who,
                "outcome": ("line_down" if who == "none" else "no_proposal")})
        # Support couldn't help -> harness gate / human, else skip
        return "unresolved"

    # ---------- decide + run ----------
    def decide(self):
        b = self.budget
        if self.state.get("mode") == "TERMINAL":
            return {"terminal": self.state["terminal_reason"]}
        if b.exhausted():
            return {"terminal": "BUDGET_EXHAUSTED"}
        phase = self.state["phase"]
        if phase == "REPORT":
            return {"terminal": "COMPLETE"}
        if phase == "DONE":
            return {"terminal": "COMPLETE"}
        if phase == "BRINGUP":
            return {"kind": "_preflight"}
        if phase in PHASE_KIND:
            return {"kind": PHASE_KIND[phase], "phase": phase}
        return {"terminal": "COMPLETE"}

    def _advance(self):
        i = PHASES.index(self.state["phase"])
        self.state["phase"] = PHASES[min(i + 1, len(PHASES) - 1)]

    def run(self):
        self._say(f"AUTO start campaign={self.campaign} base={self.base} role={self.role} dry={self.dry}")
        ticks = 0
        while ticks < self.tick_max:
            ticks += 1
            d = self.decide()
            if d.get("terminal"):
                self.state["mode"] = "TERMINAL"; self.state["terminal_reason"] = d["terminal"]
                break
            kind = d["kind"]
            if kind == "_preflight":
                pf = DSO.preflight(self.base) if self.base else {}
                if pf.get("target") and not pf["target"]["ok"]:
                    # reachability fail-closed (board): do NOT run a hunt into a dead target
                    dec = self._gate({"kind": "proceed-unreachable", "over_budget": False,
                                      "out_of_scope": False, "risk": "target unreachable after repair"}, "target unreachable")
                    if not dec:
                        self.state["mode"] = "TERMINAL"; self.state["terminal_reason"] = "STUCK"; break
                # G3: a down tool-server is not fatal, but it disables tool vectors -- record the COVERAGE
                # OMISSION explicitly (and flag it to the engine) so a clean result never overstates coverage.
                if pf.get("kali-tool-server") and not pf["kali-tool-server"]["ok"]:
                    omission = "kali tool-server (8901) down -> recon/nuclei/msf tool-vectors DISABLED"
                    if omission not in self.state["coverage_omissions"]:
                        self.state["coverage_omissions"].append(omission)
                    os.environ["AEGIS_TOOL_VECTORS"] = "0"
                    self._say(f"  COVERAGE OMISSION: {omission}")
                # G4: observe per-executor reachability (host WSL route vs Kali) for the record. The
                # working route is the Windows-host WSL localhost:8443 route; a host 000 while Kali is up
                # means WSL idle-shut and dropped the forward -> the fix is holding WSL up (_wsl_hold in
                # _start_daemons), NOT re-platforming into Kali.
                if self.base:
                    dec = EXR.select(self.base)
                    self.state["reachability"] = dec["reachability"]
                    self.state["executor"] = dec
                    self._say(f"  reachability: {dec['reachability']} -> executor={dec['executor']} "
                              f"({dec['reason']})")
                    if dec.get("wsl_idle_suspected"):
                        self._say("  NOTE: host route down but Kali up -> WSL idle-shutdown suspected; "
                                  "the WSL hold should recover it")
                # G6 (light): if no per-role creds are provisioned, the hunt runs UNAUTHENTICATED -> shallow
                # coverage. Record it honestly (full per-role provisioning is a deployment step).
                if not os.environ.get("AEGIS_ROLE_MAP"):
                    note = ("no AEGIS_ROLE_MAP -> UNAUTHENTICATED sessions (shallow coverage; provision "
                            "per-role creds to reach authenticated surface)")
                    if note not in self.state["coverage_omissions"]:
                        self.state["coverage_omissions"].append(note)
                    self._say(f"  COVERAGE NOTE: {note}")
                self._start_daemons()   # G16: keep the mirror alive + watch its health for the whole run
                self._advance(); ST.save_progress(self.campaign, self.state); continue
            # G11: nothing to remediate when 0 confirmed findings -> skip cleanly (not "MISSING report")
            if kind == "remediation" and ST.count_findings(self._store)["confirmed"] == 0:
                self._say("  no confirmed findings -> nothing to remediate; skipping REMEDIATE")
                self.state["remediation"] = {"skipped": "no confirmed findings"}
                self._advance(); ST.save_progress(self.campaign, self.state); continue
            # a real stage
            if not self.budget.can("legs"):
                self.state["mode"] = "TERMINAL"; self.state["terminal_reason"] = "BUDGET_EXHAUSTED"; break
            self.budget.consume("legs")
            self._say(f"phase {self.state['phase']} -> stage {kind}")
            _t0 = time.time()
            outcome = self._run_stage(kind)
            dur = time.time() - _t0
            # G16: a stage aborted because the mirror dropped mid-run is INFRA-blocked, not a real result --
            # wait for the health monitor to restore the target, then RE-RUN once (never accept the abort).
            if outcome.get("reason") == "aborted_target_down":
                self._say(f"  stage {kind} ABORTED (target down mid-stage) -> awaiting mirror recovery")
                if self._await_health(timeout=180):
                    self._say(f"  mirror recovered -> re-running {kind}")
                    _t0 = time.time(); outcome = self._run_stage(kind); dur = time.time() - _t0
                else:
                    self._say("  mirror did not recover in time -> STUCK")
                    self.state["mode"] = "TERMINAL"; self.state["terminal_reason"] = "STUCK"; break
            if outcome.get("status") != "ok":
                res = self._handle_incident(kind, outcome)
                if res == "unresolved":
                    # Support + Tier-A exhausted: skip optional stage, or STUCK if required
                    if kind in ("redteam", "remediation"):
                        self._say(f"  {kind} unresolved -> skip (optional), continue")
                    else:
                        self._say(f"  stage {kind}: UNRESOLVED status={outcome.get('status')} "
                                  f"reason={outcome.get('reason')} dur={dur:.0f}s -> STUCK")
                        self.state["mode"] = "TERMINAL"; self.state["terminal_reason"] = "STUCK"; break
                elif isinstance(res, dict):
                    outcome = res   # G9: adopt the RECOVERED outcome so the stage log/accounting aren't stale
            # G7: authoritative accounting from the DURABLE store (not step_runner's leg count)
            acc = ST.count_findings(self._store)
            self.state["confirmed_n"] = acc["confirmed"]
            self.state["findings"] = acc
            # G1: log the stage OUTCOME inline so a monitor sees HOW each stage did, not just that it ran
            self._say(f"  stage {kind}: status={outcome.get('status')} dur={dur:.0f}s "
                      f"reason={outcome.get('reason')} | store: confirmed={acc['confirmed']} "
                      f"candidate={acc['candidate']} rejected={acc['rejected']} "
                      f"inconclusive={acc.get('inconclusive', 0)} errored={acc.get('errored', 0)} "
                      f"total={acc['total']}")
            # G8: remediation is otherwise opaque -- surface its report path + whether it was produced
            if kind == "remediation":
                rep = outcome.get("report")
                exists = bool(rep and os.path.exists(rep))
                self._say(f"  remediation report: {'written' if exists else 'MISSING'} "
                          f"({rep or '-'}, {os.path.getsize(rep) if exists else 0}B)")
                self.state["remediation"] = {"report": rep, "written": exists}
            self._advance()
            ST.save_progress(self.campaign, self.state)
        self._stop_all_daemons()                      # G16: stop the keepalive + health daemons
        term = self.state.get("terminal_reason") or "STUCK"
        acc = ST.count_findings(self._store)          # authoritative final accounting from the store
        with self._health_lock:
            health = {"up": self._health["up"], "drops": self._health["epoch"], "restarts": self._health["restarts"]}
        report = {"campaign": self.campaign, "terminal": term,
                  "findings": acc,                    # G7: full breakdown, not a bare confirmed count
                  "confirmed_n": acc["confirmed"],
                  "phase": self.state["phase"], "budget": self.budget.snapshot(),
                  "interventions": len(ST.read_interventions(self.campaign)),
                  "coverage_omissions": self.state.get("coverage_omissions", []),
                  "target_health": health,            # G16: how many times the mirror dropped + was restarted
                  "remediation": self.state.get("remediation")}
        self._say(f"AUTO {term}: findings total={acc['total']} confirmed={acc['confirmed']} "
                  f"candidate={acc['candidate']} rejected={acc['rejected']} "
                  f"inconclusive={acc.get('inconclusive', 0)} errored={acc.get('errored', 0)} | "
                  f"interventions={report['interventions']} omissions={len(report['coverage_omissions'])}")
        ST.save_progress(self.campaign, self.state)
        return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="AUTO MODE campaign controller")
    ap.add_argument("--base", default=os.environ.get("AEGIS_TARGET"))
    ap.add_argument("--role", default="dispatcher")
    ap.add_argument("--campaign", default=None)
    ap.add_argument("--budget", type=int, default=8, help="per-leg budget")
    ap.add_argument("--auth", default=None)
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--gate-timeout", type=float, default=0.0)
    a = ap.parse_args()
    loop = AutoLoop(base=a.base, role=a.role, campaign=a.campaign, per_leg_budget=a.budget,
                    auth=a.auth, dry=a.dry, gate_timeout=a.gate_timeout)
    print(json.dumps(loop.run(), indent=2))
