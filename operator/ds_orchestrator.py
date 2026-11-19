#!/usr/bin/env python3
"""
ds_orchestrator.py -- AUTONOMOUS DeepSeek-driven orchestrator for the Aegis suite.

Replaces the interactive Claude-Code coordinator with a standalone DS brain so the full 4-stage /
3-level relay runs unattended (e.g. from the portable USB copy) with NO Claude session in the loop.

Design (benchmarked 2026-09-15: DS non-thinking ~2s/decision vs claude -p opus ~13.6s / sonnet ~7.0s):
  * DS `deepseek-v4-pro` NON-THINKING is the fast default brain for the 95% -- framing, go/no-go,
    verification framing (verification itself is ORACLE-gated, not model judgement).
  * DEEP ESCALATION only at the hard moments -- stall course-correction + novel finding-bridging:
        claude -p  (if the `claude` CLI is present)  ELSE  the DEEP BOARD preset (DS+CF consensus)
        ELSE  DS in THINKING mode (last resort).
    The board fallback beats a lone DS-thinking call, which can dump raw chain-of-thought with no clean
    final on hard problems (measured 2026-09-15). Stays fully standalone; the claude seat is an optional
    quality upgrade, never required.

Flow:
  1. DS frames the objective (unless one is given).
  2. run_complete() executes the canonical 4-stage relay (operator -> exploitgym -> red-team ->
     remediation) on the DS brain, oracle-verified, non-destructive -- the same code path complete_test
     uses, so no drift.
  3. Deep-escalation pass over the campaign's CONFIRMED findings: course-correction (is it stalled?) +
     up to 3 novel bridges (chain two findings into a deeper escalation, each with probe + oracle).
  4. If bridges are proposed and --follow-up is on, one targeted red-team leg RESUMES the same campaign
     seeded with those bridges -- so the deep recommendations are EXECUTED and re-verified, not just filed.
  5. DS writes a final synthesis report.

Usage:
    python ds_orchestrator.py --base http://127.0.0.1:PORT --role dispatcher --budget 50
    python ds_orchestrator.py --objective "..." --no-follow-up
    python ds_orchestrator.py --secret-env ../secret.env          # load DS/CF keys for a standalone run
"""
import os, sys, json, time, shutil, tempfile, subprocess, urllib.request, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


# --------------------------------------------------------------------------------------------------
# brains
# --------------------------------------------------------------------------------------------------
def _ds(system, user, thinking=False, max_tokens=900, temperature=0.2, model=None):
    """DS chat completion. thinking=False = the fast ~2s orchestrator default; thinking=True = the
    deeper (slower) fallback used only for escalation when no claude CLI is present."""
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        raise RuntimeError("no DeepSeek key (AEGIS_LLM_API_KEY / DEEPSEEK_API_KEY) -- see --secret-env")
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
    model = model or os.environ.get("AEGIS_MODEL", "deepseek-v4-pro")
    body = {"model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens, "temperature": temperature,
            "thinking": {"type": "enabled" if thinking else "disabled"}}
    req = urllib.request.Request(ep + "/chat/completions", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=(300 if thinking else 120)))
    m = (r.get("choices") or [{}])[0].get("message", {})
    return (m.get("content") or m.get("reasoning_content") or "").strip()


def _claude_bin():
    return shutil.which(os.environ.get("ASKBOARD_CLAUDE_BIN") or "claude")


def deep_consult(system, user, timeout=300):
    """Hard-moment escalation: `claude -p` if the CLI is present (frontier bridging/course-correction),
    else the DEEP BOARD preset (DS+CF consensus with salvage/cap + summary-fallback), else DS THINKING
    mode as a last resort. Returns (who, text). Never raises."""
    exe = _claude_bin()
    if exe:
        try:
            with tempfile.TemporaryDirectory(prefix="ds-orch-claude-") as cwd:
                p = subprocess.run([exe, "-p", "--max-turns", "1", "--allowed-tools", ""],
                                   input=f"{system}\n\n{user}", capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=timeout, cwd=cwd)
            if p.returncode == 0 and (p.stdout or "").strip():
                return ("claude", p.stdout.strip())
            print(f"[ds-orch] claude -p exit={p.returncode}/empty -> deep-board fallback", file=sys.stderr)
        except Exception as e:
            print(f"[ds-orch] claude -p failed ({str(e)[:80]}) -> deep-board fallback", file=sys.stderr)
    # Fallback: the DEEP BOARD preset -- a DS+CF consensus panel with the salvage/cap + summary-fallback
    # logic. Sturdier than a single DS-thinking call, which can dump raw chain-of-thought with no clean
    # final on hard problems (measured 2026-09-15). DS-thinking is the absolute last resort.
    try:
        import board_ask as _BA
        res = _BA.consult(user, members=["deep"], sysp=system, summarise=True, stage="redteam")
        summ = res.get("summary")
        if summ and "[summary failed" not in summ and not summ.lstrip().startswith("[raw reasoning"):
            return ("deep-board", summ)
        print("[ds-orch] deep-board gave no usable merge -> DS-thinking last resort", file=sys.stderr)
    except Exception as e:
        print(f"[ds-orch] deep-board fallback failed ({str(e)[:80]}) -> DS-thinking last resort", file=sys.stderr)
    return ("ds-thinking", _ds(system, user, thinking=True, max_tokens=1800))


# ==================================================================================================
# ORCHESTRATOR-LEVEL DIAGNOSTIC TOOL-LOOP  (Addition 1 + 2)
# A bounded run_command + retry loop so the orchestrator PROBES and REPAIRS the environment itself
# (target up? Kali tool-server up? restart the mirror) rather than running a hunt into a broken env.
# On a check that stays broken after its configured repair, the failure is ESCALATED to the deep seat
# (claude -p / deep board) for a diagnosis + a SINGLE non-destructive repair command, run behind a
# destructive-command guard. Everything is capped by a global retry budget. Doctrine: non-destructive.
# ==================================================================================================
import re as _re

_DESTRUCTIVE = _re.compile(r"(rm\s+-rf|\bmkfs\b|dd\s+if=|>\s*/dev/sd|shutdown\b|reboot\b|drop\s+table|"
                           r"truncate\b|del\s+/[sqf]|format\s+[a-z]:|:\s*\(\)\s*\{)", _re.I)


def _guard(cmd):
    """True only if the command is safe to auto-run (non-destructive doctrine)."""
    return bool(cmd) and not _DESTRUCTIVE.search(cmd)


def _sh(cmd, timeout=60, kali=False):
    """Run one shell command locally, or in the Kali distro (kali=True), SUPERVISED (hang/silence-proof
    via supervisor.py) so a wedged probe/repair can never stall the orchestrator. Returns (rc, output);
    a supervised kill (timeout/silence) returns rc=-1 with the reason on the output. Falls back to a plain
    bounded subprocess if the supervisor module is unavailable."""
    try:
        import supervisor as _sup
        return _sup.run(cmd, kali=kali, hard_timeout=max(15, timeout),
                        silence_timeout=max(10, min(timeout, 45)), retries=0)
    except ImportError:
        try:
            if kali:
                dist = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
                full = ["wsl", "-d", dist, "-u", "root", "--", "bash", "-lc", cmd]
            elif os.name == "nt":
                full = f'cmd /s /c "{cmd}"'
            else:
                full = ["bash", "-lc", cmd]
            p = subprocess.run(full, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=timeout)
            return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
        except Exception as e:
            return 1, f"[exec-error] {str(e)[:120]}"
    except Exception as e:
        return 1, f"[exec-error] {str(e)[:120]}"


def _extract_cmd(text):
    """Pull a single shell command from the deep seat's reply (a ```fence``` or the first line); '' if NONE."""
    if not text or text.strip().lower().startswith("none"):
        return ""
    m = _re.search(r"```(?:sh|bash)?\s*(.+?)```", text, _re.S)
    body = (m.group(1) if m else text).strip()
    line = body.splitlines()[0].strip() if body else ""
    return "" if line.lower().startswith("none") else line


def diagnose_and_repair(checks, retry_budget=3):
    """Bounded probe/repair loop. check = {name, probe, kali?, bad?, repair?, repair_kali?, timeout?}.
    `bad` = a substring whose presence in the probe output means FAIL (e.g. '000' for a curl code). On
    a check still failing after its configured repair, the deep seat is asked for ONE non-destructive
    repair command, run behind the guard. Returns {name: {ok, detail, repairs}}."""
    out = {}; budget = retry_budget
    for c in checks:
        def _probe():
            rc, o = _sh(c["probe"], kali=c.get("kali", False), timeout=c.get("timeout", 20))
            return (rc == 0 and (c["bad"] not in o if c.get("bad") else True)), o
        ok, o = _probe(); used = []
        rk = c.get("repair_kali", c.get("kali", False))
        if not ok and c.get("repair") and _guard(c["repair"]) and budget > 0:
            _sh(c["repair"], kali=rk, timeout=c.get("timeout", 120)); budget -= 1
            used.append("configured-repair"); ok, o = _probe()
        if not ok and budget > 0:                                   # Addition 2: escalate to deep seat
            who, fix = deep_consult(
                "You are an SRE fixing a contained security-test environment. Reply with ONE "
                "non-destructive shell command to try next, or exactly NONE. No prose.",
                f"Check '{c['name']}' still failing.\nProbe: {c['probe']}\nOutput:\n{o[:800]}")
            cmd = _extract_cmd(fix)
            if _guard(cmd):
                print(f"[ds-orch] deep-seat({who}) repair for {c['name']}: {cmd}", file=sys.stderr)
                _sh(cmd, kali=rk, timeout=120); budget -= 1
                used.append(f"deep:{cmd[:50]}"); ok, o = _probe()
            elif cmd:
                print(f"[ds-orch] deep-seat repair for {c['name']} BLOCKED by guard: {cmd}", file=sys.stderr)
        out[c["name"]] = {"ok": ok, "detail": o[:180], "repairs": used}
        print(f"[ds-orch] preflight {c['name']}: {'OK' if ok else 'FAIL'}"
              + (f" (repaired via {','.join(used)})" if ok and used else ""), file=sys.stderr)
    return out


def preflight(base, retry_budget=3):
    """Probe (and try to repair) the environment before a hunt: target reachable + Kali tool-server up."""
    curl = "curl.exe" if os.name == "nt" else "curl"
    devnull = "NUL" if os.name == "nt" else "/dev/null"
    checks = [
        {"name": "target", "bad": "000",
         "probe": f'{curl} -sk -o {devnull} -w "%{{http_code}}" --max-time 8 {base}/',
         # if the target is down, restart the mirror compose stack IN KALI (non-destructive: up -d)
         "repair": 'cd "$(dirname "$(find /root /home -maxdepth 4 -iname docker-compose*.yml 2>/dev/null '
                   '| grep -i mirror | head -1)")" && docker compose up -d',
         "repair_kali": True, "timeout": 120},
        {"name": "kali-tool-server", "bad": "000",
         "probe": f'{curl} -s -o {devnull} -w "%{{http_code}}" --max-time 5 http://127.0.0.1:8901/',
         "repair": None},   # advisory: the web vector works without it; tool vectors degrade gracefully
    ]
    out = diagnose_and_repair(checks, retry_budget)
    # Reachability diagnosis: probe host (WSL route) + Kali (sensor) so a host 000 is correctly attributed.
    # host-down + Kali-up == WSL idle-shutdown dropped the forward -> the fix is holding WSL up, not
    # re-platforming. Recorded to executor_state.json for the orchestrator / deep_consult to read.
    try:
        import executor_registry as EXR
        dec = EXR.select(base)
        out["_executor"] = dec
        if dec.get("wsl_idle_suspected"):
            print(f"[ds-orch] REACHABILITY: {dec['reason']}", file=sys.stderr)
    except Exception as e:
        print(f"[ds-orch] reachability diagnosis skipped ({e})", file=sys.stderr)
    return out


def failure_diagnosis(res, confirmed_n, pf):
    """Addition 2 at the run level: if legs errored or the run made no progress into a reachable target,
    route the failure context to the deep seat for a concrete diagnosis + the single next fix."""
    legs = res if isinstance(res, list) else (res.get("results") if isinstance(res, dict) else []) or []
    errored = [l.get("level") for l in legs if isinstance(l, dict) and l.get("error")]
    # Board fix: zero findings on a REACHABLE target is a valid result (checks ran, nothing found) --
    # do NOT treat it as underperformance. Only an actual leg error is a failure worth diagnosing.
    if not errored:
        return None
    who, diag = deep_consult(
        "You diagnose why an autonomous security run underperformed. Be concrete: distinguish environment "
        "vs target vs coverage, and name the ONE most important next fix. Terse.",
        f"Preflight: {json.dumps({k: v['ok'] for k, v in pf.items() if isinstance(v, dict) and 'ok' in v})}\nLegs errored: {errored}\n"
        f"Confirmed findings: {confirmed_n}\nWhat failed, and the single most important fix?")
    return {"by": who, "errored_legs": errored, "diagnosis": diag}


# --------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------
def _load_secret_env(path):
    if not path or not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _read_confirmed(store, limit=40):
    """Read oracle-CONFIRMED findings from a campaign's append-only ledger (best-effort)."""
    out = []
    try:
        for ln in open(store, encoding="utf-8"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
            except Exception:
                continue
            if str(d.get("status", "")).lower() in ("confirmed", "verified") or d.get("confirmed"):
                out.append({"title": d.get("title") or d.get("name") or d.get("class") or "?",
                            "surface": d.get("surface") or d.get("path") or d.get("endpoint") or "?",
                            "role": d.get("role") or d.get("trust") or "?"})
    except Exception:
        pass
    return out[-limit:]


def _fmt(findings):
    return "\n".join(f"- [{f['role']}] {f['title']} @ {f['surface']}" for f in findings) or "(none)"


SYS_ORCH = ("You are the autonomous ORCHESTRATOR of a contained, authorized, single-target security-research "
            "suite. Doctrine: non-destructive (plant/prove, NEVER erase), oracle-verified findings only, "
            "owned targets only, red-team stops at beacon. Be decisive and terse; no preamble.")


def frame_objective(base, role):
    return _ds(SYS_ORCH, f"Target: {base}. Operating role: {role}. In one tight paragraph, state the "
               "objective and the top priorities for a 4-stage relay (discover -> escalate -> red-team -> "
               "remediate). Concrete classes only (authz grid, money-integrity idempotency/TOCTOU, "
               "supply-chain CVEs, etc.).", max_tokens=400)


def escalation_pass(store):
    """Course-correction + novel bridging over the confirmed findings, via the deep seat."""
    findings = _read_confirmed(store)
    if not findings:
        return {"by": None, "recommendation": "(no confirmed findings to bridge yet)", "have": 0}
    user = ("Confirmed findings so far:\n" + _fmt(findings) + "\n\n"
            "As the deep escalation reviewer: (1) Is the hunt STALLED (repeating classes, no new depth)? "
            "If so, name the pivot. (2) Propose up to 3 NOVEL BRIDGES that chain two of these findings into "
            "a deeper escalation -- each as: PROBE: <one line>  ORACLE: <what confirms it>. "
            "If nothing genuinely novel, reply exactly NONE.")
    who, out = deep_consult("You do course-correction and NOVEL finding-bridging for a red-team relay. "
                            "Non-destructive, oracle-gated. Terse.", user)
    return {"by": who, "recommendation": out, "have": len(findings)}


# --------------------------------------------------------------------------------------------------
# orchestrate
# --------------------------------------------------------------------------------------------------
def orchestrate(*, base=None, role="dispatcher", budget=50, objective=None, auth_path=None,
                campaign=None, follow_up=True, report_path=None):
    import complete_test as CT  # canonical relay engine (no drift)

    base = base or os.environ.get("AEGIS_TARGET")
    campaign = campaign or f"ds-orch-{int(time.time())}"
    print(f"[ds-orch] campaign={campaign} target={base} role={role} budget/leg={budget}", file=sys.stderr)

    # Addition 1: probe (and try to repair) the environment BEFORE running a hunt into it.
    pf = preflight(base) if base else {}
    if pf.get("target") and not pf["target"]["ok"]:
        print("[ds-orch] WARNING: target still unreachable after preflight repair -- proceeding, but the "
              "run may make no progress (see failure diagnosis at the end)", file=sys.stderr)

    if not objective:
        try:
            objective = frame_objective(base, role)
            print(f"[ds-orch] DS-framed objective:\n{objective}\n", file=sys.stderr)
        except Exception as e:
            print(f"[ds-orch] objective framing failed ({e}); using engine default", file=sys.stderr)

    # 1-4: canonical 4-stage relay on the DS brain (no --claude seat), oracle-verified.
    res = CT.run_complete(role=role, budget=budget, campaign=campaign, base=base,
                          auth_path=auth_path, objective=objective, emit_fixes=True)
    store = os.path.join(CT.HERE, "campaigns", campaign, "findings.jsonl")

    # deep escalation: course-correction + novel bridging
    esc = escalation_pass(store)
    print(f"[ds-orch] escalation via {esc['by']} over {esc.get('have')} confirmed findings:\n"
          f"{esc['recommendation']}\n", file=sys.stderr)

    # execute the bridges: one targeted red-team leg RESUMING the campaign, seeded with the recommendation
    follow = None
    if follow_up and esc.get("recommendation") and "NONE" not in esc["recommendation"].upper()[:40]:
        ok, why = CT._scope_ok(auth_path, base)
        if ok:
            try:
                roe = json.load(open(auth_path, encoding="utf-8")) if auth_path else None
                print("[ds-orch] executing bridges: follow-up red-team leg (resume)", file=sys.stderr)
                follow = CT._leg("redteam", objective="EXECUTE the orchestrator's bridges:\n" + esc["recommendation"],
                                 role=role, budget=max(15, budget // 2), campaign=campaign, store=store,
                                 base=base, extra_seeds=[esc["recommendation"]], roe=roe)
            except Exception as e:
                print(f"[ds-orch] follow-up leg error (non-fatal): {e}", file=sys.stderr)
        else:
            print(f"[ds-orch] follow-up skipped -- not in scope ({why})", file=sys.stderr)

    # Addition 2 (run level): if legs errored or no progress into a reachable target, diagnose why.
    fdiag = failure_diagnosis(res, len(_read_confirmed(store)), pf)
    if fdiag:
        print(f"[ds-orch] failure diagnosis via {fdiag['by']}: {fdiag['diagnosis'][:200]}", file=sys.stderr)

    # final synthesis (DS)
    confirmed = _read_confirmed(store)
    try:
        synth = _ds(SYS_ORCH, "Write the final run synthesis: what was confirmed, the depth reached, and the "
                    "single most important next action. Terse markdown.\n\nCONFIRMED:\n" + _fmt(confirmed) +
                    "\n\nESCALATION:\n" + (esc.get("recommendation") or ""), max_tokens=1200)
    except Exception as e:
        synth = f"[synthesis failed: {e}]"

    rp = report_path or os.path.join(CT.HERE, "campaigns", campaign, "ds_orchestrator_report.md")
    pf_line = " · ".join(f"{k}={'ok' if v['ok'] else 'FAIL'}" for k, v in pf.items()
                         if isinstance(v, dict) and 'ok' in v) or "(skipped)"
    fdiag_md = (f"\n## Failure diagnosis (deep seat: {fdiag['by']})\n"
                f"errored legs: {fdiag['errored_legs']}\n\n{fdiag['diagnosis']}\n") if fdiag else ""
    try:
        with open(rp, "w", encoding="utf-8") as fh:
            fh.write(f"# DS Orchestrator run -- {campaign}\n\n"
                     f"- target: `{base}`  role: `{role}`  budget/leg: {budget}\n"
                     f"- preflight: {pf_line}\n"
                     f"- deep seat: **{esc.get('by')}**  (claude -p if present, else deep board, else DS-thinking)\n"
                     f"- confirmed findings: {len(confirmed)}\n\n"
                     f"## Objective\n{objective}\n\n## Final synthesis\n{synth}\n\n"
                     f"## Escalation (course-correction + novel bridges)\n{esc.get('recommendation')}\n"
                     f"{fdiag_md}")
        print(f"[ds-orch] report -> {rp}", file=sys.stderr)
    except Exception as e:
        print(f"[ds-orch] report write failed: {e}", file=sys.stderr)

    return {"campaign": campaign, "confirmed": len(confirmed), "escalation_by": esc.get("by"),
            "preflight": {k: v["ok"] for k, v in pf.items() if isinstance(v, dict) and "ok" in v}, "failure_diagnosis": bool(fdiag),
            "report": rp, "relay": res, "follow_up": follow}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Autonomous DeepSeek orchestrator for the Aegis 4-stage relay")
    ap.add_argument("--base", default=None, help="target base URL (default: env AEGIS_TARGET)")
    ap.add_argument("--role", default="dispatcher")
    ap.add_argument("--budget", type=int, default=50, help="per-leg budget")
    ap.add_argument("--objective", default=None, help="objective (default: DS frames one)")
    ap.add_argument("--auth", dest="auth_path", default=None, help="red-team RoE authorization file")
    ap.add_argument("--campaign", default=None)
    ap.add_argument("--no-follow-up", dest="follow_up", action="store_false",
                    help="do NOT auto-execute the deep bridges as a follow-up leg (advisory only)")
    ap.add_argument("--report", dest="report_path", default=None)
    ap.add_argument("--secret-env", default=None, help="KEY=VALUE file with DS/CF keys for standalone runs")
    ap.add_argument("--auto", action="store_true",
                    help="AUTO MODE: run the self-directed AutoLoop (supervised stages, mid-run intervene, "
                         "Support line, harness gate, terminal statuses) instead of the linear relay")
    ap.add_argument("--gate-timeout", type=float, default=0.0,
                    help="seconds to wait for a human harness-gate decision (0 = unattended -> fail-safe stick)")
    ap.add_argument("--dry", action="store_true", help="AUTO: run stages via the step-adapter in dry mode")
    a = ap.parse_args(argv)
    _load_secret_env(a.secret_env)
    if a.auto:
        import autoloop as _AL
        loop = _AL.AutoLoop(base=a.base, role=a.role, campaign=a.campaign, per_leg_budget=a.budget,
                            auth=a.auth_path, dry=a.dry, gate_timeout=a.gate_timeout)
        print(json.dumps(loop.run(), indent=2))
        return 0
    r = orchestrate(base=a.base, role=a.role, budget=a.budget, objective=a.objective,
                    auth_path=a.auth_path, campaign=a.campaign, follow_up=a.follow_up,
                    report_path=a.report_path)
    print(json.dumps({k: v for k, v in r.items() if k not in ("relay", "follow_up")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
