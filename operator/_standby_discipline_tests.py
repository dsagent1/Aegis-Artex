"""
Deterministic proof for the ARTEX-style standby-discipline port.

Drives the REAL _agent_loop with a scripted fake brain + stubbed tools, in --chat mode.
The SAME brain is run with the flag OFF and ON; only AEGIS_STANDBY_DISCIPLINE flips.

PHASE 1 -- finish gates (a "clever" model that finishes on a self-reported kill):
  OFF: the premature finish() is accepted -- zero execution, oracle never runs.
  ON : finish() is refused until the probe runs and the finding is recorded, then the
       out-of-band ORACLE runs before finish() is honoured.

PHASE 2 -- the Hard Floor (a model that hands back to the operator in prose, no tool call):
  OFF: the no-action hand-back is accepted -- clever talk, zero execution.
  ON : the hand-back is refused and ONE concrete probe is forced -- UNLESS the hand-back
       is a genuine scope/authorization question, which stays exempt.

DECOUPLING -- discipline drives EXECUTION but does NOT force the proven stack:
  discipline ON, forced-stack OFF: a novel raw-run_command probe + a neutral finish is
       accepted; the proven stack (content_discovery) is NEVER forced -> novel-code is free.
  forced-stack ON (/forcedstack): the SAME novel brain IS pushed onto the stack
       (content_discovery forced before finish) -> the stack lever still works, independently.

No network, no LLM, no Kali: _create, the tools, and the oracle are stubbed.
Run:  python operator/_standby_discipline_tests.py
"""
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import aegis_operator as ao  # noqa: E402

CONFIRM_SUMMARY = ("Confirmed SQL injection on /rest/user/login -- admin auth bypass, "
                   "oracle-confirmed admin access via ' OR 1=1--")
NEUTRAL_SUMMARY = "Probed the login surface with a custom request; no conclusive result, reporting back."
GATE_MARKERS = ("use_the_stack_first", "verify_before_finish", "execute_before_finish",
                "record_before_finish")
HARDFLOOR_MARK = "STANDBY HARD FLOOR"
STALL_PROSE = ("This login endpoint looks injectable -- you could try ' OR 1=1-- as the email, "
               "which would likely bypass auth. Happy to dig in.")
QUESTION_PROSE = ("Before I proceed: is this target in scope and authorized for testing? "
                  "Please confirm scope and I'll continue.")


def _Msg(content, tool_call_dicts):
    return ao._StreamedMsg(content, tool_call_dicts)


class _Resp:
    def __init__(self, msg):
        self.choices = [types.SimpleNamespace(message=msg)]


def _tc(name, **args):
    import uuid
    return {"id": "call_" + uuid.uuid4().hex[:8], "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


class FakeGate:
    mode = "auto"
    dry_run = False
    def approve(self, name, args, preview=None, readonly=False):
        return True


def _has_call(msgs, name):
    return any(((tcd.get("function") or {}).get("name") == name)
               for m in msgs for tcd in (m.get("tool_calls") or []) if isinstance(tcd, dict))


class Harness:
    """Installs stubs on the module and provides a scripted brain selected by `mode`."""
    def __init__(self, mode):
        self.mode = mode          # "finish" | "stall" | "question" | "novel"
        self.run_cmd_calls = 0
        self.record_calls = 0
        self.oracle_calls = 0
        self.cd_calls = 0         # content_discovery (a proven-stack tool)
        self.brain_calls = 0
        self._saved = {}

    def brain(self, client, **kw):
        self.brain_calls += 1
        msgs = kw.get("messages", [])
        last = msgs[-1] if msgs else {}
        last_content = str(last.get("content", "")) if last.get("role") in ("tool", "user") else ""
        acted = _has_call(msgs, "run_command") or _has_call(msgs, "record_finding")

        if self.mode == "finish":
            if any(k in last_content for k in GATE_MARKERS):
                return _Resp(_Msg("Running the probe and recording first.", [
                    _tc("run_command", command="curl -s -X POST .../rest/user/login -d \"email=' OR 1=1--\""),
                    _tc("record_finding", title="SQLi auth bypass", severity="critical",
                        endpoint="/rest/user/login", status="confirmed", evidence="admin JWT returned"),
                ]))
            if acted:
                return _Resp(_Msg("Done.", [_tc("finish", summary=CONFIRM_SUMMARY)]))
            return _Resp(_Msg("I've reasoned it out.", [_tc("finish", summary=CONFIRM_SUMMARY)]))

        if self.mode == "novel":
            # A novel/freewheeling worker: custom raw run_command probe, no canned stack.
            if "use_the_stack_first" in last_content:   # only reachable when forced-stack pushes it
                return _Resp(_Msg("OK -- mapping with the stack.",
                                  [_tc("content_discovery", base_url="http://localhost:3000")]))
            if _has_call(msgs, "run_command"):
                return _Resp(_Msg("Reporting back.", [_tc("finish", summary=NEUTRAL_SUMMARY)]))
            return _Resp(_Msg("Writing a custom probe.",
                              [_tc("run_command", command="curl -s http://localhost:3000/rest/user/login -d '{}'")]))

        if self.mode == "probe_handback":
            # probed + recorded a candidate, then hands back in PROSE (no finish, no verify_findings)
            if acted:
                return _Resp(_Msg("I probed and recorded a candidate SQLi; here's my read. Handing back.", None))
            return _Resp(_Msg("Probing and recording a candidate.", [
                _tc("run_command", command="curl -s -X POST http://localhost:3000/rest/user/login -d '{}'"),
                _tc("record_finding", title="candidate SQLi on login", severity="high",
                    endpoint="/rest/user/login", status="confirmed", evidence="possible bypass"),
            ]))

        # Phase 2 hand-back brains ("stall" / "question")
        if acted:
            return _Resp(_Msg("Done -- handing back with the result.", None))
        if HARDFLOOR_MARK in last_content:
            return _Resp(_Msg("Right -- firing the probe.", [
                _tc("run_command", command="curl -s -X POST http://localhost:3000/rest/user/login "
                    "-d '{\"email\":\"'\"'\"' OR 1=1--\",\"password\":\"x\"}'")]))
        return _Resp(_Msg(QUESTION_PROSE if self.mode == "question" else STALL_PROSE, None))

    def _stub_run_command(self, **kw):
        self.run_cmd_calls += 1
        return json.dumps({"stdout": "HTTP/1.1 200 OK {\"authentication\":{\"token\":\"eyJ...admin\"}}",
                           "exit_code": 0})

    def _stub_record_finding(self, **kw):
        self.record_calls += 1
        return json.dumps({"recorded": "finding", "status": "recorded", "title": kw.get("title", "")})

    def _stub_content_discovery(self, **kw):
        self.cd_calls += 1
        return json.dumps({"endpoints": ["/rest/user/login"], "note": "stub"})

    def _stub_oracle(self, run_only=True):
        self.oracle_calls += 1
        return {"candidates": 1, "verified": 1, "rejected": 0,
                "results": [{"verdict": "verified", "claim": "admin auth bypass on /rest/user/login"}]}

    def __enter__(self):
        self._saved = {"_create": ao._create, "run": ao.TOOLS["run_command"],
                       "rec": ao.TOOLS["record_finding"], "cd": ao.TOOLS["content_discovery"],
                       "oracle": ao._verify_run_candidates, "_CTX": dict(ao._CTX), "_VF": ao._VF}
        ao._create = self.brain
        ao.TOOLS["run_command"] = (lambda **kw: self._stub_run_command(**kw), False, ao.TOOLS["run_command"][2])
        ao.TOOLS["record_finding"] = (lambda **kw: self._stub_record_finding(**kw), False, ao.TOOLS["record_finding"][2])
        ao.TOOLS["content_discovery"] = (lambda **kw: self._stub_content_discovery(**kw), True, ao.TOOLS["content_discovery"][2])
        ao._verify_run_candidates = self._stub_oracle
        ao._VF = object()
        ao._CTX.clear(); ao._CTX.update(brain="ds", thinking=False, depth=0)
        return self

    def __exit__(self, *a):
        ao._create = self._saved["_create"]
        ao.TOOLS["run_command"] = self._saved["run"]
        ao.TOOLS["record_finding"] = self._saved["rec"]
        ao.TOOLS["content_discovery"] = self._saved["cd"]
        ao._verify_run_candidates = self._saved["oracle"]
        ao._VF = self._saved["_VF"]
        ao._CTX.clear(); ao._CTX.update(self._saved["_CTX"])


def _run(mode, discipline, forced_stack=False):
    os.environ.pop("AEGIS_STANDBY_HARDFLOOR", None)
    os.environ["AEGIS_REQUIRE_STACK"] = "1" if forced_stack else "0"
    if discipline:
        os.environ["AEGIS_STANDBY_DISCIPLINE"] = "1"
    else:
        os.environ.pop("AEGIS_STANDBY_DISCIPLINE", None)
    with Harness(mode) as h:
        messages = [{"role": "system", "content": "sys"},
                    {"role": "user", "content": "find and verify an auth bypass on the mirror"}]
        summ = ao._agent_loop(None, "deepseek-flash", False, messages,
                              ["finish", "record_finding", "run_command", "content_discovery"],
                              8, FakeGate(), depth=0, tag="[TST", chat=True, quiet=True)
    return summ, h


def main():
    print("=" * 72)
    print("STANDBY-DISCIPLINE PORT -- deterministic proof (--chat)")
    print("=" * 72)
    fails = []

    print("\n--- PHASE 1: finish gates (clever self-reported kill) ---")
    s_off, off = _run("finish", False)
    orc_off = "ORACLE VERIFICATION" in (s_off or "")
    print(f"[OFF] run_command={off.run_cmd_calls} record={off.record_calls} oracle={off.oracle_calls>0} "
          f"finish_accepted={s_off is not None}")
    if not (off.run_cmd_calls == 0 and off.record_calls == 0 and off.oracle_calls == 0
            and not orc_off and s_off is not None):
        fails.append("P1 OFF: expected a premature finish with zero execution")
    s_on, on = _run("finish", True)
    orc_on = "ORACLE VERIFICATION" in (s_on or "")
    print(f"[ON ] run_command={on.run_cmd_calls} record={on.record_calls} oracle={on.oracle_calls>0} "
          f"oracle_block_in_summary={orc_on}")
    if not (on.run_cmd_calls >= 1 and on.record_calls >= 1 and on.oracle_calls >= 1 and orc_on):
        fails.append("P1 ON: expected forced probe + recorded finding + oracle at finish")

    print("\n--- PHASE 2: Hard Floor (prose-only hand-back, no tool call) ---")
    s_off2, off2 = _run("stall", False)
    print(f"[OFF] brain_calls={off2.brain_calls} run_command={off2.run_cmd_calls} handed_back={s_off2 is None}")
    if not (off2.run_cmd_calls == 0 and off2.brain_calls == 1 and s_off2 is None):
        fails.append("P2 OFF: expected the no-action hand-back to be accepted (zero execution)")
    s_on2, on2 = _run("stall", True)
    print(f"[ON ] brain_calls={on2.brain_calls} run_command={on2.run_cmd_calls} handed_back={s_on2 is None}")
    if not (on2.run_cmd_calls >= 1 and on2.brain_calls >= 2):
        fails.append("P2 ON: expected the Hard Floor to refuse the hand-back and force a probe")

    print("\n--- PHASE 2: scope/authorization question is EXEMPT (ON) ---")
    s_q, q = _run("question", True)
    print(f"[ON ] brain_calls={q.brain_calls} run_command={q.run_cmd_calls} handed_back={s_q is None}")
    if not (q.run_cmd_calls == 0 and q.brain_calls == 1 and s_q is None):
        fails.append("P2 EXEMPT: a genuine scope/auth question must be allowed to hand back")

    print("\n--- DECOUPLING: discipline drives execution but does NOT force the stack ---")
    # discipline ON, forced-stack OFF: novel raw probe + neutral finish accepted; stack NOT forced.
    s_nv, nv = _run("novel", True, forced_stack=False)
    print(f"[disc ON, forced OFF] run_command={nv.run_cmd_calls} content_discovery={nv.cd_calls} "
          f"finish_accepted={s_nv is not None}  (novel probe, stack NOT forced)")
    if not (nv.run_cmd_calls >= 1 and nv.cd_calls == 0 and s_nv is not None):
        fails.append("DECOUPLE: disciplined novel run must execute + finish WITHOUT being forced onto the stack")
    # forced-stack ON: the SAME novel brain IS pushed onto the proven stack before finish.
    s_fs, fs = _run("novel", True, forced_stack=True)
    print(f"[disc ON, forced ON ] run_command={fs.run_cmd_calls} content_discovery={fs.cd_calls} "
          f"finish_accepted={s_fs is not None}  (/forcedstack still forces the stack)")
    if not (fs.cd_calls >= 1 and s_fs is not None):
        fails.append("DECOUPLE: /forcedstack must still force a proven-stack tool before finish")

    print("\n--- PROSE-HANDBACK ORACLE: unverified candidates get adjudicated on a prose hand-back ---")
    # discipline OFF: probe+record then prose hand-back -> oracle NEVER runs (the gap).
    s_po, po = _run("probe_handback", False)
    print(f"[OFF] run_command={po.run_cmd_calls} record={po.record_calls} oracle={po.oracle_calls} "
          f"handed_back={s_po is None}")
    if not (po.run_cmd_calls >= 1 and po.record_calls >= 1 and po.oracle_calls == 0 and s_po is None):
        fails.append("PROSE-HANDBACK OFF: expected NO oracle on the prose hand-back (the pre-fix gap)")
    # discipline ON: the same prose hand-back auto-runs the oracle on the unverified candidate.
    s_pn, pn = _run("probe_handback", True)
    print(f"[ON ] run_command={pn.run_cmd_calls} record={pn.record_calls} oracle={pn.oracle_calls} "
          f"handed_back={s_pn is None}  (oracle auto-ran on hand-back)")
    if not (pn.run_cmd_calls >= 1 and pn.record_calls >= 1 and pn.oracle_calls >= 1 and s_pn is None):
        fails.append("PROSE-HANDBACK ON: expected the oracle to auto-run on the prose hand-back")

    print("\n" + "-" * 72)
    if fails:
        print("RESULT: FAIL")
        for f in fails:
            print("  - " + f)
        sys.exit(1)
    print("RESULT: PASS")
    print("  P1: flag flips a clever finish() from accepted-with-zero-execution to refused-until-"
          "probe+recorded-finding+oracle.")
    print("  P2: flag flips a prose-only hand-back from accepted to refused-and-one-probe-forced; a")
    print("      genuine scope/auth question stays exempt.")
    print("  DECOUPLE: discipline drives execution without forcing the stack (novel-code free); "
          "/forcedstack remains the separate stack lever.")
    sys.exit(0)


if __name__ == "__main__":
    main()
