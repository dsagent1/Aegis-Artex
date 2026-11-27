"""ask_operator.py -- human-in-the-loop UNBLOCK primitive (ARTEX-port #4).

When a route hits something only a human can resolve -- a captcha, an email/SMS OTP, a 2FA answer, a
decision, OR an ENVIRONMENTAL block this runtime cannot fix (a filtered network path, a missing binary/key,
a proxy/TLS/auth wall, an IP ban) -- the hunt should PAUSE and ask, not burn its whole budget flailing or
die. This converts "route dead, budget wasted" into "operator answers, route continues".

Pattern (ARTEX ask_operator.go): ask precisely; for an environmental block, do NOT retry/work around it --
hand the operator ONE copy-pastable command to run in their own terminal, plus what to paste back, then
WAIT. Headless-safe: the request is written to a file + printed; the reply is read from a reply file (or
AEGIS_OPERATOR_REPLY env), so a human or the co-pilot can answer. A timeout returns None (don't hang
forever); fully-autonomous runs set AEGIS_ASK_OPERATOR=0 to skip (returns None immediately).

  ans = ask_operator.ask("Enter the wp-admin 2FA code", kind="otp")
  ans = ask_operator.ask("Origin bans this IP; run the whitelist, paste 'ok'", kind="env",
                         command="fail2ban-client set wordpress addignoreip <tester-ip>")
"""
import os, sys, json, time, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
_REQ = os.environ.get("AEGIS_OPERATOR_REQ") or os.path.join(HERE, "ask_operator_pending.jsonl")
_REPLY = os.environ.get("AEGIS_OPERATOR_REPLY_FILE") or os.path.join(HERE, "ask_operator_reply.jsonl")


def _enabled():
    return str(os.environ.get("AEGIS_ASK_OPERATOR", "1")).lower() not in ("0", "false", "no", "off")


def _poll_reply(req_id, timeout, interval=3.0):
    # 1) env fast-path (operator pre-seeded an answer)
    env = os.environ.get("AEGIS_OPERATOR_REPLY")
    if env:
        return env
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if os.path.exists(_REPLY):
                for line in open(_REPLY, encoding="utf-8", errors="ignore"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    if o.get("id") == req_id and "answer" in o:
                        return o["answer"]
        except Exception:
            pass
        time.sleep(interval)
    return None


def ask(question, kind="decision", command=None, image=None, timeout=None):
    """Pause and ask the operator. Returns their answer string, or None (skipped / timed out).
    kind: otp|captcha|2fa|decision|env. For kind='env' include the ONE copy-pastable `command`."""
    if not _enabled():
        return None
    req_id = uuid.uuid4().hex[:12]
    to = float(timeout if timeout is not None else os.environ.get("AEGIS_OPERATOR_TIMEOUT", "1800"))
    rec = {"id": req_id, "ts": time.time(), "kind": kind, "question": question,
           "command": command, "image": image, "reply_to": _REPLY}
    try:
        with open(_REQ, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass
    # surface it loudly so a watcher / co-pilot / human sees it
    print("\n" + "=" * 70, flush=True)
    print(f"[ask-operator #{req_id}] ({kind}) {question}", flush=True)
    if command:
        print(f"  RUN THIS in your terminal, then paste the result back:\n    {command}", flush=True)
    print(f"  reply: append {{\"id\":\"{req_id}\",\"answer\":\"...\"}} to {_REPLY}", flush=True)
    print(f"        (or set AEGIS_OPERATOR_REPLY env). waiting up to {to:.0f}s...", flush=True)
    print("=" * 70, flush=True)
    return _poll_reply(req_id, to)


def pending():
    """List unanswered requests (for a monitor/co-pilot)."""
    reqs, answered = [], set()
    try:
        for line in open(_REPLY, encoding="utf-8", errors="ignore"):
            try:
                answered.add(json.loads(line).get("id"))
            except Exception:
                pass
    except Exception:
        pass
    try:
        for line in open(_REQ, encoding="utf-8", errors="ignore"):
            try:
                o = json.loads(line)
                if o.get("id") not in answered:
                    reqs.append(o)
            except Exception:
                pass
    except Exception:
        pass
    return reqs


def answer(req_id, text):
    """Co-pilot/human helper: record an answer that unblocks a waiting ask()."""
    with open(_REPLY, "a", encoding="utf-8") as f:
        f.write(json.dumps({"id": req_id, "answer": text, "ts": time.time()}) + "\n")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "answer":
        answer(sys.argv[2], " ".join(sys.argv[3:])); print("recorded")
    elif len(sys.argv) > 1 and sys.argv[1] == "pending":
        print(json.dumps(pending(), indent=2))
    else:
        print(ask(" ".join(sys.argv[1:]) or "test question", timeout=15))
