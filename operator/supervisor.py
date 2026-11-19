#!/usr/bin/env python3
"""supervisor.py -- the STEP controller for the DS orchestrator's Auto mode (board build-order step 1).

Turns a blocking subprocess into a SUPERVISED, STREAMED, KILLABLE one, so a hang / halt / silent prompt
is caught WHILE the process is alive instead of being autopsied after it. Minimal-close scope: two
signals -- hard timeout, output-silence-with-liveness -- and two actions -- kill process tree, retry-once.
Later tiers (signature classifier, Tier-A verb playbook, direct Support line) layer on the CommandResult
this returns.

Design points carried from the board review:
  - Containment boundary per platform: POSIX new session -> os.killpg; Windows new process group ->
    taskkill /T /F. (WSL: killing wsl.exe may leave the Linux child; D-state fencing is a later tier.)
  - stdin=DEVNULL + noninteractive auth env by default -> PREVENTS the hidden-prompt hang class outright.
  - output-silence is measured against last_output_at from reader threads, so a process that is alive but
    silent (blocked on I/O or a prompt) is distinguishable from one making progress.
  - a worker's own liveness is not progress: callers pair this with a step-progress clock upstream.
"""
import os, sys, time, threading, subprocess, collections
import signal as _signal

_NONINTERACTIVE_ENV = {"DEBIAN_FRONTEND": "noninteractive", "GIT_TERMINAL_PROMPT": "0",
                       "PIP_NO_INPUT": "1", "PYTHONUNBUFFERED": "1"}


class CommandResult:
    """Structured outcome of a supervised run. termination_reason in {exit, hard_timeout, output_silence}."""
    __slots__ = ("returncode", "termination_reason", "stdout_tail", "stderr_tail",
                 "last_output_at", "duration", "attempts", "killed")

    def __init__(self, returncode, termination_reason, stdout_tail, stderr_tail,
                 last_output_at, duration, attempts, killed):
        self.returncode = returncode
        self.termination_reason = termination_reason
        self.stdout_tail = stdout_tail
        self.stderr_tail = stderr_tail
        self.last_output_at = last_output_at
        self.duration = duration
        self.attempts = attempts
        self.killed = killed

    @property
    def ok(self):
        return self.termination_reason == "exit" and self.returncode == 0

    @property
    def output(self):
        return (self.stdout_tail + ("\n" + self.stderr_tail if self.stderr_tail else "")).strip()

    def __repr__(self):
        return (f"CommandResult(rc={self.returncode}, reason={self.termination_reason}, "
                f"dur={self.duration:.1f}s, attempts={self.attempts}, killed={self.killed})")


def _popen(cmd, kali=False, cwd=None):
    env = dict(os.environ); env.update(_NONINTERACTIVE_ENV)
    if kali:
        dist = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
        argv = ["wsl", "-d", dist, "-u", "root", "--", "bash", "-lc", cmd]
    elif os.name == "nt":
        # cmd /c with several quoted tokens ("python" "script") is mangled by cmd's quote-stripping;
        # `cmd /s /c "<whole command>"` (passed as a STRING so subprocess doesn't re-quote a list) makes
        # cmd strip only the outermost pair and run the rest verbatim.
        argv = f'cmd /s /c "{cmd}"'
    else:
        argv = ["bash", "-lc", cmd]
    kw = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
              bufsize=1, universal_newlines=True, encoding="utf-8", errors="replace", cwd=cwd, env=env)
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(argv, **kw)


def kill_tree(p):
    """Kill the whole process tree/group of a supervised Popen. Best-effort, never raises."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)],
                           capture_output=True, timeout=30)
        else:
            try:
                os.killpg(os.getpgid(p.pid), _signal.SIGKILL)
            except Exception:
                p.kill()
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def supervise(cmd, *, kali=False, cwd=None, hard_timeout=600, silence_timeout=120,
              on_silence=None, retries=1, tick=1.0, tail_lines=200,
              progress_fn=None, progress_timeout=300, abort_check=None):
    """Run `cmd` supervised; return a CommandResult.

    hard_timeout    : absolute wall-clock cap (s).
    silence_timeout : max seconds with NO new output while the process is alive (catches hangs / prompts).
    on_silence      : optional hook (elapsed_silence)->('kill'|'wait'); default 'kill'. Use 'wait' to grant
                      a legitimately long-but-silent op more time (board: silence -> diagnose-first).
    progress_fn     : optional ()->comparable; a PROGRESS clock (e.g. findings.jsonl line count). If it
                      does not change for progress_timeout seconds -- even while the process is chatty --
                      the step is a no-progress stall (G2: 'busy but not advancing') and is killed.
    progress_timeout: max seconds with no progress-delta (default 300; set generous, real work has gaps).
    retries         : kill+retry count on a SUPERVISED termination (timeout/silence/no_progress) -- NOT on
                      a clean nonzero exit (that is the command's own result, returned as-is).
    """
    attempt = 0; killed = False
    while True:
        attempt += 1
        p = _popen(cmd, kali=kali, cwd=cwd)
        out = collections.deque(maxlen=tail_lines)
        err = collections.deque(maxlen=tail_lines)
        state = {"last": time.time()}

        def _reader(stream, buf):
            try:
                for line in iter(stream.readline, ''):
                    if line == '':
                        break
                    buf.append(line.rstrip('\n')); state["last"] = time.time()
            except Exception:
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        threading.Thread(target=_reader, args=(p.stdout, out), daemon=True).start()
        threading.Thread(target=_reader, args=(p.stderr, err), daemon=True).start()

        start = time.time(); reason = None
        last_prog = start
        try:
            last_prog_val = progress_fn() if progress_fn else None
        except Exception:
            last_prog_val = None
        while True:
            if p.poll() is not None:
                reason = "exit"; break
            now = time.time()
            # G16: external abort -- the AutoLoop's health monitor confirmed the TARGET is down, so this
            # stage's probes can only produce infra-blocked 'inconclusive'; kill it now to restart + re-run.
            if abort_check is not None:
                try:
                    if abort_check():
                        reason = "aborted_target_down"; break
                except Exception:
                    pass
            if now - start > hard_timeout:
                reason = "hard_timeout"; break
            silence = now - state["last"]
            if silence > silence_timeout:
                decision = on_silence(silence) if on_silence else "kill"
                if decision == "kill":
                    reason = "output_silence"; break
                state["last"] = time.time()          # 'wait' granted -> reset the silence clock
            if progress_fn:                          # G2: progress-delta -- chatty-but-stuck detection
                try:
                    cur = progress_fn()
                except Exception:
                    cur = last_prog_val
                if cur != last_prog_val:
                    # G15: PROGRESS counts as liveness. A leg that writes findings to the store but is
                    # stdout-quiet during internal work IS alive -- advancing the silence clock too stops
                    # output-silence from false-killing a progressing-but-quiet stage. Output-silence now
                    # only fires when there has been NEITHER stdout NOR progress for silence_timeout.
                    last_prog_val = cur; last_prog = now; state["last"] = now
                elif now - last_prog > progress_timeout:
                    reason = "no_progress"; break
            time.sleep(tick)

        dur = time.time() - start
        if reason == "exit":
            return CommandResult(p.returncode, "exit", "\n".join(out), "\n".join(err),
                                 state["last"], dur, attempt, killed)
        # supervised termination -> kill the tree; retry-once if budget remains
        kill_tree(p); killed = True
        if attempt <= retries:
            continue
        return CommandResult(None, reason, "\n".join(out), "\n".join(err),
                             state["last"], dur, attempt, killed)


def run(cmd, **kw):
    """Thin (rc, output) adapter so a supervised call can drop in for the old _sh. A supervised
    termination reports rc = -1 with the reason prefixed on the output tail."""
    r = supervise(cmd, **kw)
    if r.termination_reason == "exit":
        return r.returncode, r.output
    return -1, f"[supervisor: {r.termination_reason} after {r.duration:.0f}s, killed]\n{r.output}"


if __name__ == "__main__":
    # tiny self-test: normal, hard-timeout, and output-silence cases
    print("normal :", run('echo hello', silence_timeout=5, hard_timeout=10))
    slp = "import time; time.sleep(30)"
    print("silence:", supervise(f'{sys.executable} -c "{slp}"', silence_timeout=2, hard_timeout=20, retries=0))
