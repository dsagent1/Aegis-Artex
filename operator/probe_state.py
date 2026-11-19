#!/usr/bin/env python3
"""probe_state.py -- mechanical STATE-CARRY across novel-code refine attempts (board design A, 7/8).

Each refine attempt of a hypothesis runs as a fresh, stateless subprocess. Without state-carry, "keep the
working setup" relies on the LLM re-emitting its auth/setup every time -- fragile for multi-step exploits
(auth -> stage CREATE EXTENSION / COPY FROM STDIN / create largeobject -> trigger -> verify). This module
lets a probe EMIT what it established as a `STATE {json}` block; the driver captures it into a per-hypothesis
ProbeState (persisted to disk), and injects it -- with an explicit RE-VALIDATE-BEFORE-USE instruction -- into
the next attempt's bench task, so the bench continues from the last good state.

Board doctrine, enforced here:
  - Non-destructive: every planted artifact carries its own teardown, registered BEFORE it is relied on;
    teardown runs in REVERSE order on every terminal state (win/tried/dead/error). Only CREATE in the
    namespaced prefix poc_<hyp_id>_ or recorded lo_* OIDs; never DELETE/UPDATE/DROP pre-existing objects.
  - Reproducibility: the state blob is a HINT for the refine loop, never the source of truth for the proof.
    A confirmed win records the ordered setup_steps + replay_seed so it replays from a clean mirror.
  - Biggest risk (stale/tampered state): the injected state is always presented as "re-validate, then use";
    a reuse failure is a signal to rebuild that step, not to trust it.
"""
import os, json, time, hashlib, re

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(HERE, "probe_state")
_STATE_RE = re.compile(r"STATE\s*(\{.*?\})\s*(?:$|\n[A-Z]{3,})", re.S)   # a `STATE {json}` block in output

# fields carried across attempts (board list)
_FIELDS = ("hypothesis_id", "attempt_index", "session", "setup_steps", "artifacts", "captured_values",
           "last_successful_step", "last_good_code_hash", "environment_fingerprint", "teardown_plan",
           "replay_seed", "non_destructive_assertion")


def prefix_for(hyp_id):
    """The ONLY namespace a probe may CREATE objects under (non-destructive collision-free)."""
    return f"poc_{(hyp_id or 'anon')[:12]}_"


class ProbeState:
    def __init__(self, hypothesis_id):
        self.hypothesis_id = hypothesis_id
        self.attempt_index = 0
        self.session = {}                 # cookies, headers, auth_token, csrf_token, base_url
        self.setup_steps = []             # [{step,status,artifact_id,reversible,teardown_cmd}]
        self.artifacts = []               # [{type,id,name,location,created_at,cleanup_key,proof_hash}]
        self.captured_values = {}         # {lo_oid,table_name,row_id,file_path,payload_hash,session_id}
        self.last_successful_step = None
        self.last_good_code_hash = None
        self.environment_fingerprint = {}
        self.teardown_plan = []           # reverse-ordered cleanup actions
        self.replay_seed = {}             # deterministic inputs to replay from a clean mirror
        self.non_destructive_assertion = {"verified": True, "touched_objects": []}

    # ---- persistence (per hypothesis, survives a driver restart) ------------------------------------
    def _path(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        return os.path.join(STATE_DIR, f"{(self.hypothesis_id or 'anon')[:40]}.json")

    def save(self):
        try:
            p = self._path(); tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:   # temp + atomic replace so a crash mid-write
                json.dump({f: getattr(self, f) for f in _FIELDS}, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, p)                             # never leaves a truncated state file (Pass 3 #11)
        except Exception:
            pass

    @classmethod
    def load(cls, hypothesis_id):
        s = cls(hypothesis_id)
        p = s._path()
        if os.path.exists(p):
            try:
                d = json.load(open(p, encoding="utf-8"))
                for f in _FIELDS:
                    if f in d:
                        setattr(s, f, d[f])
            except Exception:
                pass
        return s

    def has_state(self):
        return bool(self.session or self.setup_steps or self.artifacts or self.captured_values)

    # ---- ingest a probe's emitted STATE block ------------------------------------------------------
    def merge_output(self, output, code=None):
        """Parse a `STATE {json}` block the probe emitted and merge it. Returns True if state was found."""
        m = _STATE_RE.search(output or "")
        if not m:
            return False
        try:
            blk = json.loads(m.group(1))
        except Exception:
            return False
        if isinstance(blk.get("session"), dict):
            self.session.update(blk["session"])
        if isinstance(blk.get("captured_values"), dict):
            self.captured_values.update(blk["captured_values"])
        for step in (blk.get("setup_steps") or []):
            if isinstance(step, dict):
                self.setup_steps.append(step)
                if step.get("status") == "ok":
                    self.last_successful_step = step.get("step")
        for art in (blk.get("artifacts") or []):
            if isinstance(art, dict):
                self.register_artifact(art)
        if isinstance(blk.get("replay_seed"), dict):
            self.replay_seed.update(blk["replay_seed"])
        if code:
            self.last_good_code_hash = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()[:16]
        self.save()
        return True

    def register_artifact(self, art):
        """Record a planted artifact + its teardown BEFORE we rely on it (non-destructive)."""
        art.setdefault("created_at", time.time())
        self.artifacts.append(art)
        td = art.get("teardown_cmd") or art.get("cleanup_key")
        if td:
            self.teardown_plan.insert(0, td)      # reverse order: last created torn down first
        self.non_destructive_assertion["touched_objects"].append(art.get("name") or art.get("id"))
        self.save()

    # ---- inject the carried state into the next attempt's bench task --------------------------------
    def inject_text(self):
        """Render the PRIOR STATE for the bench, with the board's re-validate-before-use rider."""
        if not self.has_state():
            return ""
        payload = {"session": self.session, "captured_values": self.captured_values,
                   "last_successful_step": self.last_successful_step,
                   "setup_steps_done": [s.get("step") for s in self.setup_steps if s.get("status") == "ok"]}
        return (
            "PRIOR STATE from your last attempt (a HINT, not gospel):\n"
            f"{json.dumps(payload)[:1400]}\n"
            f"RE-VALIDATE each carried value with a cheap check BEFORE building on it (a session may have "
            f"expired, an artifact may be gone); if a carried value fails, REBUILD that one step. Then CONTINUE "
            f"from '{self.last_successful_step}' and add the NEXT step -- do NOT redo the setup that already "
            f"succeeded. Create objects ONLY under the prefix '{prefix_for(self.hypothesis_id)}'. Emit an "
            f"updated STATE {{json}} block (session, captured_values, setup_steps[{{step,status}}], artifacts"
            f"[{{type,id,name,teardown_cmd}}]) at the end so the next step can continue.\n")

    # ---- non-destructive teardown at any terminal state --------------------------------------------
    def teardown(self, runner=None):
        """Run recorded teardown actions in reverse order. `runner(cmd)->None` executes each (best-effort,
        idempotent) and only an EXECUTED command is cleared from the plan. WITHOUT a runner nothing is
        executed and the plan is KEPT (still-present artifacts stay tracked -- the mirror snapshot is the
        real backstop, and a caller can execute the plan later). Never raises. Returns the commands run."""
        if runner is None:
            return []                       # not executed -> do NOT falsely mark the plan done
        done = []
        for cmd in list(self.teardown_plan):
            try:
                runner(cmd); done.append(cmd)
            except Exception:
                pass
        self.teardown_plan = [c for c in self.teardown_plan if c not in done]
        self.save()
        return done

    # ---- reproducibility recipe for a confirmed win -----------------------------------------------
    def replay_recipe(self):
        """The self-contained, ordered chain a reviewer replays from a CLEAN mirror (not the live blob)."""
        return {"hypothesis_id": self.hypothesis_id,
                "steps": [s.get("step") for s in self.setup_steps],
                "replay_seed": self.replay_seed,
                "environment_fingerprint": self.environment_fingerprint,
                "namespace": prefix_for(self.hypothesis_id)}
