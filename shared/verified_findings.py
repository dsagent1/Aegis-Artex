"""
verified_findings.py - SHARED verified-findings + oracle layer.

Used by BOTH the aegis_operator co-pilot and the ExploitGym benchmark. The design point
(converged on independently by Claude and Sol): a finding is not a model's prose claim -
it is an immutable, evidence-bearing object whose status can only be moved
candidate -> verified/rejected by an out-of-band VERIFIER running a ground-truth ORACLE.
Reports and benchmark scores count ONLY `verified`. This kills over-claiming, removes the
manual-verification bottleneck, and gives dedup + scoring + tamper-evident replay.

Storage is an append-only, hash-chained JSONL event log (event-sourced): findings and
their status transitions are appended as events, never mutated in place - which also makes
concurrent multi-agent writes safe (no lost updates) and the audit tamper-evident.

Stdlib only, except `requests` is used by HttpOracle (optional). No network at import time.
"""
from __future__ import annotations
import json, hashlib, os, tempfile, time, uuid, subprocess, re
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional
from contextlib import contextmanager

# ---------- hashing / ids ----------
def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def new_id() -> str:
    return uuid.uuid4().hex

def run_marker(prefix: str = "vf") -> str:
    """A globally-unique marker for RUN-SCOPED oracles. Plant this exact value in a writable
    field and assert on IT, so the oracle is robust to accumulated state across re-runs. LESSON:
    never assert an absolute table count (e.g. `count(*)==1`) - twin state accumulates and the
    assertion flips. Assert existence of a per-run marker/artifact instead."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"

# ---------- finding schema ----------
VALID_STATUS = {"candidate", "verified", "rejected", "inconclusive"}
VALID_RETEST = {"still_reproducible", "fixed", "cannot_confirm"}   # ARTEX-port A2

@dataclass
class Evidence:
    kind: str                 # "http" | "db" | "file" | "note"
    detail: str               # human-readable
    artifact_sha256: str = "" # content-hash of the stored artifact/exchange (EvidenceStore key); "" = none captured
    tool_call_id: str = ""
    timestamp: str = field(default_factory=_now)
    # --- ARTEX-port A1: durable, role-tagged HTTP evidence. The bytes live in EvidenceStore under
    # artifact_sha256 (content-addressed, replayable); these fields are the at-a-glance metadata so a
    # report/retest never has to open the blob. All default-empty -> fully backward-compatible. ---
    role: str = ""            # "baseline" | "proof" | "verification" | "supporting" | "" (unspecified)
    url: str = ""             # request URL
    method: str = ""          # request method
    status: int = 0           # response status code (0 = n/a)
    req_len: int = 0          # request body length (chars)
    resp_len: int = 0         # response body length (chars)

@dataclass
class Finding:
    claim_type: str           # taxonomy id, e.g. "money.unbounded_field"
    summary: str
    target_id: str = "target-mirror"
    run_id: str = ""
    finding_id: str = field(default_factory=new_id)
    status: str = "candidate"
    severity: str = "unknown"
    evidence: list = field(default_factory=list)         # list[Evidence-as-dict]
    oracle_id: str = ""
    oracle_receipt: dict = field(default_factory=dict)
    coverage_tags: list = field(default_factory=list)    # ["surface:/api/parts","technique:boundary"]
    provenance: dict = field(default_factory=dict)       # {provider,model,...}
    remediation: dict = field(default_factory=dict)      # stage-10 fix, appended post-verify (never at
                                                         # discovery). {path,fix,component,fixed_version,
                                                         # references,sources,consensus_model,ts}. "path"
                                                         # = "known-cve" (RAG-filled) | "novel" (panel-designed).

# ---------- ARTEX-port A1: content-addressed HTTP-evidence blob store + replay ----------
VALID_ROLE = {"", "baseline", "proof", "verification", "supporting"}

def _evidence_dir() -> str:
    """Where captured exchanges live. Overridable so a run can isolate its evidence."""
    return os.environ.get("AEGIS_EVIDENCE_DIR") or os.path.join(os.getcwd(), "evidence_store")

class EvidenceStore:
    """Content-addressed store for raw HTTP exchanges. The verified-findings chain keeps only the
    sha256 (which binds to these bytes -> tamper-evident); the bytes themselves live here so a finding's
    proof is DURABLE, AUDITABLE and REPLAYABLE after the run. The id IS the content hash -> dedup is free
    and write-once. Separate from the JSONL chain by design: the chain never bloats with bodies."""
    def __init__(self, path: str = None):
        self.path = os.path.abspath(path or _evidence_dir())
        os.makedirs(self.path, exist_ok=True)
    def _file(self, sha: str) -> str:
        return os.path.join(self.path, sha + ".json")
    def put(self, exchange: dict) -> str:
        raw = json.dumps(exchange, sort_keys=True, ensure_ascii=False)
        sha = _sha256(raw)
        fp = self._file(sha)
        if not os.path.exists(fp):                     # write-once dedup
            tmp = fp + ".tmp-" + new_id()[:8]
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, fp)
        return sha
    def get(self, sha: str) -> Optional[dict]:
        fp = self._file(sha)
        if not sha or not os.path.exists(fp):
            return None
        with open(fp, encoding="utf-8") as f:
            return json.load(f)
    def has(self, sha: str) -> bool:
        return bool(sha) and os.path.exists(self._file(sha))

def _exchange(method, url, req_headers, req_body, status, resp_headers, resp_body) -> dict:
    return {"request": {"method": (method or "").upper(), "url": url or "",
                        "headers": dict(req_headers or {}), "body": req_body if req_body is not None else ""},
            "response": {"status": int(status or 0), "headers": dict(resp_headers or {}),
                         "body": resp_body if resp_body is not None else ""}}

def capture_exchange(*, method, url, req_headers=None, req_body="", status=0, resp_headers=None,
                     resp_body="", role="proof", detail="", tool_call_id="",
                     store: "EvidenceStore" = None) -> Evidence:
    """Persist a full HTTP exchange and return a role-tagged Evidence whose artifact_sha256 is POPULATED
    (the field that was historically always empty). Reuses _sha256 via EvidenceStore. ARTEX-port A1."""
    if role not in VALID_ROLE:
        raise ValueError(f"invalid evidence role {role!r} (not in {sorted(VALID_ROLE)})")
    headers = dict(req_headers or {})
    if isinstance(req_body, (dict, list)):             # direct callers may pass a JSON body
        body_req = json.dumps(req_body)
        headers.setdefault("Content-Type", "application/json")
    else:
        body_req = req_body if req_body is not None else ""
    st = store or EvidenceStore()
    sha = st.put(_exchange(method, url, headers, body_req, status, resp_headers, resp_body))
    resp_body = resp_body if resp_body is not None else ""
    return Evidence(kind="http", detail=(detail or f"{(method or '').upper()} {url} -> {status}"),
                    artifact_sha256=sha, tool_call_id=tool_call_id, role=role, url=url or "",
                    method=(method or "").upper(), status=int(status or 0),
                    req_len=len(body_req or ""), resp_len=len(resp_body))

def replay(artifact_sha256: str, *, override: dict = None, store: "EvidenceStore" = None,
           timeout: float = 25, verify: bool = False):
    """Re-fire a stored request from the content-addressed store (ARTEX-style traffic replay), grounded
    on bytes we actually kept. `override` patches request fields (url/method/headers/body) for a retest
    against a patched target. Returns the requests.Response; raises KeyError if the exchange is missing."""
    import requests  # local import so the module loads without requests
    st = store or EvidenceStore()
    ex = st.get(artifact_sha256)
    if ex is None:
        raise KeyError(f"no stored exchange for {artifact_sha256!r}")
    req = dict(ex.get("request", {}))
    if override:
        req.update(override)
    headers = dict(req.get("headers") or {})
    # If the override retargets the host or changes the body, the stored Host / Content-Length belong to
    # the ORIGINAL exchange and would now be wrong (wrong vhost, mismatched length) -> drop them and let
    # requests recompute from the actual url+body. Exact replays (and caller-supplied headers) are untouched.
    if override and ("url" in override or "body" in override) and "headers" not in override:
        headers = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length")}
    kwargs = {"headers": headers, "verify": verify, "timeout": timeout}
    body = req.get("body", "")
    if body:                                           # stored as text -> send verbatim as the body
        kwargs["data"] = body if isinstance(body, str) else json.dumps(body)
    return requests.request(req.get("method", "GET"), req.get("url", ""), **kwargs)

def _maybe_capture(resp, role, *, store: "EvidenceStore" = None):
    """Capture a live requests.Response (and the exact request it carries) into the evidence store, if
    enabled. Returns an Evidence-as-dict or None. NEVER raises into an oracle -- a capture failure or a
    missing `requests` must not abort a hunt. Kill-switch: AEGIS_CAPTURE_EVIDENCE=0."""
    if os.environ.get("AEGIS_CAPTURE_EVIDENCE", "1") == "0" or resp is None:
        return None
    try:
        rq = getattr(resp, "request", None)
        req_body = getattr(rq, "body", "") or ""
        if isinstance(req_body, bytes):
            req_body = req_body.decode("utf-8", "replace")
        ev = capture_exchange(method=getattr(rq, "method", "") or "", url=getattr(rq, "url", "") or "",
                              req_headers=dict(getattr(rq, "headers", {}) or {}), req_body=req_body,
                              status=getattr(resp, "status_code", 0),
                              resp_headers=dict(getattr(resp, "headers", {}) or {}),
                              resp_body=(getattr(resp, "text", "") or ""), role=role, store=store)
        return asdict(ev)
    except Exception:
        return None

# ---------- H13: ONE canonical SPA/catch-all shell predicate (kills the per-oracle copies) ----------
def is_spa_shell(status=None, content_type="", body_head=""):
    """True when a response is the SPA / history-fallback HTML app shell rather than a real API handler
    result -- so a status-based PASS must never fire on it (the recurring bake-off false-PASS). If `status`
    is given, only a 2xx can be a shell (a genuine 4xx/5xx IS a real handler response); pass status=None to
    check the body/type markers regardless of status (e.g. a data-vector guard). Body markers are a fallback
    for servers that return text/html without a definitive content-type. Every oracle/vector should call
    this instead of re-deriving the check."""
    ct = (content_type or "").lower(); b = (body_head or "").lower()
    if status is not None:
        try:
            if not (200 <= int(status) < 300):
                return False
        except (TypeError, ValueError):
            pass
    return ("text/html" in ct) or ("<!doctype html" in b) or ('id="root"' in b) \
        or ("id=root" in b) or ('<div id="app"' in b) or ("id=app" in b)


# ---------- A3: dedup / severity helpers (advisory -- for report/summary; never mutate the chain) --------
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0, "": 0}

# X gate-fix: oracle_id prefixes whose 'verified' verdict is DETERMINISTIC ground truth on its own (OOB
# callback / DB witness / DB-confirmed injection) -> a single one of these is sufficient for a HIGH. An
# HTTP-status/body/timing/rate/header oracle is NOT here, so a lone one of those still caps to medium.
_HIGH_CONF_ORACLE = ("canary@", "db-witness@", "ssrf@", "sqlraw@", "filterinjection@", "dbcausation", "ssti@")

def high_confidence_oracle(oracle_ids) -> bool:
    """ARTEX-port B2 helper: does any oracle_id name a high-confidence (ground-truth) oracle?"""
    return any(any(str(oid).startswith(p) for p in _HIGH_CONF_ORACLE) for oid in (oracle_ids or ()))

def grade_poe(status, confirmations, high_conf, traffic_count) -> int:
    """ARTEX-port B2: proof-of-exploitation grade 0-4. Shared by the chain fold (FindingStore.findings)
    and the report fold (run_monitor._fold_ledger) so both surfaces grade a finding identically.
      0 = not verified · 1 = verified, claim only · 2 = + a bound replayable proof exchange
      3 = ground-truth oracle OR >=2 independent confirmations · 4 = that AND a bound exchange (strongest)."""
    if status != "verified":
        return 0
    poe = 2 if (traffic_count or 0) >= 1 else 1
    if high_conf or (confirmations or 0) >= 2:
        poe = max(poe, 3)
    if (high_conf or (confirmations or 0) >= 2) and (traffic_count or 0) >= 1:
        poe = 4
    return poe


def grade_confidence(status, confirmations, high_conf, traffic_count, poe,
                     disagreement=False, reflect_fp_risk="") -> float:
    """#2 assurance: a CALIBRATED confidence 0..1 that a VERIFIED finding is a true positive. Combines proof
    depth (PoE), independent confirmations, ground-truth-oracle presence and bound replayable evidence;
    DOWNgraded by oracle DISAGREEMENT and a high reflective false-positive risk (#6). Non-verified -> 0.0.
    Advisory only -- the oracle is still ground truth; this is a trust SIGNAL, not a gate."""
    if status != "verified":
        return 0.0
    c = 0.45 + 0.10 * min(int(poe or 0), 4)              # 0.45..0.85 from proof depth
    if high_conf:
        c += 0.10                                        # a ground-truth oracle confirmed it
    c += 0.05 * max(0, (confirmations or 1) - 1)         # each extra INDEPENDENT oracle
    if (traffic_count or 0) >= 1:
        c += 0.05                                        # a replayable proof exchange is bound
    if disagreement:
        c -= 0.25                                        # oracles disagreed on this finding
    c -= {"high": 0.30, "medium": 0.15}.get((reflect_fp_risk or "").lower(), 0.0)   # #6 reflection
    return round(max(0.0, min(1.0, c)), 3)


# ---------- #4: deceptive-target robustness (ATOBench-style) ----------------------------------------
# Threat: a DECEPTIVE / honeypot target emits a "success" signal (200, reflected payload, canned vuln
# banner, slow response) for EVERY input, so a weak oracle that only reads that signal is fooled into a
# false 'verified'. Defense: a DECEIVABLE oracle (status/body/timing/rate/header -- anything NOT in
# _HIGH_CONF_ORACLE) must pass a NEGATIVE CONTROL: the same request shape with a benign/nonsense payload
# that should NOT trigger the vuln. If the control ALSO fires, the target is deceptive and the positive is
# meaningless. GROUND-TRUTH oracles (canary echo / OOB callback / DB witness / raw-SQL / SSTI) are
# deception-resistant by construction -- they require a specific side-channel WITNESS (a unique token
# echoed out-of-band, a DB row actually written) that an always-success target cannot fabricate without
# truly being vulnerable -- so they are exempt from the control requirement.
def oracle_is_deceivable(oracle_ids) -> bool:
    """True iff EVERY confirming oracle is weak (deceivable) -- i.e. none is a ground-truth oracle.
    A finding confirmed by at least one ground-truth oracle is NOT deceivable."""
    ids = list(oracle_ids or ())
    if not ids:
        return True
    return not any(any(str(oid).startswith(p) for p in _HIGH_CONF_ORACLE) for oid in ids)

def deception_verdict(positive: bool, control_positive, high_conf: bool = False) -> str:
    """Classify a weak-oracle observation against its negative control.
      'clean'      -- positive fired, control did NOT (a real differential signal) OR a ground-truth oracle.
      'deceptive'  -- positive fired AND the benign control fired too (target answers success to anything).
      'negative'   -- the positive did not fire (no finding).
      'untested'   -- a deceivable oracle fired but NO control was run (cannot trust -> treat as suspect).
    control_positive is None when no control was run."""
    if not positive:
        return "negative"
    if high_conf:
        return "clean"                 # ground-truth oracle: exempt from the control requirement
    if control_positive is None:
        return "untested"
    return "deceptive" if control_positive else "clean"


def dedup_findings(findings):
    """Collapse duplicate / synthetic-variant findings sharing the same (claim-family, surface, class) --
    e.g. a synthetic concurrency variant of the same resource-persistence bug on the same surface -- keeping
    the highest-severity representative. Returns (kept:list, removed:int). Advisory only: callers use it for
    the report/summary; it never touches the hash-chained store."""
    def _tag(f, pfx):
        for t in (f.get("coverage_tags") or []):
            if str(t).startswith(pfx):
                return str(t)[len(pfx):].split("?")[0]
        return ""
    groups = {}
    for f in findings:
        k = (str(f.get("claim_type", "")).split(".")[0],
             _tag(f, "surface:"),
             _tag(f, "class:") or f.get("claim_type", ""))
        groups.setdefault(k, []).append(f)
    kept, removed = [], 0
    for g in groups.values():
        g.sort(key=lambda f: _SEV_RANK.get(str(f.get("severity", "")).lower(), 0), reverse=True)
        kept.append(g[0]); removed += len(g) - 1
    return kept, removed


# ---------- cross-process append lock (keeps the hash chain intact under concurrent writers) ----------
@contextmanager
def _append_lock(path: str, timeout: float = 10.0, poll: float = 0.02):
    lockpath = path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(lockpath)), exist_ok=True)
    fd = None; start = time.time()
    while True:
        try:
            fd = os.open(lockpath, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            break
        except (FileExistsError, PermissionError):
            # lock is held -> retry. (POSIX raises FileExistsError on O_EXCL; WINDOWS raises
            # PermissionError for a contended/held/being-unlinked lockfile -- both just mean "try
            # again", never crash the writer, or a concurrent writer would lose its update.)
            # stale-lock recovery: a lock older than `timeout` almost certainly belongs to a CRASHED
            # writer. STEAL it (unlink) and retry the acquire so we still end up HOLDING the lock --
            # never proceed unlocked, which would let concurrent writers fork/lose the hash chain.
            if time.time() - start > timeout:
                try:
                    if time.time() - os.path.getmtime(lockpath) > timeout:
                        os.unlink(lockpath)
                        start = time.time()
                        continue                 # retry the acquire immediately
                except FileNotFoundError:
                    continue                     # another waiter already cleared it; retry
                except Exception:
                    pass
            time.sleep(poll)
    try:
        yield
    finally:
        if fd is not None:
            try: os.close(fd)
            except Exception: pass
            try: os.unlink(lockpath)
            except Exception: pass


# ---------- append-only hash-chained store ----------
class FindingStore:
    """Event-sourced: every record/transition is an appended, hash-chained JSONL event.
    Current finding state = fold of its events (latest transition wins)."""
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _last_hash(self) -> str:
        # Read only the TAIL of the append-only log to find the last event_hash -- O(1) per append
        # instead of re-parsing the whole (growing) file on every write (which was O(n^2) over a run
        # and held the cross-process lock ever longer). Falls back to a full scan only if the tail
        # doesn't contain a parseable line (e.g. one huge final event).
        if not os.path.exists(self.path):
            return "GENESIS"
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return "GENESIS"
                span = min(size, 262144)                 # last 256 KB is plenty for the final JSON line
                f.seek(size - span)
                tail = f.read().decode("utf-8", "replace")
            for line in reversed(tail.splitlines()):
                line = line.strip()
                if line:
                    try:
                        return json.loads(line)["event_hash"]
                    except Exception:
                        continue
            if span >= size:                             # whole file scanned via the tail, nothing valid
                return "GENESIS"
        except Exception:
            pass
        # fallback: last valid line via a full scan (rare -- only if the final event exceeds the tail span)
        h = "GENESIS"
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            h = json.loads(line)["event_hash"]
                        except Exception:
                            pass
        except Exception:
            pass
        return h

    def _append(self, event: dict) -> dict:
        event = dict(event)
        event.setdefault("ts", _now())
        # read-head + append under a cross-process lock so concurrent writers cannot
        # both chain off the same prev_hash and fork the chain.
        with _append_lock(self.path):
            event["prev_hash"] = self._last_hash()
            # hash binds the event content to the chain -> tamper-evident
            event["event_hash"] = _sha256(json.dumps(event, sort_keys=True))
            line = json.dumps(event)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n"); f.flush(); os.fsync(f.fileno())
        return event

    def record_candidate(self, finding: Finding) -> str:
        finding.status = "candidate"
        self._append({"type": "record", "finding": asdict(finding)})
        return finding.finding_id

    def _transition(self, finding_id: str, status: str, oracle_id: str, receipt: dict) -> None:
        if status not in VALID_STATUS:   # raise, don't assert: asserts vanish under `python -O` (Pass 4 #8)
            raise ValueError(f"invalid finding status {status!r} (not in {sorted(VALID_STATUS)})")
        self._append({"type": "transition", "finding_id": finding_id,
                      "status": status, "oracle_id": oracle_id, "oracle_receipt": receipt})

    def record_remediation(self, finding_id: str, remediation: dict) -> None:
        """Attach a stage-10 remediation to a finding, append-only (the hash chain stays intact; the
        finding object is never mutated in place). Only meaningful for an already-verified finding -
        remediation is the END of the pipeline, after found -> worked -> tested -> confirmed."""
        rem = dict(remediation); rem.setdefault("ts", _now())
        self._append({"type": "remediation", "finding_id": finding_id, "remediation": rem})

    def record_retest(self, finding_id: str, verdict: str, receipt: dict) -> None:
        """ARTEX-port A2: attach a retest verdict (still_reproducible | fixed | cannot_confirm) to a
        finding, append-only. The finding's original status/evidence are NEVER mutated -- a retest is a
        new, dated observation layered on the historical truth, so 'fixed' never erases the proof the
        finding was once real. Reports read the folded `retest` field for current reproducibility."""
        if verdict not in VALID_RETEST:
            raise ValueError(f"invalid retest verdict {verdict!r} (not in {sorted(VALID_RETEST)})")
        rt = {"verdict": verdict, "receipt": dict(receipt or {}), "ts": _now()}
        self._append({"type": "retest", "finding_id": finding_id, "retest": rt})

    def record_reflection(self, finding_id: str, reflection: dict) -> None:
        """#6: attach a reflective self-verification verdict (adversarial 'why this is a false positive')
        to a finding, append-only. ADVISORY -- it never changes status/evidence (the oracle is ground
        truth); it lowers the finding's confidence and flags it for review. {fp_risk, reasons, recommend}."""
        rf = dict(reflection or {}); rf.setdefault("ts", _now())
        self._append({"type": "reflection", "finding_id": finding_id, "reflection": rf})

    def events(self) -> list:
        out = []
        if not os.path.exists(self.path): return out
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try: out.append(json.loads(line))
                    except Exception: pass
        return out

    def verify_chain(self) -> bool:
        """Re-derive the hash chain to detect tampering."""
        prev = "GENESIS"
        for e in self.events():
            body = {k: v for k, v in e.items() if k != "event_hash"}
            if e.get("prev_hash") != prev: return False
            if e.get("event_hash") != _sha256(json.dumps(body, sort_keys=True)): return False
            prev = e["event_hash"]
        return True

    def findings(self) -> dict:
        """Fold events into current finding states."""
        state: dict = {}
        confirms: dict = {}   # A1: fid -> set of DISTINCT oracle_ids that produced a 'verified' transition
        ev_by_fid: dict = {}  # ARTEX-port A1: fid -> accumulated bound evidence across ALL transitions
        verdicts: dict = {}   # #2 assurance: fid -> {oracle_id: status} across ALL transitions (disagreement)
        decept: dict = {}     # #4: fid -> strongest deception verdict seen in any transition receipt
        for e in self.events():
            if e["type"] == "record":
                fd = e["finding"]; state[fd["finding_id"]] = fd
            elif e["type"] == "transition":
                fid = e["finding_id"]
                if fid in state:
                    state[fid]["status"] = e["status"]
                    state[fid]["oracle_id"] = e["oracle_id"]
                    state[fid]["oracle_receipt"] = e["oracle_receipt"]
                    if e["status"] == "verified" and e.get("oracle_id"):
                        confirms.setdefault(fid, set()).add(e["oracle_id"])
                    verdicts.setdefault(fid, {})[e.get("oracle_id") or "?"] = e["status"]   # #2
                    # a later transition overwrites oracle_receipt, so accumulate its evidence separately
                    _rev = (e.get("oracle_receipt") or {}).get("evidence") or []
                    if _rev:
                        ev_by_fid.setdefault(fid, []).extend(_rev)
                    _dv = (e.get("oracle_receipt") or {}).get("deception")   # #4
                    if _dv in ("deceptive", "untested"):
                        # 'deceptive' is the stronger signal; never let a later 'untested' downgrade it
                        if decept.get(fid) != "deceptive":
                            decept[fid] = _dv
            elif e["type"] == "remediation":
                fid = e["finding_id"]
                if fid in state:
                    state[fid]["remediation"] = e["remediation"]
            elif e["type"] == "retest":                      # ARTEX-port A2
                fid = e["finding_id"]
                if fid in state:
                    state[fid].setdefault("retests", []).append(e["retest"])
                    state[fid]["retest"] = e["retest"]       # latest verdict wins
            elif e["type"] == "reflection":                  # #6 reflective self-verification
                fid = e["finding_id"]
                if fid in state:
                    state[fid].setdefault("reflections", []).append(e["reflection"])
                    state[fid]["reflection"] = e["reflection"]  # latest reflection wins
        # A1 (doctrine) + X gate-fix: a HIGH/critical needs >=2 INDEPENDENT oracle confirmations -- UNLESS a
        # single confirming oracle is HIGH-CONFIDENCE deterministic ground truth (a canary/OOB callback, a DB
        # witness, an OOB-SSRF, or a DB-confirmed raw-SQL/filter-injection), which is sufficient alone. A
        # single HTTP-status/body/timing/rate oracle is NOT sufficient -> CAPPED to medium (never dropped, so
        # this only LOWERS false-severity, never raises the false-positive rate). Without the X gate-fix a
        # true novel-class HIGH proven by a lone canary/DB oracle could never reach verified-HIGH.
        for fid, f in state.items():
            oids = confirms.get(fid, set())
            n = len(oids)
            f["confirmations"] = n
            hi_conf = any(any(str(oid).startswith(p) for p in _HIGH_CONF_ORACLE) for oid in oids)
            f["high_confidence_oracle"] = hi_conf
            if f.get("status") == "verified" and str(f.get("severity", "")).lower() in ("high", "critical") \
                    and n < 2 and not hi_conf:
                f["severity_claimed"] = f.get("severity")
                f["severity"] = "medium"
                f["severity_note"] = ("A1: single-oracle %s capped to medium pending a 2nd independent "
                                      "oracle (%d confirmation, none high-confidence)" % (f["severity_claimed"], n))
            # ARTEX-port B2: proof-strength grade (PoE 0-4) + count of BOUND http exchanges (A1 evidence).
            evs = list(f.get("evidence") or []) + ev_by_fid.get(fid, [])
            bound = [ev for ev in evs if isinstance(ev, dict)
                     and ev.get("kind") == "http" and ev.get("artifact_sha256")]
            seen, dedup = set(), []
            for ev in bound:                             # distinct exchanges by content hash
                s = ev.get("artifact_sha256")
                if s not in seen:
                    seen.add(s); dedup.append(ev)
            f["bound_evidence"] = dedup                  # merged, deduped -- for reports + retest
            tc = len(dedup)
            f["traffic_count"] = tc
            f["poe"] = grade_poe(f.get("status"), n, hi_conf, tc)
            # #2 assurance: oracle DISAGREEMENT (verified AND a non-verified verdict on the same finding) +
            # a CALIBRATED confidence (downgraded by disagreement and a high reflective FP-risk from #6).
            _vd = verdicts.get(fid, {})
            _st = set(_vd.values())
            _base_disagree = ("verified" in _st and bool(_st - {"verified"}))
            # #4: a deceptive-target verdict (benign control also fired, weak oracle only) is a hard
            # trust failure -- treat it like oracle disagreement so confidence collapses; 'untested' (a
            # deceivable oracle fired with no control run) is a softer suspicion, also folded in. A
            # ground-truth confirmation (hi_conf) clears it -- that oracle can't be deceived.
            f["deception"] = decept.get(fid, "")
            _dec_hit = (not hi_conf) and f["deception"] in ("deceptive", "untested")
            f["disagreement"] = bool(_base_disagree or _dec_hit)
            f["verdict_spread"] = _vd
            f["confidence"] = grade_confidence(f.get("status"), n, hi_conf, tc, f["poe"],
                                               f["disagreement"], (f.get("reflection") or {}).get("fp_risk", ""))
        return state

    def assurance(self) -> dict:
        """#2 assurance metrics over the store: verification-outcome rates + confidence + disagreement.
        false_positive_rate = rejected / (verified + rejected) -- the trust number ATO/JEV-style harnesses
        track (how often a CANDIDATE was an over-claim the oracle refuted). Advisory report metric."""
        fs = list(self.findings().values())
        ver = [f for f in fs if f.get("status") == "verified"]
        rej = [f for f in fs if f.get("status") == "rejected"]
        inc = [f for f in fs if f.get("status") == "inconclusive"]
        confs = [f.get("confidence", 0.0) for f in ver]
        denom = len(ver) + len(rej)
        buckets = {"high(>=0.8)": 0, "med(0.5-0.8)": 0, "low(<0.5)": 0}
        for c in confs:
            buckets["high(>=0.8)" if c >= 0.8 else "med(0.5-0.8)" if c >= 0.5 else "low(<0.5)"] += 1
        return {"total": len(fs), "verified": len(ver), "rejected": len(rej), "inconclusive": len(inc),
                "false_positive_rate": round(len(rej) / denom, 3) if denom else None,
                "inconclusive_rate": round(len(inc) / len(fs), 3) if fs else None,
                "disagreements": sum(1 for f in fs if f.get("disagreement")),
                "deceptive_target_flags": sum(1 for f in fs if f.get("deception") == "deceptive"),
                "mean_confidence": round(sum(confs) / len(confs), 3) if confs else None,
                "confidence_distribution": buckets,
                "low_confidence_verified": [f.get("finding_id") for f in ver if f.get("confidence", 0) < 0.5]}

    def verified(self) -> list:
        return [f for f in self.findings().values() if f["status"] == "verified"]

    def coverage(self) -> dict:
        tags: dict = {}
        for f in self.findings().values():
            for t in f.get("coverage_tags", []):
                tags[t] = tags.get(t, 0) + 1
        return tags

# ---------- oracles ----------
class Oracle:
    """Given a Finding, return (status, receipt). Only a Verifier may apply the result."""
    id = "base@0"
    def check(self, finding: Finding):  # -> (status, receipt)
        raise NotImplementedError

class CallableOracle(Oracle):
    """Wrap any function fn(finding)->(bool_or_status, receipt_dict)."""
    def __init__(self, fn: Callable, oracle_id: str):
        self._fn = fn; self.id = oracle_id
    def check(self, finding: Finding):
        res, receipt = self._fn(finding)
        status = res if isinstance(res, str) else ("verified" if res else "rejected")
        return status, receipt

class HttpOracle(Oracle):
    """Re-issue an HTTP request and assert on the response (status code + body regex).
    expected_status: int or None; body_regex: pattern that MUST match for 'verified'."""
    def __init__(self, base, method, path, *, cookie=None, json_body=None,
                 expected_status=None, body_regex=None, absent_regex=None, oracle_id="http@1"):
        import requests  # local import so module loads without requests
        self._requests = requests
        self.base, self.method, self.path = base, method, path
        self.cookie, self.json_body = cookie, json_body
        self.expected_status, self.body_regex, self.absent_regex = expected_status, body_regex, absent_regex
        self.id = oracle_id
    def check(self, finding: Finding):
        try:
            r = self._requests.request(self.method, self.base + self.path,
                                       headers=({"Cookie": self.cookie} if self.cookie else {}),
                                       json=self.json_body, verify=False, timeout=25)
        except Exception as e:
            # target unreachable / transport error: we CANNOT confirm the claim (this is not a
            # refutation -- we never got to test), so return 'inconclusive' with the error on the
            # receipt. Crucially this never raises: an oracle that raised would abort the whole hunt.
            return ("inconclusive", {"error": str(e)[:200], "unreachable": True})
        body = r.text or ""
        ok = True
        if self.expected_status is not None: ok = ok and (r.status_code == self.expected_status)
        if self.body_regex is not None:      ok = ok and bool(re.search(self.body_regex, body))
        if self.absent_regex is not None:    ok = ok and not bool(re.search(self.absent_regex, body))
        receipt = {"status_code": r.status_code, "body_sha256": _sha256(body),
                   "body_head": body[:160], "checked": {"expected_status": self.expected_status,
                   "body_regex": self.body_regex, "absent_regex": self.absent_regex}}
        # SPA / catch-all GUARD: a bare 2xx with no distinguishing body assertion can be an SPA history-
        # fallback (the app serves the SAME shell for every path) -- a 200 there confirms NOTHING. Require a
        # DISTINGUISHING response: hit a random nonexistent path; if the target's 2xx is indistinguishable
        # from that baseline (same status + same body shell), reject it as a fallback rather than over-claim.
        if ok and self.body_regex is None and 200 <= (r.status_code or 0) < 300:
            try:
                import random as _rnd
                bpath = "/__aegis_nx_%d" % _rnd.randint(10 ** 6, 10 ** 7 - 1)
                b = self._requests.request("GET", self.base + bpath,
                                           headers=({"Cookie": self.cookie} if self.cookie else {}),
                                           verify=False, timeout=15)
                bbody = b.text or ""
                same_shell = (_sha256(bbody) == _sha256(body)) or (
                    abs(len(bbody) - len(body)) <= max(16, int(0.02 * len(body))) and bbody[:80] == body[:80])
                if b.status_code == r.status_code and same_shell:
                    ok = False
                    receipt["spa_fallback"] = {
                        "baseline_path": bpath, "baseline_status": b.status_code,
                        "note": "2xx indistinguishable from a nonexistent path (SPA/catch-all fallback) -- "
                                "not a finding; use a body_regex/expected content to confirm a real hit"}
            except Exception:
                pass
        ev = _maybe_capture(r, "proof")           # ARTEX-port A1: durable, replayable proof exchange
        if ev:
            receipt["evidence"] = [ev]
        return ("verified" if ok else "rejected"), receipt

class AuthzOracle(Oracle):
    """BROKEN-ACCESS / OVER-REACH oracle (cross-role, FP-resistant). A plain status check cannot express
    over-reach: 200 is only a finding when a role that SHOULD be denied gets it. This oracle re-issues
    the SAME request as TWO roles and confirms over-reach only on TWO independent signals:
      (1) the TESTED role gets a success (2xx)  AND
      (2) a BASELINE role (one that must be denied) gets 401/403 on the same surface -- proving the
          surface is genuinely access-controlled (so we never flag a public endpoint).
    It also never flags a role listed in `intended_roles` (e.g. a business-intended privileged role),
    so a legitimately-allowed role isn't reported as a bug. Needs session_for_role(role)->Session."""
    def __init__(self, base, method, path, role, baseline_role, session_for_role, *,
                 json_body=None, intended_roles=None, denied=(401, 403), conflict=(409, 422),
                 confirm_json_body=None, oracle_id="authz@1"):
        self.base, self.method, self.path = base, method, path
        self.role, self.baseline_role = role, baseline_role
        self.session_for_role, self.json_body = session_for_role, json_body
        # F5: intended_roles may be a FLAT list (global -- backward-compatible) OR a PER-SURFACE dict
        # {surface_glob: [roles]}, so a role intended on /api/invoices/* is NOT excused on /api/settings/*
        # (a coarse global list over-excuses a legitimately-privileged-elsewhere role and hides real bugs).
        self.intended_roles = intended_roles or []
        self.denied = set(denied)
        # MUTATION-AWARENESS: on a WRITE, these statuses mean the request reached business logic (got PAST
        # authz), so a tested role hitting them proves it HOLDS the permission even when the action was
        # business-blocked. `confirm_json_body` (optional) is a fresh, non-conflicting body re-issued as the
        # tested role to upgrade a conflict-only signal to a proven successful write.
        self.conflict = set(conflict)
        self.confirm_json_body = confirm_json_body
        self.id = oracle_id

    def _intended_for(self, path):
        """Roles business-intended-privileged FOR THIS SURFACE (never flagged as over-reach). A dict maps
        surface glob/substring -> roles; a flat list is treated as global (all surfaces)."""
        ir = self.intended_roles
        if isinstance(ir, dict):
            import fnmatch
            out = set()
            for pat, roles in ir.items():
                p = str(pat)
                if fnmatch.fnmatch(path or "", p) or (p and p in (path or "")):
                    out |= {str(r).lower() for r in (roles or [])}
            return out
        return {str(r).lower() for r in (ir or [])}

    @staticmethod
    def _norm_body(t):
        """Collapse volatile bits (CSRF tokens, nonces, timestamps, long hex/uuid runs) so an SPA/public
        shell that only differs by a per-request token still compares EQUAL -- otherwise those diffs defeat
        the spa_or_public guard and a public 200 is falsely VERIFIED as over-reach (Pass 4 #17). Erring
        toward 'equal' is FP-safe here (a missed bug beats a false finding)."""
        import re as _r
        t = t or ""
        t = _r.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\"'\s]*", "TS", t)      # ISO timestamps
        t = _r.sub(r"(?i)(csrf[_-]?token|xsrf[_-]?token|nonce|_token)([\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9\-_./+]+",
                   r"\1\2TOK", t)                                                      # token values
        t = _r.sub(r"\b[0-9a-fA-F]{16,}\b", "HEX", t)                                # long hex/hashes/uuids
        return t.strip()

    def check(self, finding: Finding):
        role = str(self.role or "").lower()
        intended = self._intended_for(self.path)
        if role in intended:
            return "rejected", {"note": f"role {role!r} is intended-privileged on {self.path} -- not over-reach",
                                "tested_role": role, "surface": self.path}
        try:
            st = self.session_for_role(self.role)
            sb = self.session_for_role(self.baseline_role)
            ar = st.request(self.method, self.base + self.path, json=self.json_body, verify=False, timeout=25)
            br = sb.request(self.method, self.base + self.path, json=self.json_body, verify=False, timeout=25)
        except Exception as e:
            return "inconclusive", {"error": str(e)[:200], "unreachable": True}
        tested_ok = 200 <= ar.status_code < 300
        baseline_denied = br.status_code in self.denied
        # MUTATION-AWARENESS: on a WRITE method a tested 409/422 is NOT a denial -- it proves the request
        # reached business logic (got PAST authz), e.g. dispatcher POST /api/invoices on a duplicate job
        # -> 409 "already exists". Pairing that with a baseline that is genuinely DENIED (401/403) confirms
        # a differential PERMISSION grant = over-reach, even when this instance was business-blocked. (400 is
        # EXCLUDED: stacks that validate before authz return 400 without authz ever running.) A 2xx also
        # proves the ACTION itself succeeded, not just the grant.
        mutating = str(self.method).upper() in ("POST", "PUT", "PATCH", "DELETE")
        tested_conflict = mutating and ar.status_code in self.conflict
        tested_passed = tested_ok or tested_conflict
        # DISTINGUISHING-2xx guard (mirrors HttpOracle's SPA-200 fix): a tested 2xx is only real,
        # role-gated ACCESS if it differs both from an UNAUTHENTICATED request (else the surface is
        # public / an SPA shell, not attributable to the role) and from a random nonexistent path
        # (else it's the SPA/catch-all fallback). Without this, a public/SPA 200 + a baseline 401/403
        # (e.g. a role-account lockout that returns 403 while anon gets the SPA 200) reads as over-reach.
        spa_or_public = False; guard_note = ""
        if tested_ok:
            try:
                import requests as _rq, uuid as _uuid
                anon = _rq.Session(); anon.verify = False
                ur = anon.request(self.method, self.base + self.path, json=self.json_body, verify=False, timeout=20)
                if 200 <= ur.status_code < 300 and self._norm_body(ur.text) == self._norm_body(ar.text):
                    spa_or_public = True
                    guard_note = " | rejected-guard: tested 2xx identical to an UNAUTHENTICATED request (public/SPA, not role-gated)"
                else:
                    npath = "/zz-nonexistent-" + _uuid.uuid4().hex[:10]
                    nr = st.request("GET", self.base + npath, verify=False, timeout=20)
                    if nr.status_code == ar.status_code and self._norm_body(nr.text) == self._norm_body(ar.text):
                        spa_or_public = True
                        guard_note = " | rejected-guard: tested 2xx identical to a nonexistent-path baseline (SPA catch-all)"
            except Exception:
                pass
        # optional 2-STEP CONFIRM: re-issue as the tested role with a fresh, non-conflicting body; a 2xx
        # there upgrades a conflict-only signal to a proven successful write (PLAUSIBLE -> CONFIRMED).
        action_confirmed = tested_ok
        if tested_conflict and not tested_ok and self.confirm_json_body is not None:
            try:
                cr = st.request(self.method, self.base + self.path, json=self.confirm_json_body,
                                verify=False, timeout=25)
                action_confirmed = 200 <= cr.status_code < 300
            except Exception:
                pass
        over_reach = tested_passed and baseline_denied and not spa_or_public
        receipt = {
            "over_reach": over_reach, "surface": self.path,
            "tested_role": role, "tested_status": ar.status_code,
            "baseline_role": str(self.baseline_role).lower(), "baseline_status": br.status_code,
            "spa_or_public": spa_or_public, "action_confirmed": action_confirmed,
            "via": ("action-2xx" if tested_ok else "business-conflict" if tested_conflict else "none"),
            "note": (("write over-reach: tested role reached business logic (status %s) while the baseline "
                      "role is denied (%s) on an access-controlled write%s" %
                      (ar.status_code, br.status_code,
                       " -- action success CONFIRMED via fresh-object 2xx" if action_confirmed and not tested_ok else ""))
                     if over_reach and tested_conflict and not tested_ok else
                     "access-controlled surface (baseline denied) reached by a role that should be denied"
                     if over_reach else
                     "not over-reach: tested role not granted, surface not access-controlled, or public/SPA 2xx") + guard_note}
        # ARTEX-port A1: bind both role exchanges as evidence -- tested role = proof, baseline role = baseline
        _evs = [e for e in (_maybe_capture(ar, "proof"), _maybe_capture(br, "baseline")) if e]
        if _evs:
            receipt["evidence"] = _evs
        return ("verified" if over_reach else "rejected"), receipt


class InvariantOracle(Oracle):
    """A numeric DOMAIN INVARIANT that must hold (measured <= bound). Verified (a BUG) iff the invariant
    HELD before the action and is VIOLATED after -- e.g. sum(issued credit notes) <= invoice.total held
    at 0<=78, then 156>78 after replaying a full credit. Numbers are pre-measured by the stateful leg;
    the oracle applies the rule (re-running the stateful move re-measures, so it stays re-verifiable)."""
    def __init__(self, before, after, bound, *, oracle_id="invariant@1", label="", surface=""):
        self.before, self.after, self.bound = float(before), float(after), float(bound)
        self.id, self.label, self.surface = oracle_id, label, surface
    def check(self, finding=None):
        eps = 1e-9
        held = self.before <= self.bound + eps
        violated = self.after > self.bound + eps
        ok = held and violated
        return ("verified" if ok else "rejected"), {
            "invariant": self.label or "measured<=bound", "surface": self.surface,
            "before": self.before, "after": self.after, "bound": self.bound,
            "held_before": held, "violated_after": violated}


class IdempotencyOracle(Oracle):
    """Replaying a mutation N>1 times must be a NO-OP after the first (idempotent). Verified (a BUG) iff a
    business-state metric grew by MORE than one unit-effect across the replays (e.g. credit-note count
    0 -> 2 on a double POST). Distinguishes an allowed duplicate (delta<=unit) from a real replay bug."""
    def __init__(self, before, after, repeats, *, unit=1.0, oracle_id="idempotency@1", label="", surface=""):
        self.before, self.after, self.repeats, self.unit = float(before), float(after), int(repeats), float(unit)
        self.id, self.label, self.surface = oracle_id, label, surface
    def check(self, finding=None):
        delta = self.after - self.before
        non_idempotent = (self.repeats > 1) and (delta > self.unit + 1e-9)
        return ("verified" if non_idempotent else "rejected"), {
            "metric": self.label or "state-count", "surface": self.surface,
            "metric_before": self.before, "metric_after": self.after, "delta": delta,
            "repeats": self.repeats, "unit_effect": self.unit, "non_idempotent": non_idempotent}


class ResourcePersistenceOracle(Oracle):
    """SCAFFOLD/stack resource LEAK or exhaustion: a HEAVY request run must not leave a resource metric
    (container RSS, temp-file count, DB connections) elevated after a cooldown BEYOND what a benign CONTROL
    run leaves. Verified (a BUG) iff the heavy-run delta exceeds the control-run delta by `factor` AND an
    absolute `floor` -- so warmup / GC / JIT jitter (which the control incurs too) is subtracted out and
    not mistaken for a leak. Numbers are measured by the stateful leg (docker cgroup / exec / sql / fs)."""
    def __init__(self, heavy_delta, control_delta, *, floor=0.0, factor=2.0, unit="bytes",
                 oracle_id="resource-persistence@1", surface=""):
        self.heavy_delta = float(heavy_delta); self.control_delta = float(control_delta)
        self.floor = float(floor); self.factor = float(factor); self.unit = unit
        self.id = oracle_id; self.surface = surface
    def check(self, finding=None):
        leak = (self.heavy_delta > self.floor) and                (self.heavy_delta > self.control_delta * self.factor + self.floor)
        return ("verified" if leak else "rejected"), {
            "metric": "resource-persistence", "unit": self.unit, "surface": self.surface,
            "heavy_delta": self.heavy_delta, "control_delta": self.control_delta,
            "floor": self.floor, "factor": self.factor, "leak": leak}


class AuthStateOracle(Oracle):
    """Auth/session STATE at the stack layer. After an explicit logout/invalidation the SAME session must no
    longer reach a protected resource. Verified (a BUG) iff the resource was authorized BEFORE logout (2xx)
    AND is STILL authorized AFTER (2xx) -- server-side session invalidation failed (token_not_invalidated).
    (Also the shape for session-fixation: pre = a pre-seeded id becoming authenticated.)"""
    def __init__(self, pre_status, post_status, *, denied=(401, 403), oracle_id="auth-state@1",
                 surface="", label=""):
        self.pre = int(pre_status); self.post = int(post_status); self.denied = set(denied)
        self.id = oracle_id; self.surface = surface; self.label = label
    def check(self, finding=None):
        was_authed = 200 <= self.pre < 300
        still_authed = 200 <= self.post < 300
        bug = was_authed and still_authed
        return ("verified" if bug else "rejected"), {
            "metric": self.label or "session-invalidation", "surface": self.surface,
            "pre_logout_status": self.pre, "post_logout_status": self.post,
            "invalidated": (not still_authed), "bug": bug}


class MassAssignOracle(Oracle):
    """MASS ASSIGNMENT / auto-binding -- the server accepts+persists a client-supplied PRIVILEGED field it
    should ignore (role/isAdmin/status/approved/balance/ownerId/id...). VERIFIED iff, after a create/update
    that INJECTED such a field with a distinctive MARKER value, the returned/read-back object carries that
    field == our marker (persisted), AND a CONTROL object (created without the injection) does NOT have that
    value -- so a legitimate default can't masquerade as acceptance. Non-destructive: plant-for-proof."""
    _PRIVILEGED = ("role", "isadmin", "is_admin", "admin", "approved", "verified", "status", "balance",
                   "ownerid", "owner_id", "userid", "user_id", "id", "createdby", "created_by", "amount",
                   "price", "total", "discount", "iscleared", "paid")

    def __init__(self, created_obj, injected, *, control_obj=None, oracle_id="massassign@1", surface=""):
        self.obj = created_obj if isinstance(created_obj, dict) else {}
        self.injected = injected or {}
        self.control = control_obj if isinstance(control_obj, dict) else None
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        leads = []
        for k, v in self.injected.items():
            if k.lower() not in self._PRIVILEGED:
                continue
            got = self.obj.get(k)
            if got is None or str(got) != str(v):
                continue                                   # our marker did NOT persist
            if self.control is not None and str(self.control.get(k)) == str(v):
                continue                                   # a legitimate default equals our value -> not a bug
            leads.append({"field": k, "injected": v, "persisted": got})
        verdict = "verified" if leads else "rejected"
        return verdict, {"surface": self.surface, "n_leads": len(leads), "leads": leads[:8],
                         "note": ("privileged client-supplied field(s) accepted+persisted (mass assignment)"
                                  if leads else "no injected privileged field persisted")}


class OpenRedirectOracle(Oracle):
    """OPEN REDIRECT -- a redirect parameter sends the user to an attacker-controlled EXTERNAL host.
    VERIFIED iff a 3xx Location header (or a meta/JS redirect in the body) points to the injected CANARY
    host. FP guard: the canary must be an EXTERNAL host (not the target's own), and it must appear as the
    redirect TARGET (host position), not merely echoed elsewhere. Reads only (GET) -- non-destructive."""
    def __init__(self, status, location, body, canary_host, *, target_host="", oracle_id="openredir@1", surface="", param=""):
        self.status = int(status or 0); self.location = str(location or ""); self.body = str(body or "")
        self.canary = str(canary_host or "").lower(); self.target = str(target_host or "").lower()
        self.id = oracle_id; self.surface = surface; self.param = param
    def check(self, finding=None):
        import re as _re
        loc = self.location.lower()
        # Location points at the canary host (scheme-relative //canary, https://canary, or ...@canary)
        in_location = bool(self.canary) and (self.status in (301, 302, 303, 307, 308)) and (
            _re.search(r"(?://|https?:/{2}|@)" + _re.escape(self.canary), loc) is not None
            or loc.startswith(self.canary) or loc.startswith("//" + self.canary))
        # meta-refresh / JS redirect in body -> the canary as a url= / location= target
        in_body = bool(self.canary) and _re.search(
            r"(?:url=|location(?:\.href)?\s*=\s*[\"']?)\s*(?://|https?:/{2})?" + _re.escape(self.canary),
            self.body.lower()) is not None
        verdict = "verified" if (in_location or in_body) else "rejected"
        return verdict, {"surface": self.surface, "param": self.param, "status": self.status,
                         "location": self.location[:200], "canary": self.canary, "via": ("location" if in_location else ("body" if in_body else None)),
                         "note": ("open redirect to external canary" if verdict == "verified" else "no external redirect")}


class SessionFixationOracle(Oracle):
    """SESSION FIXATION -- the session id must ROTATE on privilege change (login). VERIFIED (a bug) iff a
    pre-auth session id existed, it did NOT change after a successful login (same id value), AND that same
    session is now AUTHENTICATED -- an attacker-fixed id survives authentication. Reads only (a normal
    login); non-destructive."""
    def __init__(self, pre_id, post_id, authed_after, *, oracle_id="sessfix@1", surface="", cookie=""):
        self.pre = pre_id; self.post = post_id; self.authed = bool(authed_after)
        self.id = oracle_id; self.surface = surface; self.cookie = cookie
    def check(self, finding=None):
        had_pre = bool(self.pre)
        not_rotated = had_pre and self.pre == self.post
        bug = not_rotated and self.authed
        return ("verified" if bug else "rejected"), {
            "surface": self.surface, "cookie": self.cookie, "pre_id_present": had_pre,
            "rotated_on_login": (not not_rotated), "authenticated_after": self.authed, "bug": bug,
            "note": ("session id NOT rotated on login and is authenticated (fixation)" if bug else
                     ("session id rotated on login (ok)" if had_pre else "no pre-auth session id to fix"))}


class FileUploadOracle(Oracle):
    """UNRESTRICTED / dangerous FILE UPLOAD. VERIFIED iff a file with ACTIVE-CONTENT type/extension (html,
    svg, xhtml, js, php, phtml, svg-with-script) was ACCEPTED (upload 2xx) AND is RETRIEVABLE and served with
    a RENDERABLE content-type (text/html, image/svg+xml, application/xhtml) -- i.e. it could execute in a
    victim's browser (stored XSS / RCE-adjacent). If `executed` is set (a headless check confirmed the marker
    ran) that is the strongest signal. FP guard: the file must actually be retrievable + served renderable,
    not merely 200-on-upload. Non-destructive: plants ONE benign marker file, never erases."""
    _RENDERABLE = ("text/html", "image/svg+xml", "application/xhtml", "application/xml", "text/xml")
    _DANGEROUS_EXT = (".html", ".htm", ".svg", ".xhtml", ".js", ".php", ".phtml", ".php5", ".jsp", ".asp")

    def __init__(self, upload_status, retrieve_status, retrieve_ctype, filename, *, executed=False,
                 oracle_id="upload@1", surface=""):
        self.up = int(upload_status or 0); self.rs = int(retrieve_status or 0)
        self.ctype = str(retrieve_ctype or "").lower(); self.fn = str(filename or "")
        self.executed = bool(executed); self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        accepted = 200 <= self.up < 300
        retrievable = 200 <= self.rs < 300
        dangerous_ext = any(self.fn.lower().endswith(e) for e in self._DANGEROUS_EXT)
        renderable = any(c in self.ctype for c in self._RENDERABLE)
        bug = accepted and dangerous_ext and (self.executed or (retrievable and renderable))
        sev = "high" if (self.executed or renderable) else "medium"
        return ("verified" if bug else "rejected"), {
            "surface": self.surface, "filename": self.fn, "upload_status": self.up,
            "retrieve_status": self.rs, "retrieve_ctype": self.ctype, "renderable": renderable,
            "executed": self.executed, "severity": sev,
            "note": ("active-content upload accepted + served renderable" + (" + EXECUTED" if self.executed else "")
                     if bug else "no dangerous upload confirmed")}


class XssOracle(Oracle):
    """XSS (reflected / DOM / stored) confirmed by EXECUTION, not reflection. The probe injects a marker
    payload that, IF it executes in the browser, sets `window.__aegis_xss` to a unique TOKEN. VERIFIED iff a
    headless browser load of the target shows `window.__aegis_xss === token` -- i.e. the script actually RAN
    (a real, FP-free signal; mere reflection of the string is NOT enough). Non-destructive (reads/loads)."""
    def __init__(self, executed_token, expected_token, *, surface="", param="", context="", oracle_id="xss@1"):
        self.executed = executed_token; self.expected = expected_token
        self.surface = surface; self.param = param; self.context = context; self.id = oracle_id
    def check(self, finding=None):
        fired = bool(self.expected) and self.executed == self.expected
        return ("verified" if fired else "rejected"), {
            "surface": self.surface, "param": self.param, "context": self.context,
            "executed": bool(fired), "note": ("payload EXECUTED in the browser (XSS confirmed)" if fired
                                              else "payload did not execute (no XSS via this vector)")}


class SsrfOracle(Oracle):
    """SSRF -- VERIFIED by EITHER (a) blind OOB: our injected CANARY token was CALLED BACK (the target made
    an outbound request we controlled), OR (#3) (b) SSRF-to-metadata: the target FETCHED an internal/IMDS
    URL and REFLECTED the response, so its body carries a distinctive cloud-metadata/credential SIGNATURE
    (AccessKeyId, ami-id, iam/security-credentials, GCP computeMetadata token). Both are ground truth --
    the callback is unforgeable; the IMDS signature is metadata content the app could only have if it
    fetched the internal endpoint (NOT our echoed input). FP-free. Non-destructive (GETs)."""
    _IMDS_SIG = [re.compile(p, re.I) for p in (
        r'"AccessKeyId"\s*:', r'"SecretAccessKey"\s*:', r'"Token"\s*:\s*"[A-Za-z0-9/+=]{40,}',
        r'\bami-[0-9a-f]{8,}\b', r'iam/security-credentials', r'instance-identity/document',
        r'computeMetadata|metadata\.google\.internal', r'"accountId"\s*:\s*"\d{6,}"')]

    def __init__(self, token_hits=None, *, reflected_body="", surface="", param="", oracle_id="ssrf@1"):
        self.hits = list(token_hits or [])
        self.body = str(reflected_body or "")
        self.surface = surface; self.param = param; self.id = oracle_id

    def check(self, finding=None):
        callback = bool(self.hits)
        sigs = [rx.pattern for rx in self._IMDS_SIG if rx.search(self.body)] if self.body else []
        verdict = "verified" if (callback or sigs) else "rejected"
        return verdict, {"surface": self.surface, "param": self.param, "severity": "high",
                         "n_hits": len(self.hits), "hits": self.hits[:4],
                         "callback": callback, "imds_signature": sigs[:3],
                         "note": ("target called back the canary (blind SSRF confirmed)" if callback else
                                  ("SSRF-to-metadata: response reflects cloud-metadata signature %s" % sigs[:2]
                                   if sigs else "no OOB callback and no reflected metadata signature"))}


class CsrfOracle(Oracle):
    """CSRF POSTURE (non-destructive -- assesses defenses, does not forge a state-changing request).
    VERIFIED (exposed) iff the session cookie provides NO cross-site protection (SameSite absent or =None)
    AND no anti-CSRF token mechanism is evident (no csrf/xsrf token in the session cookies, response body,
    or a X-CSRF/X-XSRF header). If SameSite is Lax/Strict OR a token mechanism exists -> rejected (mitigated).
    Conservative by design: a real forged-request test would modify state, so we assess posture only."""
    def __init__(self, set_cookies=None, body="", resp_headers=None, *, oracle_id="csrf@1", surface=""):
        self.cookies = list(set_cookies or [])
        self.body = str(body or "")
        self.h = {str(k).lower() for k in dict(resp_headers or {}).keys()}
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        import re as _re
        session_cookies = [c for c in self.cookies
                           if any(t in c.split("=", 1)[0].lower() for t in ("session", "sess", "sid", "auth", "jwt", "token"))]
        samesite_protected = any(_re.search(r"samesite\s*=\s*(lax|strict)", c, _re.I) for c in session_cookies)
        # anti-CSRF token evidence: a csrf/xsrf cookie, a token in the body, or a csrf header exposed
        token_cookie = any(_re.search(r"(csrf|xsrf)", c, _re.I) for c in self.cookies)
        token_body = _re.search(r"(csrf|xsrf)[-_]?token", self.body, _re.I) is not None
        token_header = any("csrf" in h or "xsrf" in h for h in self.h)
        has_token = token_cookie or token_body or token_header
        exposed = bool(session_cookies) and (not samesite_protected) and (not has_token)
        return ("verified" if exposed else "rejected"), {
            "surface": self.surface, "samesite_protected": samesite_protected, "anti_csrf_token": has_token,
            "session_cookie_seen": bool(session_cookies),
            "note": ("no SameSite protection and no anti-CSRF token (CSRF exposed)" if exposed else
                     ("SameSite Lax/Strict on the session cookie (mitigated)" if samesite_protected else
                      ("anti-CSRF token present" if has_token else "no session cookie to assess")))}


class SecurityHeadersOracle(Oracle):
    """Missing cookie flags + security response headers (commercial-parity passive check). VERIFIED (a
    weakness) iff a SESSION cookie is missing HttpOnly/Secure/SameSite, OR >=2 key security headers are
    absent (CSP, HSTS, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy). A single
    missing header alone is reported but does NOT verify (too noisy / low value). Reads only."""
    _SESSION_COOKIE_HINTS = ("session", "sess", "sid", "connect.sid", "token", "auth", "jwt", "csrftoken")

    def __init__(self, headers, set_cookies=None, *, over_https=True, oracle_id="secheaders@1", surface=""):
        # headers: case-insensitive dict-like; set_cookies: list of raw Set-Cookie header values
        self.h = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
        self.cookies = list(set_cookies or [])
        self.over_https = over_https
        self.id = oracle_id
        self.surface = surface

    def check(self, finding=None):
        # GUARD: no response captured (leg failed / target down) -> CANNOT ASSESS, not "all headers missing".
        # Without this an empty headers dict counts all 5 as absent and FALSELY verifies a misconfig.
        if not self.h and not self.cookies:
            return "rejected", {"surface": self.surface, "note": "no response headers/cookies to assess",
                                "n_issues": 0, "missing_headers": []}
        issues = []
        # 1) session-cookie flags
        for c in self.cookies:
            name = c.split("=", 1)[0].strip().lower()
            if not any(h in name for h in self._SESSION_COOKIE_HINTS):
                continue
            low = c.lower()
            # A CSRF double-submit token cookie is READ by JS and legitimately lacks HttpOnly/SameSite --
            # flagging it is a false positive (Pass 4 #20). Only Secure is still meaningful for it.
            is_csrf = "csrf" in name or "xsrf" in name
            flag_checks = ((("Secure", "secure"),) if is_csrf
                           else (("HttpOnly", "httponly"), ("SameSite", "samesite"), ("Secure", "secure")))
            miss = [flag for flag, tok in flag_checks if tok not in low]
            if not self.over_https and "Secure" in miss:
                miss.remove("Secure")                    # Secure is only meaningful over HTTPS
            for m in miss:
                issues.append({"kind": "cookie_flag", "detail": f"session cookie {name!r} missing {m}",
                               "severity": "medium"})
        # 2) security headers
        header_checks = [("content-security-policy", "CSP"), ("strict-transport-security", "HSTS"),
                         ("x-content-type-options", "X-Content-Type-Options"),
                         ("x-frame-options", "X-Frame-Options"), ("referrer-policy", "Referrer-Policy")]
        missing_headers = [label for key, label in header_checks if key not in self.h
                           and not (label == "X-Frame-Options" and "frame-ancestors" in self.h.get("content-security-policy", ""))]
        for label in missing_headers:
            issues.append({"kind": "missing_header", "detail": f"missing {label}", "severity": "low"})
        cookie_issue = any(i["kind"] == "cookie_flag" for i in issues)
        weakness = cookie_issue or (len(missing_headers) >= 2)
        sev = "medium" if cookie_issue else ("low" if weakness else "info")
        return ("verified" if weakness else "rejected"), {
            "surface": self.surface, "severity": sev, "n_issues": len(issues),
            "missing_headers": missing_headers, "issues": issues[:10],
            "note": ("session-cookie flag(s) missing" if cookie_issue else
                     (f"{len(missing_headers)} security headers missing" if weakness else "headers acceptable"))}


class RateLimitOracle(Oracle):
    """MISSING RATE-LIMIT / anti-automation on a SENSITIVE endpoint (auth/login/reset/OTP) -- enables
    brute-force / credential-stuffing. Given the statuses of N rapid IDENTICAL requests, VERIFIED (a
    weakness) iff: the endpoint is sensitive, the server PROCESSED all N (each got a real handled status,
    not a transport error) and NONE was a throttle/lockout signal (429 Too Many Requests, 503 with
    Retry-After, or 423 Locked). FP guard: needs >= min_attempts processed; a single 429 anywhere ->
    rejected (throttling present). Non-destructive: the caller uses a NONEXISTENT identity so no real
    account is locked; N is bounded so the burst can't be a DoS."""
    _THROTTLE = {429, 423, 503}
    # credential-submission endpoints: no-rate-limit HERE is where brute-force/stuffing actually bites
    _CRED_EP = ("login", "signin", "sign-in", "auth/token", "/token", "reset", "forgot", "otp",
                "verify", "2fa", "mfa", "register", "password")

    def __init__(self, statuses, *, endpoint="", min_attempts=10, oracle_id="ratelimit@1"):
        self.statuses = [int(s) for s in (statuses or [])]
        self.endpoint = endpoint
        self.min_attempts = min_attempts
        self.id = oracle_id

    def check(self, finding=None):
        processed = [s for s in self.statuses if s and s > 0]
        throttled = [s for s in processed if s in self._THROTTLE]
        enough = len(processed) >= self.min_attempts
        weakness = enough and not throttled
        # A3 severity-gate: an endpoint that ALREADY denies the anon caller (every processed status is 401/403)
        # and is NOT a credential-submission endpoint is a SOFT positive -- rate-limiting it prevents no
        # meaningful brute-force (you'd need a valid session first). Keep it verified (there IS no throttle)
        # but downgrade to low so it doesn't read as MEDIUM (the g57full /logout+/me soft-positive). Login/
        # reset/OTP keep full weight -- that's exactly where guessing matters.
        all_denied = bool(processed) and all(s in (401, 403) for s in processed)
        is_cred = any(k in (self.endpoint or "").lower() for k in self._CRED_EP)
        soft = weakness and all_denied and not is_cred
        sev = "low" if soft else "medium"
        return ("verified" if weakness else "rejected"), {
            "endpoint": self.endpoint, "attempts": len(self.statuses), "processed": len(processed),
            "throttle_seen": bool(throttled), "throttle_statuses": sorted(set(throttled)),
            "status_histogram": {s: processed.count(s) for s in sorted(set(processed))},
            "severity": sev, "soft_positive": soft,
            "note": (("no throttle after %d rapid requests to a sensitive endpoint (brute-force feasible)"
                      % len(processed)) + (" [soft: endpoint already denies anon -> low]" if soft else "")
                     if weakness else
                     ("throttled (rate-limit present)" if throttled else "not enough processed attempts"))}


def _median(xs):
    s = sorted(float(x) for x in xs if x is not None)
    if not s:
        return None
    n = len(s); m = n // 2
    return s[m] if n % 2 else (s[m - 1] + s[m]) / 2.0


def _mad(xs, med=None):
    """Median absolute deviation (robust noise floor)."""
    s = [float(x) for x in xs if x is not None]
    if not s:
        return None
    med = _median(s) if med is None else med
    return _median([abs(x - med) for x in s])


class BruteForceFeasibilityOracle(Oracle):
    """D8: SYNTHESIZE credential brute-force FEASIBILITY for a {name,PIN}/password login from the CONTROLS
    observed -- the rate-limit verdict (throttle present?), the credential KEYSPACE, and the account-LOCKOUT
    threshold. This turns 'no rate limit' (a precondition) into an actionable VERDICT ('brute-forceable in
    ~N expected guesses'). VERIFIED (feasible) iff there is NO effective limiter: no throttle AND no lockout
    below the keyspace, for a non-empty keyspace. Derivation only -- no new traffic (consumes RateLimitOracle
    output + a known/measured keyspace + lockout). Severity scales with how small the keyspace is."""
    def __init__(self, *, keyspace, throttled, lockout_threshold=None, req_per_sec=None,
                 oracle_id="bruteforce@1", surface=""):
        self.keyspace = int(keyspace or 0)
        self.throttled = bool(throttled)
        self.lockout = lockout_threshold      # None = no account-lockout observed
        self.rps = req_per_sec
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        expected = (self.keyspace // 2) if self.keyspace else None
        limited = self.throttled or (self.lockout is not None and self.keyspace and self.lockout < self.keyspace)
        feasible = (self.keyspace > 0) and (not limited)
        sev = ("high" if (feasible and self.keyspace <= 10 ** 6)
               else ("medium" if feasible else "info"))
        eta = (expected / max(self.rps, 1e-3)) if (feasible and expected and self.rps) else None
        return ("verified" if feasible else "rejected"), {
            "surface": self.surface, "severity": sev, "keyspace": self.keyspace,
            "expected_guesses": expected, "throttle_present": self.throttled,
            "lockout_threshold": self.lockout, "eta_seconds": eta,
            "note": (f"brute-forceable: no effective limiter, ~{expected} expected guesses over keyspace "
                     f"{self.keyspace}" + (f" (~{eta:.0f}s @ {self.rps}/s)" if eta else "")
                     if feasible else
                     (f"limited (throttle={self.throttled}, lockout={self.lockout}) -> not feasible"
                      if limited else "keyspace unknown -> inconclusive"))}


class UserEnumerationOracle(Oracle):
    """D8: username ENUMERATION via a differential between a VALID and an INVALID identifier on a login/reset/
    register endpoint. Signals: status code, response body, or TIMING (a valid name that triggers a DB lookup
    + bcrypt is measurably slower than an invalid one that returns early). VERIFIED iff status or body differ,
    OR a ROBUST timing separation: |median(valid)-median(invalid)| >= k*MAD(noise) with >= min_samples each.
    Timing-only is the weakest arm (jitter-prone) so it requires the k*MAD margin. Read-only."""
    def __init__(self, *, valid_statuses=None, invalid_statuses=None, valid_body="", invalid_body="",
                 valid_latencies=None, invalid_latencies=None, k_mad=6.0, min_samples=5,
                 min_delta_ms=5.0, oracle_id="userenum@1", surface=""):
        self.vs = list(valid_statuses or []); self.is_ = list(invalid_statuses or [])
        self.vb = str(valid_body or ""); self.ib = str(invalid_body or "")
        self.vl = list(valid_latencies or []); self.il = list(invalid_latencies or [])
        self.k = float(k_mad); self.min_samples = int(min_samples); self.min_delta = float(min_delta_ms)
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        status_diff = bool(self.vs) and bool(self.is_) and set(self.vs) != set(self.is_)
        body_diff = bool(self.vb) and bool(self.ib) and self.vb.strip() != self.ib.strip()
        timing = False; delta = mad = None
        if len(self.vl) >= self.min_samples and len(self.il) >= self.min_samples:
            mv, mi = _median(self.vl), _median(self.il)
            # noise floor >= 1ms so zero-variance (rounded/synthetic) samples can't make any tiny delta fire;
            # AND require a real absolute delta (>= min_delta_ms) -- sub-ms separation is jitter, not bcrypt.
            noise = max((_mad(self.vl) or 0.0), (_mad(self.il) or 0.0), 1.0)
            delta = abs(mv - mi); mad = noise
            timing = (delta >= self.k * noise) and (delta >= self.min_delta)
        verified = status_diff or body_diff or timing
        arms = [a for a, on in (("status", status_diff), ("body", body_diff), ("timing", timing)) if on]
        sev = "medium" if verified else "info"
        return ("verified" if verified else "rejected"), {
            "surface": self.surface, "severity": sev, "signals": arms,
            "timing_delta": delta, "timing_noise_mad": mad,
            "timing_ratio": (delta / mad if (delta is not None and mad) else None),
            "note": ("enumerable via " + "+".join(arms) +
                     (f" (timing {delta:.1f} vs {mad:.1f} MAD)" if timing else "")
                     if verified else "no valid/invalid differential (status+body+timing indistinct)")}


class PinPolicyOracle(Oracle):
    """D8: weak PIN/password POLICY. Given the PIN length + charset (and, if observed, whether a known-weak
    value was ACCEPTED at set/change), VERIFIED iff the policy is weak: keyspace below the safe threshold
    (a short numeric PIN), or a weak value was accepted. Feeds BruteForceFeasibility's keyspace estimate."""
    _CHARSET = {"digits": 10, "alnum": 36, "alnum_case": 62}

    def __init__(self, *, length=None, charset="digits", weak_accepted=None,
                 safe_keyspace=10 ** 8, oracle_id="pinpolicy@1", surface=""):
        self.length = length; self.charset = charset
        self.weak_accepted = weak_accepted
        self.safe = int(safe_keyspace)
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        base = self._CHARSET.get(self.charset, 10)
        keyspace = base ** int(self.length) if self.length else None
        weak = bool(self.weak_accepted) or (keyspace is not None and keyspace < self.safe)
        sev = "high" if (weak and keyspace and keyspace <= 10 ** 6) else ("medium" if weak else "info")
        return ("verified" if weak else "rejected"), {
            "surface": self.surface, "severity": sev, "length": self.length, "charset": self.charset,
            "keyspace": keyspace, "weak_value_accepted": self.weak_accepted,
            "note": (f"weak policy: {self.charset} x{self.length} = keyspace {keyspace}"
                     + (" ; weak value accepted" if self.weak_accepted else "")
                     if weak else "policy meets the keyspace threshold")}


class CanaryCallbackOracle(Oracle):
    """X: DETERMINISTIC proof of blind egress / exfil -- a UNIQUE canary token planted in the probe was
    observed at an out-of-band sink (DNS/HTTP callback, or reflected into a log/DB we control). VERIFIED
    iff the exact token was seen at the sink. HIGH-CONFIDENCE (oracle_confidence='high'): a callback is
    unforgeable ground truth, so this single oracle is sufficient for a HIGH (the A1 gate honors it). This
    is the form the old 2-shape {HTTP,SELECT} taxonomy could never express -> unlocks blind SSRF, blind
    injection exfil, OOB cmdi. Read-only w.r.t. the target; the token is the proof."""
    def __init__(self, token, sink_observations, *, oracle_id="canary@1", surface=""):
        self.token = str(token or ""); self.hits = [str(x) for x in (sink_observations or [])]
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        hit = bool(self.token) and any(self.token in h for h in self.hits)
        return ("verified" if hit else "rejected"), {
            "surface": self.surface, "severity": "high", "oracle_confidence": "high",
            "token": self.token[:16], "sink_hits": len(self.hits),
            "note": ("canary callback observed at OOB sink (deterministic blind-exfil proof)" if hit
                     else "no canary callback at the sink -> not confirmed")}


class TimingDifferentialOracle(Oracle):
    """X: generic TIME-BLIND / timing side-channel (blind injection with a sleep payload, etc.). Given
    BASELINE latencies (calibration) and TEST latencies (with the delay payload), VERIFIED iff
    median(test)-median(baseline) >= max(k*MAD(noise), min_delta_ms) with >= min_samples each -- the same
    robust gate as the user-enum timing arm, with a >=1ms noise floor AND an absolute min-delta so jitter
    can't fire. NOT high-confidence alone (timing is inherently probabilistic) -> stays under the >=2-oracle
    HIGH cap; pair it with a canary/DB witness for HIGH."""
    def __init__(self, baseline_latencies, test_latencies, *, k_mad=6.0, min_samples=3, min_delta_ms=250.0,
                 oracle_id="timing@1", surface=""):
        self.b = list(baseline_latencies or []); self.t = list(test_latencies or [])
        self.k = float(k_mad); self.min_samples = int(min_samples); self.min_delta = float(min_delta_ms)
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        if len(self.b) < self.min_samples or len(self.t) < self.min_samples:
            return "inconclusive", {"surface": self.surface, "severity": "medium",
                                    "note": "not enough samples to calibrate timing"}
        mb, mt = _median(self.b), _median(self.t)
        noise = max((_mad(self.b) or 0.0), (_mad(self.t) or 0.0), 1.0)
        delta = mt - mb
        hit = (delta >= self.k * noise) and (delta >= self.min_delta)
        return ("verified" if hit else "rejected"), {
            "surface": self.surface, "severity": "medium", "delta_ms": delta, "noise_mad": noise,
            "note": (f"time-blind separation: +{delta:.0f}ms vs {noise:.0f}ms MAD floor" if hit
                     else f"no timing separation (+{delta:.0f}ms < gate)")}


class SstiOracle(Oracle):
    """#5: SERVER-SIDE TEMPLATE INJECTION / expression-language eval. Inject an ARITHMETIC MARKER the server
    can only produce if it EVALUATED the template ({{a*b}} / ${a*b} / #{a*b} / <%= a*b %>). VERIFIED iff the
    response contains the PRODUCT (a*b) AND NOT the literal expression -- proving evaluation, not reflection.
    Use a distinctive operand pair (large primes) so the product can't occur naturally. HIGH-confidence
    deterministic (the product is unforgeable without eval). Non-destructive (arithmetic only)."""
    def __init__(self, expr, product, response_body, *, oracle_id="ssti@1", surface="", param=""):
        self.expr = str(expr); self.product = str(product); self.body = str(response_body or "")
        self.id = oracle_id; self.surface = surface; self.param = param

    def check(self, finding=None):
        evaluated = bool(self.product) and (self.product in self.body) and (self.expr not in self.body)
        return ("verified" if evaluated else "rejected"), {
            "surface": self.surface, "param": self.param, "severity": "high", "oracle_confidence": "high",
            "expr": self.expr, "product": self.product,
            "note": (f"template EVALUATED {self.expr} -> {self.product} in response (SSTI confirmed)" if evaluated
                     else "no evaluation (expression reflected literally or absent)")}


class SecretsOracle(Oracle):
    """SECRETS / PII / stack-traces leaked in a RESPONSE (commercial-parity passive check). Deterministic
    regex over a response body; verified iff >=1 HIGH-confidence secret pattern matches (private keys, AWS/
    cloud keys, JWTs, bearer/api tokens, connection strings) or a clear server stack-trace. Low-confidence
    PII (emails) is reported but does NOT alone verify (too noisy). Reads only -- non-destructive."""
    # (name, regex, high_confidence). Kept tight to limit false positives.
    _PATTERNS = [
        ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", True),
        ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", True),
        ("aws_secret", r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}", True),
        ("gcp_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", True),
        ("slack_token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}", True),
        ("github_pat", r"\bghp_[0-9A-Za-z]{36}\b", True),
        ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", True),
        ("bearer_token", r"(?i)\b(?:authorization|bearer|api[_-]?key|secret|token|password)\b\s*[=:]\s*[\"']?[A-Za-z0-9\-_./+]{16,}", True),
        ("conn_string", r"(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^\s:@/]+:[^\s:@/]+@", True),
        ("stack_trace", r"(?:Traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+\.java:\d+\)|\b[\w./]+\.(?:py|js|ts|rb|go):\d+\b.{0,40}(?:Error|Exception))", True),
        ("pii_email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", False),
    ]

    def __init__(self, body, *, surface="", status=None, oracle_id="secrets@1", allow_pii_only=False):
        self.body = body or ""
        self.surface = surface
        self.status = status
        self.id = oracle_id
        self.allow_pii_only = allow_pii_only

    def check(self, finding=None):
        import re as _re
        hits, high = [], False
        for name, rx, hi in self._PATTERNS:
            try:
                m = _re.search(rx, self.body)
            except Exception:
                m = None
            if m:
                snip = (m.group(0) or "")[:12]
                hits.append({"kind": name, "high_confidence": hi, "sample": snip + "..."})
                high = high or hi
        verdict = "verified" if (high or (self.allow_pii_only and hits)) else "rejected"
        return verdict, {"surface": self.surface, "status": self.status, "n_hits": len(hits),
                         "kinds": sorted({h["kind"] for h in hits}), "hits": hits[:8],
                         "note": ("high-confidence secret/PII leaked in response" if high else
                                  ("only low-confidence PII (not verified alone)" if hits else "no secrets found"))}


class IdorOracle(Oracle):
    """BROKEN OBJECT-LEVEL AUTHZ (IDOR / BOLA) -- object-level, not surface-level (that is AuthzOracle). A
    non-owner role reads/writes a SPECIFIC object it should not, even on a surface it may generally reach.
    Verified only on FP-resistant, distinguishing signals per object:
      (1) the OWNER role gets the object (2xx)                  -- the object exists,
      (2) the ATTACKER role gets 2xx for the SAME object AND its body MATCHES the owner's body
          (same object id -> same bytes)                        -- the attacker actually read THAT object,
      (3) a CONTROL request (a nonexistent object id) as the attacker is DENIED/404
          (not a blanket 2xx)                                   -- the endpoint distinguishes existence,
          so a catch-all/SPA 200 cannot masquerade as access.
    `observations` = [{id, role, owner_status, attacker_status, owner_sha, attacker_sha, control_status}].
    Non-destructive: reads by default (GET); a write/BOLA variant plants-for-proof, never erases."""
    def __init__(self, observations, *, denied=(401, 403, 404), intended=None, oracle_id="idor@1", surface=""):
        self.obs = observations or []
        self.denied = set(denied)
        # PER-OBJECT intended allow-map: a role legitimately permitted a SPECIFIC object is not IDOR
        # (e.g. a dispatcher may read jobs dispatched to them, but not others). `intended` is a
        # {object_id: [roles]} dict OR a callable(object_id)->[roles]; a per-observation `intended_roles`
        # list is honoured too. Without it a legitimately-scoped read would be mis-flagged as over-reach.
        self.intended = intended
        self.id = oracle_id
        self.surface = surface

    def _role_intended(self, o):
        role = str(o.get("role") or "").lower()
        if not role:
            return False
        allowed = {str(r).lower() for r in (o.get("intended_roles") or [])}
        oid = o.get("id")
        m = self.intended
        if callable(m):
            try:
                allowed |= {str(r).lower() for r in (m(oid) or [])}
            except Exception:
                pass
        elif isinstance(m, dict):
            allowed |= {str(r).lower() for r in (m.get(oid, []) or [])}
        return role in allowed

    def check(self, finding=None):
        leads = []; intended_skipped = 0
        for o in self.obs:
            if self._role_intended(o):   # role legitimately permitted THIS object -- not IDOR
                intended_skipped += 1
                continue
            owner_ok = 200 <= int(o.get("owner_status", 0)) < 300
            atk_ok = 200 <= int(o.get("attacker_status", 0)) < 300
            same_obj = bool(o.get("owner_sha")) and o.get("owner_sha") == o.get("attacker_sha")
            control_denied = int(o.get("control_status", 0)) in self.denied
            if owner_ok and atk_ok and same_obj and control_denied:
                leads.append({"id": o.get("id"), "role": o.get("role"),
                              "attacker_status": o.get("attacker_status"),
                              "owner_status": o.get("owner_status"),
                              "control_status": o.get("control_status"),
                              "verb": o.get("verb", "GET")})
        verdict = "verified" if leads else "rejected"
        return verdict, {"surface": self.surface, "n_leads": len(leads), "leads": leads[:8],
                         "checked": len(self.obs), "intended_skipped": intended_skipped,
                         "note": ("object-level over-reach confirmed (attacker read the owner's object; "
                                  "control id denied)" if leads else
                                  "no object-level over-reach above the FP guards")}


class IdorCrossUserOracle(Oracle):
    """DIRECT-OBJECT IDOR/BOLA where there is no owner-vs-attacker byte comparison to make (no collection to
    enumerate an owner from) -- e.g. juice-shop's GET /rest/basket/{id}. A SINGLE attacker identity walks the
    object id space and the tell is that it reads objects OWNED BY OTHER users. VERIFIED iff, on 2xx reads,
    the attacker saw objects belonging to a FOREIGN owner (owner != the attacker's own id) OR to >=2 DISTINCT
    owners, AND a nonexistent-id CONTROL was denied -- so a public catch-all endpoint that 200s everything
    cannot masquerade as access. `reads` = [{id, status, owner}] where owner is the object's owner-id parsed
    from the body. Reads only (GET) -> non-destructive."""
    def __init__(self, reads, *, attacker_owner=None, control_denied=True, oracle_id="idor-xuser@1", surface=""):
        self.reads = reads or []
        self.attacker_owner = None if attacker_owner is None else str(attacker_owner)
        self.control_denied = bool(control_denied)
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        ok = [r for r in self.reads if 200 <= int(r.get("status", 0)) < 300 and r.get("owner") is not None]
        owners = {str(r["owner"]) for r in ok}
        foreign = owners - ({self.attacker_owner} if self.attacker_owner else set())
        cross = (bool(foreign) if self.attacker_owner else len(owners) >= 2)
        if not self.control_denied:
            return "inconclusive", {"why": "nonexistent-id control also returned data -- endpoint looks "
                                    "public, not object-scoped", "surface": self.surface,
                                    "reads_ok": len(ok), "distinct_owners": len(owners)}
        if cross:
            return "verified", {"why": "attacker read objects owned by other users by walking the id space",
                                "distinct_owners": len(owners), "foreign_owners": sorted(foreign)[:5],
                                "reads_ok": len(ok), "surface": self.surface}
        return "rejected", {"why": "no cross-user reads (only own object, or all denied)",
                            "surface": self.surface, "reads_ok": len(ok), "distinct_owners": len(owners)}


class DifferentialOracle(Oracle):
    """MECH 2 -- oracle-diversity / DIFFERENTIAL discovery: read MANY signals on the SAME interaction across
    VARIANTS (role/session/order/concurrency) and flag a DELTA a human never computes -- status, body-hash,
    body-SIZE, JSON field-ORDER, response LATENCY (timing side-channel). NOISE-FLOOR gated: a latency delta
    counts only if it exceeds the baseline variant's own k-sample noise (median + MAD) AND a fraction of the
    median; a size delta only if it exceeds a fraction of the body. Emits a LEAD (not a verified finding) --
    per board doctrine, a lead promotes to verified only when a SECOND oracle confirms."""
    def __init__(self, observations, noise, *, latency_k_mad=6.0, size_floor_frac=0.05,
                 oracle_id="differential@1", surface=""):
        self.obs = observations or {}       # {variant: {status, latency_ms, body_len, body_sha, field_order}}
        self.noise = noise or {}            # {latency_med, latency_mad} from k baseline repeats
        self.latency_k_mad = latency_k_mad; self.size_floor_frac = size_floor_frac
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        vs = list(self.obs.items())
        leads = []
        med = float(self.noise.get("latency_med", 0.0))
        mad = max(float(self.noise.get("latency_mad", 0.0)), 1.0)
        for i in range(len(vs)):
            for j in range(i + 1, len(vs)):
                (va, oa), (vb, ob) = vs[i], vs[j]
                if oa.get("status") != ob.get("status"):
                    leads.append({"metric": "status", "a": va, "b": vb,
                                  "va": oa.get("status"), "vb": ob.get("status")})
                if oa.get("body_sha") != ob.get("body_sha"):
                    da = abs((oa.get("body_len") or 0) - (ob.get("body_len") or 0))
                    if da > self.size_floor_frac * max(oa.get("body_len") or 1, ob.get("body_len") or 1):
                        leads.append({"metric": "body_size", "a": va, "b": vb, "delta_bytes": da})
                    elif oa.get("field_order") != ob.get("field_order"):
                        leads.append({"metric": "field_order", "a": va, "b": vb})
                dl = abs((oa.get("latency_ms") or 0) - (ob.get("latency_ms") or 0))
                if dl > self.latency_k_mad * mad and dl > 0.2 * med:      # timing side-channel, noise-gated
                    leads.append({"metric": "latency", "a": va, "b": vb, "delta_ms": round(dl, 1),
                                  "noise_mad": round(mad, 1)})
        verdict = "lead" if leads else "rejected"
        return verdict, {"surface": self.surface, "leads": leads[:8], "n_leads": len(leads),
                         "noise": {"latency_med": round(med, 1), "latency_mad": round(mad, 1)},
                         "variants": {v: {"status": o.get("status"),
                                          "latency_ms": round(o.get("latency_ms") or 0, 1),
                                          "body_len": o.get("body_len")} for v, o in self.obs.items()}}


# ---- G54: breadth-closing oracles for the Prisma/Express blind spots (board-designed) ----
class NestedWriteOracle(Oracle):
    """PRISMA NESTED-WRITE OVER-POST -- a create/update accepts a client-supplied NESTED relation/field the
    caller must not set (data:{relation:{connect|create}}, or a forbidden scalar). VERIFIED iff, after a
    create that INJECTED the forbidden nested value with a distinctive marker, the read-back row carries it
    (persisted) AND the caller's role is NOT permitted that relation/field. Non-destructive: create+read only.
    (Mass-assignment through a relation edge; distinct from the flat MassAssignOracle.)"""
    def __init__(self, created_obj, injected, *, role_permitted=False, control_obj=None,
                 oracle_id="nestedwrite@1", surface=""):
        self.obj = created_obj if isinstance(created_obj, dict) else {}
        self.injected = injected or {}          # {relation_or_field: marker_value}
        self.role_permitted = bool(role_permitted)
        self.control = control_obj if isinstance(control_obj, dict) else None
        self.id = oracle_id; self.surface = surface

    def _get(self, obj, path):
        cur = obj
        for seg in str(path).split("."):
            if isinstance(cur, dict):
                cur = cur.get(seg)
            else:
                return None
        return cur

    def check(self, finding=None):
        if self.role_permitted:
            return "rejected", {"why": "role is permitted this relation/field (not a bug)", "surface": self.surface}
        leaked = []
        for path, marker in self.injected.items():
            got = self._get(self.obj, path)
            if got is None:
                continue
            if str(marker) in str(got) or str(got) == str(marker):
                if self.control is not None and str(self._get(self.control, path)) == str(got):
                    continue                    # a legitimate default, not our injection
                leaked.append({"path": path, "persisted": str(got)[:80]})
        if leaked:
            return "verified", {"nested_over_post": leaked, "surface": self.surface}
        return "rejected", {"why": "injected nested relation/field was not persisted", "surface": self.surface}


class FieldLeakOracle(Oracle):
    """FIELD-LEVEL OVER-EXPOSURE -- a read response returns fields a role should NOT see. VERIFIED iff the
    body contains a DENYLISTED sensitive field with a non-empty value, OR a field present for the low role
    that is ABSENT from that role's policy but present for owner (role-diff). Read-only; SPA-shell guarded."""
    _DENY = ("passwordhash", "password", "pin", "pinhash", "token", "sessiontoken", "resettoken", "secret",
             "apikey", "api_key", "mfasecret", "otp", "ssn", "sortcode", "iban", "cardnumber", "cvv",
             "privatekey", "clientsecret", "refreshtoken")

    def __init__(self, body, *, role="", owner_extra_fields=None, is_spa=False, oracle_id="fieldleak@1", surface=""):
        self.body = body
        self.role = role
        self.owner_extra = set(owner_extra_fields or [])   # fields the low role got that only owner should
        self.is_spa = is_spa
        self.id = oracle_id; self.surface = surface

    def _keys(self, obj, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                out.add(str(k).lower()); self._keys(v, out)
        elif isinstance(obj, list):
            for it in obj[:50]:
                self._keys(it, out)

    def check(self, finding=None):
        if self.is_spa:
            return "rejected", {"why": "SPA shell / not a real handler body", "surface": self.surface}
        keys = set()
        try:
            self._keys(self.body if isinstance(self.body, (dict, list)) else json.loads(self.body), keys)
        except Exception:
            return "rejected", {"why": "non-JSON body", "surface": self.surface}
        hits = sorted(k for k in keys if any(d in k for d in self._DENY))
        if hits:
            return "verified", {"leaked_sensitive_fields": hits, "role": self.role, "surface": self.surface}
        rolediff = sorted(f.lower() for f in self.owner_extra if f.lower() in keys)
        if rolediff:
            return "verified", {"role_diff_fields": rolediff, "role": self.role,
                                "why": "fields exposed to a role that should not see them", "surface": self.surface}
        return "rejected", {"why": "no denylisted or over-scoped field", "surface": self.surface}


class FilterInjectionOracle(Oracle):
    """PRISMA FILTER/OPERATOR INJECTION -- untrusted query params reach where/orderBy/select/take/skip so a
    caller widens scope past their authorization. VERIFIED iff the injected response returns row ids NOT in
    the caller's baseline set AND those extra ids are DB-CONFIRMED to belong to another owner/scope (a real
    scope bypass). Rejected if the id-set is unchanged (filter ignored/sanitised). Read-only."""
    def __init__(self, baseline_ids, injected_ids, cross_scope_ids, *, oracle_id="filterinjection@1", surface=""):
        self.baseline = set(map(str, baseline_ids or []))
        self.injected = set(map(str, injected_ids or []))
        self.cross = set(map(str, cross_scope_ids or []))   # DB-confirmed to belong to another owner
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        extra = self.injected - self.baseline
        confirmed = sorted(extra & self.cross)
        if confirmed:
            return "verified", {"scope_bypass_ids": confirmed[:20], "extra_count": len(extra),
                                "surface": self.surface}
        if extra and not self.cross:
            return "inconclusive", {"why": "widened id-set but cross-owner not DB-confirmed",
                                    "extra_count": len(extra), "surface": self.surface}
        return "rejected", {"why": "filter ignored/sanitised (id-set unchanged)", "surface": self.surface}


class SqlRawOracle(Oracle):
    """RAW SQL INJECTION into a Prisma $queryRaw/$executeRaw handler. Boolean-differential, SELECT-only:
    a TRUE condition returns the baseline rows, a FALSE condition returns none of them, and a clean control
    matches the TRUE set -- proving the string was concatenated into SQL and evaluated. DB-confirmed to rule
    out app-level filtering. VERIFIED iff true!=false, true~control, and DB confirms the injection fired."""
    def __init__(self, true_ids, false_ids, control_ids, *, db_confirmed=False, oracle_id="sqlraw@1", surface=""):
        self.t = set(map(str, true_ids or []))
        self.f = set(map(str, false_ids or []))
        self.c = set(map(str, control_ids or []))
        self.db_confirmed = bool(db_confirmed)
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        distinguishable = bool(self.t) and (self.t != self.f) and not (self.t & self.f and self.f - self.t == set() and self.t - self.f == set())
        true_vs_false = bool(self.t) and (self.f < self.t or not (self.f & self.t)) and self.t != self.f
        control_ok = (not self.c) or (self.c == self.t) or (len(self.c & self.t) >= max(1, len(self.t) // 2))
        if true_vs_false and control_ok and self.db_confirmed:
            return "verified", {"true_rows": len(self.t), "false_rows": len(self.f),
                                "control_rows": len(self.c), "surface": self.surface}
        if true_vs_false and control_ok and not self.db_confirmed:
            return "inconclusive", {"why": "boolean differential but DB causation not confirmed",
                                    "surface": self.surface}
        return "rejected", {"why": "no boolean differential (param not reaching SQL)", "surface": self.surface}


class SqlAuthBypassOracle(Oracle):
    """SQL injection in an AUTHENTICATION handler (login) -- the shape the boolean-differential SqlRawOracle
    misses. The identity field is concatenated into the auth WHERE clause, so a TAUTOLOGY payload (`' OR 1=1--`)
    short-circuits it and the server issues a valid SESSION for an account the attacker never authenticated to.
    VERIFIED iff: the tautology injection yields an auth token/identity, the SAME endpoint with a bogus
    (non-injected) credential does NOT, AND a FALSE-condition injection (`' OR 1=2--`) also does NOT -- proving
    it is the injected boolean, not a credential, that grants the session. A session you never earned is a
    high-confidence deterministic catch, so it carries the sqlraw@ family id and needs no separate DB witness."""
    def __init__(self, *, bypass_authed, baseline_authed, control_authed, token_sample="",
                 oracle_id="sqlraw@authbypass", surface=""):
        self.bypass = bool(bypass_authed)      # ' OR 1=1--   -> authenticated?
        self.baseline = bool(baseline_authed)  # bogus cred, no injection -> authenticated?
        self.control = bool(control_authed)    # ' OR 1=2--   -> authenticated?
        self.token = str(token_sample or "")
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        # the injected TAUTOLOGY grants a session that neither a bogus credential nor a FALSE injection does
        if self.bypass and not self.baseline and not self.control:
            return "verified", {"why": "tautology login-injection issued a session; bogus credential and "
                                "false-condition injection did not", "surface": self.surface,
                                "token_seen": bool(self.token)}
        if self.bypass and self.control:
            return "inconclusive", {"why": "both true- and false-condition injections authenticated -- an "
                                    "auth bug, but not injection-boolean-controlled", "surface": self.surface}
        if self.bypass and self.baseline:
            return "inconclusive", {"why": "bogus credential ALSO authenticated -- broken auth, not an "
                                    "injection oracle", "surface": self.surface}
        return "rejected", {"why": "tautology injection did not yield a session (param not reaching auth SQL)",
                            "surface": self.surface}


class JwtForgeryOracle(Oracle):
    """JWT signature-bypass forgery (build-target 4): the server accepts a token the attacker MINTED
    without the signing key -- classically `alg:none` (strip the signature) or RS256->HS256 confusion
    (verify an RS256 token with HS256 using the PUBLIC key as the HMAC secret). This is the juice-shop
    broken-auth-jwt class the generic oracles miss.

    Designed to AVOID the round-2 novel-code FP class (a bare 200 is not proof): VERIFIED requires a
    differential AND a positive identity witness --
      * forged_authed:   the forged token is accepted as a PRIVILEGED identity (2xx + privileged data), AND
      * control_denied:  the SAME request with NO token / a random token is denied (401/403), AND
      * identity_match:   the response reflects the FORGED claims (the injected sub/role/email) -- proving
                          the server trusted the forged, unsigned identity, not a public fallback.
    A single unforgeable-key bypass is a high-confidence deterministic catch (like SqlAuthBypass), so it
    carries a jwt@ family id and needs no separate DB witness."""
    def __init__(self, *, forged_authed, control_denied, identity_match, vector="alg:none",
                 token_sample="", oracle_id="jwt@forgery", surface=""):
        self.forged = bool(forged_authed)          # minted token -> accepted as privileged?
        self.control_denied = bool(control_denied) # no/random token -> denied?
        self.identity_match = bool(identity_match)  # response reflects the FORGED sub/role?
        self.vector = str(vector or "alg:none")     # "alg:none" | "rs256->hs256"
        self.token = str(token_sample or "")
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        if self.forged and self.control_denied and self.identity_match:
            return "verified", {"why": f"forged {self.vector} token accepted as the forged identity; "
                                "no-token/random-token control was denied", "surface": self.surface,
                                "vector": self.vector, "token_seen": bool(self.token)}
        # identity_match is the real witness: if the forged token did NOT impersonate the forged
        # identity, the forgery FAILED and the defense held -> REJECTED, whether the app answered 401
        # or a bad-token 200-empty (juice-shop's shape). (Live-refine: was 'inconclusive' before.)
        if self.forged and not self.identity_match:
            return "rejected", {"why": "forged token did not impersonate the forged identity "
                                "(401 or a bad-token 200-empty) -- signature/claim validation held",
                                "surface": self.surface, "vector": self.vector}
        # identity reflected BUT the no-token control ALSO got in -> the endpoint is unauthenticated,
        # which is a different (broken-access) finding, not a signature-forgery win.
        if self.forged and not self.control_denied:
            return "inconclusive", {"why": "response reflects the forged identity BUT the no-token "
                                    "control was also accepted -- endpoint unauthenticated, not a "
                                    "signature bypass", "surface": self.surface, "vector": self.vector}
        return "rejected", {"why": "forged token rejected outright -- signature verification is working",
                            "surface": self.surface, "vector": self.vector}


class DbOracle(Oracle):
    """Run a SQL query via docker-exec psql and assert the single scalar result matches.
    'verified' iff the returned value matches expected_regex."""
    def __init__(self, container, user, db, sql, expected_regex, *,
                 pgpassword="", oracle_id="db@1"):
        self.container, self.user, self.db, self.sql = container, user, db, sql
        self.expected_regex, self.pgpassword, self.id = expected_regex, pgpassword, oracle_id
    def check(self, finding: Finding):
        cmd = ["docker", "exec", "-e", f"PGPASSWORD={self.pgpassword}", self.container,
               "psql", "-U", self.user, "-d", self.db, "-t", "-A", "-c", self.sql]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
        except Exception as e:
            return "inconclusive", {"error": repr(e)[:200]}
        ok = bool(re.search(self.expected_regex, out))
        return ("verified" if ok else "rejected"), {"query": self.sql, "result": out[:200],
                                                     "expected_regex": self.expected_regex}

# ---------- verifier ----------
class Verifier:
    """The ONLY component that transitions a finding to verified/rejected. Agents submit
    candidates + evidence; the verifier runs an out-of-band oracle and records the receipt."""
    def __init__(self, store: FindingStore):
        self.store = store
    @staticmethod
    def _build(fd: dict) -> Finding:
        """Construct a Finding from a (possibly malformed) store entry without a cryptic TypeError:
        keep only known fields and ensure the two REQUIRED ones exist (item 41)."""
        data = {k: fd[k] for k in fd if k in Finding.__dataclass_fields__}
        data.setdefault("claim_type", "unknown")
        data.setdefault("summary", "")
        return Finding(**data)

    @staticmethod
    def _dedupe_oracles(oracles: list) -> list:
        """Distinct oracles by id -- so CONSENSUS cannot be gamed by passing the same oracle twice (item 18)."""
        seen, uniq = set(), []
        for o in oracles:
            oid = getattr(o, "id", None) or id(o)
            if oid in seen:
                continue
            seen.add(oid); uniq.append(o)
        return uniq

    @staticmethod
    def _safe_check(oracle, finding):
        """Run one oracle's check; a failing oracle becomes an 'inconclusive' receipt, never an abort
        of the whole run (item 40)."""
        try:
            return oracle.check(finding)
        except Exception as e:
            return "inconclusive", {"error": str(e)[:200], "oracle_error": True,
                                    "oracle": getattr(oracle, "id", "?")}

    def verify(self, finding_id: str, oracle: Oracle) -> dict:
        fd = self.store.findings().get(finding_id)
        if not fd: raise KeyError(finding_id)
        finding = self._build(fd)
        status, receipt = self._safe_check(oracle, finding)
        self.store._transition(finding_id, status, oracle.id, receipt)
        return self.store.findings()[finding_id]

    def verify_consensus(self, finding_id: str, oracles: list, min_confirm: int = 2) -> dict:
        """Multi-oracle CONSENSUS gate (v3): a HIGH/CRITICAL finding is moved to `verified` ONLY when
        at least `min_confirm` INDEPENDENT oracles agree; lower severities need one. Every oracle's
        receipt is recorded. Oracles are DEDUPED by id (no gaming with duplicates) and each check is
        isolated (one failing oracle can't abort consensus). Stops one lucky/gamed oracle verifying HIGH."""
        fd = self.store.findings().get(finding_id)
        if not fd: raise KeyError(finding_id)
        finding = self._build(fd)
        oracles = self._dedupe_oracles(oracles)
        sev = (getattr(finding, "severity", "") or "").lower()
        need = min_confirm if sev in ("high", "critical") else 1
        confirms, receipts = 0, []
        confirm_classes = set()                       # DISTINCT oracle CLASSES that confirmed
        for oracle in oracles:
            st, rc = self._safe_check(oracle, finding)
            receipts.append({"oracle": getattr(oracle, "id", "?"), "status": st, "receipt": rc})
            if st == "verified":
                confirms += 1
                confirm_classes.add(type(oracle).__name__)
        # CLASS-INDEPENDENT consensus (board fix): a HIGH/CRITICAL needs `need` confirmations from DISTINCT
        # oracle CLASSES -- two checks of the SAME class (or a re-run/echo) are ONE independent signal, not
        # two. Lower severities still need one. This stops a single signal self-confirming a HIGH.
        independent = len(confirm_classes)
        status = "verified" if (independent >= need if sev in ("high", "critical") else confirms >= need) else "rejected"
        oid = "+".join(getattr(o, "id", "?") for o in oracles) or "consensus"
        self.store._transition(finding_id, status, oid,
                               {"confirms": confirms, "independent_classes": sorted(confirm_classes),
                                "need": need, "severity": sev, "receipts": receipts})
        return self.store.findings()[finding_id]
