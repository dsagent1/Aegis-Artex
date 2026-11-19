"""_artex_port_tests.py -- durable tests for the ARTEX-port capabilities (A1/A2/B1/B2).

Stdlib + a throwaway local HTTP server only (no external network, no mirror). Run:
    python shared/_artex_port_tests.py
"""
import sys, os, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "operator"))
import verified_findings as vf  # noqa: E402

_PASS = 0


def ok(cond, label):
    global _PASS
    assert cond, "FAIL: " + label
    _PASS += 1
    print("PASS", label)


def _server(handler_body):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            handler_body(self)
        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_a1_evidence_store_and_capture():
    import requests
    d = tempfile.mkdtemp(); os.environ["AEGIS_EVIDENCE_DIR"] = os.path.join(d, "ev")
    st = vf.EvidenceStore()
    ev = vf.capture_exchange(method="GET", url="https://x/api/s", req_body={"a": 1},
                             status=200, resp_body='{"ok":true}', role="proof")
    ok(ev.artifact_sha256 and ev.role == "proof" and ev.status == 200, "A1 capture_exchange populates sha+role+meta")
    ok(st.get(ev.artifact_sha256)["request"]["method"] == "GET", "A1 EvidenceStore.get returns the exchange")
    ok(st.put(st.get(ev.artifact_sha256)) == ev.artifact_sha256 and len(os.listdir(st.path)) == 1, "A1 content-addressed dedup (write-once)")
    try:
        vf.capture_exchange(method="GET", url="x", role="bogus"); bad = False
    except ValueError:
        bad = True
    ok(bad, "A1 invalid role rejected")


def test_a1_replay_roundtrip():
    import requests
    d = tempfile.mkdtemp(); os.environ["AEGIS_EVIDENCE_DIR"] = os.path.join(d, "ev")
    seen = {"n": 0}
    def body(h):
        seen["n"] += 1; h.send_response(200); h.end_headers(); h.wfile.write(b"hello")
    srv, base = _server(body)
    r = requests.get(base + "/probe", timeout=5)
    ev = vf._maybe_capture(r, "proof")
    r2 = vf.replay(ev["artifact_sha256"])
    ok(r2.status_code == 200 and seen["n"] == 2, "A1 replay re-fires the stored request from bytes")
    srv.shutdown()


def test_a2_retest_fixed_and_immutable():
    import requests
    from retest import retest_finding
    d = tempfile.mkdtemp(); os.environ["AEGIS_EVIDENCE_DIR"] = os.path.join(d, "ev")
    state = {"code": 200}
    def body(h):
        c = state["code"]; h.send_response(c); h.end_headers(); h.wfile.write(b'{"s":1}' if c == 200 else b'no')
    srv, base = _server(body)
    r = requests.get(base + "/api/settings", timeout=5)
    store = vf.FindingStore(os.path.join(d, "f.jsonl"))
    fid = store.record_candidate(vf.Finding(claim_type="authz.role_overreach", summary="x", severity="high"))
    store._transition(fid, "verified", "authz@1", {"evidence": [vf._maybe_capture(r, "proof")]})
    v1, _ = retest_finding(store, fid, base=base)
    state["code"] = 403
    v2, _ = retest_finding(store, fid, base=base)
    cur = store.findings()[fid]
    ok(v1 == "still_reproducible" and v2 == "fixed", "A2 retest: reproducible -> fixed")
    ok(cur["status"] == "verified" and len(cur["retests"]) == 2 and store.verify_chain(), "A2 original status immutable, chain intact, retests logged")
    srv.shutdown()


def test_b1_noise_governor_gating():
    import importlib
    os.environ["AEGIS_NOISE_PROFILE"] = "balanced"
    os.environ["AEGIS_TARGET"] = "http://127.0.0.1:9"
    import noise; importlib.reload(noise)
    ok(noise.install() and noise.status()["profile"] == "balanced", "B1 governor installs when profile set")
    ok(noise._should_pace("127.0.0.1:9") and not noise._should_pace("api.deepseek.com"), "B1 paces target host only, not LLM/API hosts")
    os.environ.pop("AEGIS_NOISE_PROFILE"); os.environ.pop("AEGIS_TARGET")


def test_b2_poe_grades():
    ok(vf.grade_poe("rejected", 3, True, 5) == 0, "B2 poe 0 when not verified")
    ok(vf.grade_poe("verified", 1, False, 0) == 1, "B2 poe 1 = verified, claim only")
    ok(vf.grade_poe("verified", 1, False, 1) == 2, "B2 poe 2 = + bound exchange")
    ok(vf.grade_poe("verified", 2, False, 0) == 3, "B2 poe 3 = 2 independent confirmations")
    ok(vf.grade_poe("verified", 2, False, 1) == 4, "B2 poe 4 = corroborated AND replayable")


def test_backcompat_legacy_finding():
    d = tempfile.mkdtemp(); os.environ["AEGIS_EVIDENCE_DIR"] = os.path.join(d, "ev")
    store = vf.FindingStore(os.path.join(d, "f.jsonl"))
    # a finding recorded before the new fields existed still loads + folds + grades
    fid = store.record_candidate(vf.Finding(claim_type="x", summary="legacy", severity="low"))
    store._transition(fid, "verified", "http@1", {})
    cur = store.findings()[fid]
    ok(cur["poe"] == 1 and cur["traffic_count"] == 0 and store.verify_chain(), "back-compat: legacy finding folds, poe=1, no evidence")


if __name__ == "__main__":
    for t in (test_a1_evidence_store_and_capture, test_a1_replay_roundtrip, test_a2_retest_fixed_and_immutable,
              test_b1_noise_governor_gating, test_b2_poe_grades, test_backcompat_legacy_finding):
        t()
    print(f"\n{_PASS}/{_PASS} PASS")
