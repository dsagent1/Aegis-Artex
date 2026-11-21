"""_capture_tests.py -- tests for ARTEX-port #1 (authenticated-traffic capture -> hunt).

Stdlib + a synthetic HAR fixture only (no network, no mirror). Run:
    python operator/_capture_tests.py
"""
import sys, os, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "shared"))
import capture as cap  # noqa: E402

_PASS = 0


def ok(cond, label):
    global _PASS
    assert cond, "FAIL: " + label
    _PASS += 1
    print("PASS", label)


BASE = "https://t.example"
HAR = {"log": {"entries": [
    {"startedDateTime": "2026-11-21T00:00:00Z",
     "request": {"method": "GET", "url": BASE + "/rest/user/whoami",
                 "headers": [{"name": "Authorization", "value": "Bearer JWT123"},
                             {"name": "Cookie", "value": "token=JWT123; lang=en"}],
                 "cookies": [{"name": "token", "value": "JWT123"}]},
     "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                  "content": {"text": '{"email":"u@t"}'}}},
    {"request": {"method": "GET", "url": BASE + "/api/Users/42",
                 "headers": [{"name": "Authorization", "value": "Bearer JWT123"}]},
     "response": {"status": 200, "headers": [], "content": {"text": '{"id":42}'}}},
    {"request": {"method": "GET", "url": BASE + "/main.js", "headers": []},
     "response": {"status": 200, "content": {"text": "x"}}},
    {"request": {"method": "GET", "url": "https://evil.example/track",
                 "headers": [{"name": "Authorization", "value": "Bearer OFFHOST-SECRET"}]},
     "response": {"status": 200, "content": {"text": ""}}},
]}}


def test_parse():
    ex = cap.parse_har(HAR)
    ok(len(ex) == 4 and ex[0]["method"] == "GET", "parse_har: all entries normalized")
    ok(ex[0]["req_headers"].get("Authorization") == "Bearer JWT123", "parse_har: request headers parsed")
    ok(ex[0]["resp_body"] == '{"email":"u@t"}', "parse_har: response body extracted")


def test_ingest_evidence_offhost_excluded():
    d = tempfile.mkdtemp(); os.environ["AEGIS_EVIDENCE_DIR"] = os.path.join(d, "ev")
    import verified_findings as vf
    st = vf.EvidenceStore()
    b = cap.ingest(cap.parse_har(HAR), store=st, base=BASE)
    ok(b["n"] == 3, "ingest: off-host (evil.example) exchange excluded from evidence")
    ok(all(e["artifact_sha256"] for e in b["evidence"]), "ingest: every exchange bound in EvidenceStore")


def test_auth_and_session():
    auth = cap.extract_auth(cap.parse_har(HAR), base=BASE)
    ok(auth["cookies"].get("token") == "JWT123" and auth["cookies"].get("lang") == "en",
       "extract_auth: cookies lifted (Cookie header + HAR cookies)")
    ok(auth["headers"].get("Authorization") == "Bearer JWT123", "extract_auth: bearer header lifted")
    ok("OFFHOST-SECRET" not in str(auth), "extract_auth: off-host auth NOT folded into target session (hygiene)")
    sf = cap.session_factory(auth, BASE)
    s_owner, s_anon = sf("owner"), sf("anon")
    ok(s_owner.headers.get("Authorization") == "Bearer JWT123" and s_owner.cookies.get("token") == "JWT123",
       "session_factory: authenticated role carries captured bearer + cookies")
    ok(s_anon.headers.get("Authorization") is None and s_anon.cookies.get("token") is None,
       "session_factory: anon role is UNAUTHENTICATED (AuthzOracle baseline)")


def test_endpoints_and_seeds():
    eps = cap.endpoints(cap.parse_har(HAR), base=BASE)
    paths = {e["path"] for e in eps}
    ok(paths == {"/rest/user/whoami", "/api/Users/42"}, "endpoints: static + off-host dropped, real routes kept")
    ok(any(e["path"] == "/api/Users/42" and e["id_bearing"] for e in eps), "endpoints: id-bearing surface flagged")
    seeds = cap.seeds_from_endpoints(eps, role="owner")
    sh = [s for s in seeds if s["action"] == "security_headers"]
    idor = [s for s in seeds if s["action"] == "idor"]
    ok(len(sh) == 2, "seeds: a security-headers probe per real surface")
    ok(len(idor) == 1 and idor[0]["collection"] == "/api/Users" and idor[0]["surface"] == "/api/Users/42"
       and idor[0]["role"] == "owner", "seeds: IDOR sweep seeded on the id-bearing surface, collection parent")
    ok(all(s["seed"] == "capture" for s in seeds), "seeds: tagged seed='capture'")


def test_load_bundle():
    d = tempfile.mkdtemp(); os.environ["AEGIS_EVIDENCE_DIR"] = os.path.join(d, "ev")
    b = cap.load_capture(HAR, base=BASE, role="owner")
    ok(b["authenticated"] and callable(b["session_for_role"]) and b["seeds"] and b["endpoints"],
       "load_capture: one-call bundle (authenticated, session_for_role, seeds, endpoints)")


if __name__ == "__main__":
    for t in (test_parse, test_ingest_evidence_offhost_excluded, test_auth_and_session,
              test_endpoints_and_seeds, test_load_bundle):
        t()
    print(f"\n{_PASS}/{_PASS} PASS")
