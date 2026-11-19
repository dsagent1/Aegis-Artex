"""_deception_tests.py -- #4 deceptive-target robustness self-test.

Proves the oracle layer REFUSES to be fooled by deceptive / honeypot targets (ATOBench-style): a weak
(deceivable) oracle only reaches 'clean' when a benign NEGATIVE CONTROL stays silent; a ground-truth
oracle (canary OOB) is never fooled by an always-success honeypot. Stdlib only, in-process mocks, no
network. Run:  python shared/_deception_tests.py
"""
import sys, os, random, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "operator"))
import verified_findings as vf          # noqa: E402
import deception as dc                  # noqa: E402

_PASS = 0


def ok(cond, label):
    global _PASS
    assert cond, "FAIL: " + label
    _PASS += 1
    print("PASS", label)


def _guard(oracle_id, probe, control=None):
    return dc.guard_oracle(oracle_id, probe, control)


def test_reflection_oracle():
    atk = "<script>alert(1)</script>"
    # honest vulnerable: attack reflects, benign control does NOT -> clean (a real differential signal)
    g = _guard("reflect@body",
               lambda: dc.sig_reflection(dc.honest_vulnerable(atk), atk),
               lambda: dc.sig_reflection(dc.honest_vulnerable(dc._BENIGN), dc._BENIGN))
    ok(g.verdict == "clean" and g.trustworthy, "reflection on HONEST-vuln -> clean (trustworthy)")
    # honeypot that reflects EVERYTHING: attack reflects AND benign control reflects -> deceptive
    g = _guard("reflect@body",
               lambda: dc.sig_reflection(dc.deceptive_reflect_everything(atk), atk),
               lambda: dc.sig_reflection(dc.deceptive_reflect_everything(dc._BENIGN), dc._BENIGN))
    ok(g.verdict == "deceptive" and not g.trustworthy, "reflection on REFLECT-EVERYTHING honeypot -> deceptive")
    # honest safe: attack does not reflect -> negative (no finding at all)
    g = _guard("reflect@body",
               lambda: dc.sig_reflection(dc.honest_safe(atk), atk),
               lambda: dc.sig_reflection(dc.honest_safe(dc._BENIGN), dc._BENIGN))
    ok(g.verdict == "negative", "reflection on HONEST-safe -> negative (no false finding)")


def test_status_oracle_is_non_differential():
    # a bare 'status==200' oracle is worthless: every target 200s. The negative control catches that the
    # signal cannot distinguish -> deceptive, so no false 'verified' is ever emitted off it.
    sig = lambda r: r.get("status") == 200
    g = _guard("status@200",
               lambda: sig(dc.deceptive_always_success("' OR 1=1 -- ")),
               lambda: sig(dc.deceptive_always_success(dc._BENIGN)))
    ok(g.verdict == "deceptive" and not g.trustworthy, "always-200 honeypot caught by status control")


def test_canned_banner_oracle():
    g = _guard("bannererr@body",
               lambda: dc.sig_error_banner(dc.deceptive_canned_banner("' OR 1=1 -- ")),
               lambda: dc.sig_error_banner(dc.deceptive_canned_banner(dc._BENIGN)))
    ok(g.verdict == "deceptive" and not g.trustworthy, "canned fake-vuln banner caught by control")


def test_timing_oracle():
    # honest time-based blind: attack sleeps (900ms), benign is fast (20ms) -> clean
    g = _guard("timing@blind",
               lambda: dc.sig_timing(dc.honest_vulnerable("sleep(1)")),
               lambda: dc.sig_timing(dc.honest_vulnerable(dc._BENIGN)))
    ok(g.verdict == "clean", "honest time-based blind -> clean")
    # noisy honeypot: random latency. Over trials the benign control frequently also crosses the
    # threshold -> the guard flags deceptive (never reliably 'clean'), so a lone timing read is not trusted.
    random.seed(7)
    verdicts = [_guard("timing@blind",
                       lambda: dc.sig_timing(dc.deceptive_timing_noise("sleep(1)")),
                       lambda: dc.sig_timing(dc.deceptive_timing_noise(dc._BENIGN))).verdict
                for _ in range(40)]
    ok("deceptive" in verdicts, "noisy-timing honeypot flagged deceptive on control collision")
    ok(sum(v == "clean" for v in verdicts) < 40, "noisy-timing honeypot NOT reliably clean (untrusted)")


def test_untested_when_no_control():
    # a deceivable oracle that fires with NO control supplied -> 'untested' (held below verified)
    g = _guard("reflect@body",
               lambda: dc.sig_reflection(dc.deceptive_reflect_everything("x"), "x"))
    ok(g.verdict == "untested" and not g.trustworthy, "deceivable oracle, no control -> untested (suspect)")


def test_ground_truth_oracle_not_fooled():
    dc._OOB.clear()
    ssrf = "http://oob/ping?t=" + "abc"
    # honeypot: calling it does NOT populate the OOB channel -> canary never returns -> negative (not fooled)
    dc.deceptive_always_success(ssrf)
    g = _guard("canary@oob", lambda: dc.sig_canary_oob(ssrf))      # no control needed: ground-truth
    ok(g.verdict == "negative", "canary/OOB oracle on honeypot -> negative (honeypot cannot fake the witness)")
    # honest vulnerable: the server REALLY fetches the canary URL -> token returns OOB -> clean, high-conf
    dc._OOB.clear()
    dc.honest_vulnerable(ssrf)
    g = _guard("canary@oob", lambda: dc.sig_canary_oob(ssrf))
    ok(g.verdict == "clean" and g.high_conf, "canary/OOB oracle on honest-vuln -> clean (ground truth, exempt)")


def test_helpers():
    ok(vf.oracle_is_deceivable(["status@200", "reflect@body"]), "oracle_is_deceivable: all weak -> True")
    ok(not vf.oracle_is_deceivable(["status@200", "canary@oob"]), "oracle_is_deceivable: a ground-truth -> False")
    ok(vf.deception_verdict(True, True) == "deceptive", "deception_verdict pos+control -> deceptive")
    ok(vf.deception_verdict(True, False) == "clean", "deception_verdict pos+clean-control -> clean")
    ok(vf.deception_verdict(True, None) == "untested", "deception_verdict pos+no-control -> untested")
    ok(vf.deception_verdict(True, True, high_conf=True) == "clean", "deception_verdict high-conf exempt -> clean")
    ok(vf.deception_verdict(False, None) == "negative", "deception_verdict no-signal -> negative")


def test_fold_integration():
    # a weak-oracle 'verified' carrying a 'deceptive' receipt -> fold forces disagreement, confidence collapses
    d = tempfile.mkdtemp()
    st = vf.FindingStore(os.path.join(d, "f.jsonl"))
    fid = st.record_candidate(vf.Finding(claim_type="xss.reflected", summary="x", severity="high"))
    st._transition(fid, "verified", "reflect@body",
                   dc.guard_oracle("reflect@body", lambda: True, lambda: True).as_receipt())
    f = st.findings()[fid]
    ok(f["deception"] == "deceptive", "fold: deceptive verdict surfaced on finding")
    ok(f["disagreement"] is True, "fold: deceptive weak-oracle forces disagreement")
    ok(f["confidence"] <= 0.6, "fold: deceptive finding confidence collapsed (%.3f)" % f["confidence"])
    # same receipt but a GROUND-TRUTH oracle clears it (a canary can't be deceived)
    fid2 = st.record_candidate(vf.Finding(claim_type="ssrf.oob", summary="x", severity="high"))
    st._transition(fid2, "verified", "canary@oob", {"deception": "clean"})
    f2 = st.findings()[fid2]
    ok(not f2["disagreement"] and f2["high_confidence_oracle"], "fold: ground-truth oracle not deception-flagged")
    ok(st.verify_chain(), "fold: hash chain intact after deception receipts")


def main():
    for t in (test_reflection_oracle, test_status_oracle_is_non_differential, test_canned_banner_oracle,
              test_timing_oracle, test_untested_when_no_control, test_ground_truth_oracle_not_fooled,
              test_helpers, test_fold_integration):
        t()
    print("\n%d/%d PASS" % (_PASS, _PASS))


if __name__ == "__main__":
    main()
