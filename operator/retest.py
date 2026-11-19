"""retest.py -- ARTEX-port A2: the automated vulnerability RETEST loop.

Promotes the old hand-written `record_retest_findings.py` (a manual log) into a real agent. Given a
verified finding that carries an A1 proof exchange (bytes stored in the content-addressed EvidenceStore),
it RE-FIRES that exact request against the current target and decides:

    still_reproducible | fixed | cannot_confirm

and APPENDS the verdict via FindingStore.record_retest -- the finding's original status and evidence are
never mutated (so 'fixed' never erases the proof it was once real). This is the stage-10 closed loop:
after a fix is applied to the mirror, retest tells you whether the weakness is actually gone.

Two mechanisms:
  * replay (default, general): no oracle object is stored with a finding, so we replay the bound proof
    request and compare the response against the one we captured when it was confirmed.
  * oracle (programmatic): a caller may pass a live Oracle to re-run its exact predicate instead.

Non-destructive: replays only the request we already made at discovery (usually a GET/read proof).
Contained-mirror doctrine unchanged. CLI:  python operator/retest.py --store f.jsonl --id <fid> [--base https://host:port]
"""
from __future__ import annotations
import os, sys, argparse
from urllib.parse import urlsplit, urlunsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "shared"))
sys.path.insert(0, HERE)
from verified_findings import FindingStore, EvidenceStore, replay, _sha256  # noqa: E402


def _rebase(url: str, base: str) -> str:
    """Point a stored request URL at a (possibly) different origin for retest, keeping path+query."""
    if not base:
        return url
    b, u = urlsplit(base), urlsplit(url)
    return urlunsplit((b.scheme or u.scheme, b.netloc or u.netloc, u.path, u.query, u.fragment))


def _bodies_similar(a: str, b: str) -> bool:
    a, b = a or "", b or ""
    if _sha256(a) == _sha256(b):
        return True
    if not a and not b:
        return True
    if a[:120] == b[:120] and abs(len(a) - len(b)) <= max(32, int(0.1 * max(len(a), 1))):
        return True
    return False


def _proof_evidence(finding: dict) -> dict | None:
    """The exchange to replay: prefer role=proof, else the first bound http exchange."""
    bound = finding.get("bound_evidence") or []
    for ev in bound:
        if ev.get("role") == "proof":
            return ev
    return bound[0] if bound else None


def retest_finding(store: FindingStore, finding_id: str, *, base: str | None = None,
                   oracle=None, record: bool = True) -> tuple[str, dict]:
    """Return (verdict, receipt) and (by default) append it to the store. verdict in VALID_RETEST."""
    finding = store.findings().get(finding_id)
    if finding is None:
        raise KeyError(f"no finding {finding_id!r} in {store.path}")

    # Mechanism 2: a live oracle was supplied -> re-run its exact predicate.
    if oracle is not None:
        from verified_findings import Finding
        status, oreceipt = oracle.check(Finding(**{k: finding[k] for k in
            ("claim_type", "summary") if k in finding}))
        verdict = {"verified": "still_reproducible", "rejected": "fixed"}.get(status, "cannot_confirm")
        receipt = {"mechanism": "oracle", "oracle_id": getattr(oracle, "id", ""), "status": status,
                   "detail": oreceipt}
        if record:
            store.record_retest(finding_id, verdict, receipt)
        return verdict, receipt

    # Mechanism 1 (default): replay the bound proof exchange and compare to the captured response.
    ev = _proof_evidence(finding)
    if not ev:
        receipt = {"mechanism": "replay", "error": "no bound proof exchange (A1 evidence) to replay"}
        if record:
            store.record_retest(finding_id, "cannot_confirm", receipt)
        return "cannot_confirm", receipt

    sha = ev["artifact_sha256"]
    stored = EvidenceStore().get(sha) or {}
    orig = stored.get("response", {})
    orig_status = int(orig.get("status") or ev.get("status") or 0)
    orig_body = orig.get("body", "")
    override = {"url": _rebase(ev.get("url", ""), base)} if base else None
    try:
        r = replay(sha, override=override)
    except Exception as e:
        receipt = {"mechanism": "replay", "sha": sha, "error": str(e)[:200], "unreachable": True}
        if record:
            store.record_retest(finding_id, "cannot_confirm", receipt)
        return "cannot_confirm", receipt

    ns, nbody = r.status_code, (r.text or "")
    orig_2xx, new_2xx = 200 <= orig_status < 300, 200 <= ns < 300
    similar = _bodies_similar(orig_body, nbody)
    if orig_2xx:
        # an access/success proof: still reproducible only if it still succeeds with a like response
        if new_2xx and similar:
            verdict = "still_reproducible"
        elif ns in (401, 403) or not new_2xx:
            verdict = "fixed"
        else:
            verdict = "cannot_confirm"
    else:
        # a proof keyed on a specific non-2xx response (e.g. a body signature): reproduced iff it recurs
        verdict = "still_reproducible" if (ns == orig_status and similar) else "fixed"

    receipt = {"mechanism": "replay", "sha": sha, "url": _rebase(ev.get("url", ""), base),
               "orig_status": orig_status, "new_status": ns, "body_similar": similar,
               "orig_body_sha256": _sha256(orig_body), "new_body_sha256": _sha256(nbody)}
    if record:
        store.record_retest(finding_id, verdict, receipt)
    return verdict, receipt


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Automated retest of a verified finding by replaying its proof.")
    ap.add_argument("--store", required=True, help="path to the findings JSONL store")
    ap.add_argument("--id", required=True, help="finding_id to retest")
    ap.add_argument("--base", default=None, help="optional target base (scheme://host:port) to replay against")
    ap.add_argument("--no-record", action="store_true", help="print the verdict without appending it")
    a = ap.parse_args(argv)
    store = FindingStore(a.store)
    verdict, receipt = retest_finding(store, a.id, base=a.base, record=not a.no_record)
    print(f"[retest] {a.id} -> {verdict}")
    for k in ("orig_status", "new_status", "body_similar", "error"):
        if k in receipt:
            print(f"  {k}: {receipt[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
