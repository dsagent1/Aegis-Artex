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
from verified_findings import FindingStore, EvidenceStore, replay, _sha256, verify_quote  # noqa: E402


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
                   oracle=None, fixed_version: str | None = None, conditions: str | None = None,
                   record: bool = True) -> tuple[str, dict]:
    """Return (verdict, receipt) and (by default) append it to the store. verdict in VALID_RETEST.
    A2 EXTENSION: `fixed_version`/`conditions` label the retest context (e.g. the framework bump a fix
    targets) and are stamped into every receipt -- so a later report can say which patch state was tested.
    When the proof carried a verbatim quote (A1), a 'still_reproducible' additionally requires the quote to
    survive on replay (a response that no longer contains the proving string is treated as fixed)."""
    finding = store.findings().get(finding_id)
    if finding is None:
        raise KeyError(f"no finding {finding_id!r} in {store.path}")

    _ctx = {k: v for k, v in (("fixed_version", fixed_version), ("conditions", conditions)) if v}

    # Mechanism 2: a live oracle was supplied -> re-run its exact predicate.
    if oracle is not None:
        from verified_findings import Finding
        status, oreceipt = oracle.check(Finding(**{k: finding[k] for k in
            ("claim_type", "summary") if k in finding}))
        verdict = {"verified": "still_reproducible", "rejected": "fixed"}.get(status, "cannot_confirm")
        receipt = {"mechanism": "oracle", "oracle_id": getattr(oracle, "id", ""), "status": status,
                   "detail": oreceipt, **_ctx}
        if record:
            store.record_retest(finding_id, verdict, receipt)
        return verdict, receipt

    # Mechanism 1 (default): replay the bound proof exchange and compare to the captured response.
    ev = _proof_evidence(finding)
    if not ev:
        receipt = {"mechanism": "replay", "error": "no bound proof exchange (A1 evidence) to replay", **_ctx}
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
        receipt = {"mechanism": "replay", "sha": sha, "error": str(e)[:200], "unreachable": True, **_ctx}
        if record:
            store.record_retest(finding_id, "cannot_confirm", receipt)
        return "cannot_confirm", receipt

    ns, nbody = r.status_code, (r.text or "")
    orig_2xx, new_2xx = 200 <= orig_status < 300, 200 <= ns < 300
    similar = _bodies_similar(orig_body, nbody)
    # A1/A2 EXTENSION: if the proof bound a verbatim quote, the quote must still be present for the proof to
    # still hold -- a response that dropped the proving string is a fix even if the status/shape look alike.
    quote = ev.get("quote") or ""
    quote_survives = verify_quote(ev, nbody) if quote else None
    if orig_2xx:
        # an access/success proof: still reproducible only if it still succeeds with a like response
        if new_2xx and similar and quote_survives is not False:
            verdict = "still_reproducible"
        elif ns in (401, 403) or not new_2xx or quote_survives is False:
            verdict = "fixed"
        else:
            verdict = "cannot_confirm"
    else:
        # a proof keyed on a specific non-2xx response (e.g. a body signature): reproduced iff it recurs
        recurs = (ns == orig_status and similar and quote_survives is not False)
        verdict = "still_reproducible" if recurs else "fixed"

    receipt = {"mechanism": "replay", "sha": sha, "url": _rebase(ev.get("url", ""), base),
               "orig_status": orig_status, "new_status": ns, "body_similar": similar,
               "orig_body_sha256": _sha256(orig_body), "new_body_sha256": _sha256(nbody), **_ctx}
    if quote:
        receipt["quote_survives"] = bool(quote_survives)
    if record:
        store.record_retest(finding_id, verdict, receipt)
    return verdict, receipt


def retest_all(store: FindingStore, *, base: str | None = None, fixed_version: str | None = None,
               conditions: str | None = None, status: str = "verified",
               record: bool = True) -> dict:
    """A2 EXTENSION: batch-retest every finding in the store with the given status (default 'verified') by
    replaying each bound proof. Returns {finding_id: (verdict, receipt)} plus a 'summary' tally. Each retest
    is independent + append-only; one unreachable finding never aborts the batch."""
    out, tally = {}, {"still_reproducible": 0, "fixed": 0, "cannot_confirm": 0}
    for fid, f in store.findings().items():
        if status and f.get("status") != status:
            continue
        try:
            v, rc = retest_finding(store, fid, base=base, fixed_version=fixed_version,
                                   conditions=conditions, record=record)
        except Exception as e:
            v, rc = "cannot_confirm", {"error": str(e)[:200]}
        out[fid] = (v, rc)
        tally[v] = tally.get(v, 0) + 1
    out["summary"] = tally
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Automated retest of a verified finding by replaying its proof.")
    ap.add_argument("--store", required=True, help="path to the findings JSONL store")
    ap.add_argument("--id", default=None, help="finding_id to retest (omit with --all)")
    ap.add_argument("--all", action="store_true", help="retest EVERY verified finding in the store")
    ap.add_argument("--base", default=None, help="optional target base (scheme://host:port) to replay against")
    ap.add_argument("--fixed-version", default=None, help="label: the fixed version/patch state being tested")
    ap.add_argument("--conditions", default=None, help="label: free-text retest conditions")
    ap.add_argument("--no-record", action="store_true", help="print the verdict without appending it")
    a = ap.parse_args(argv)
    store = FindingStore(a.store)
    if a.all:
        res = retest_all(store, base=a.base, fixed_version=a.fixed_version, conditions=a.conditions,
                         record=not a.no_record)
        for fid, rv in res.items():
            if fid == "summary":
                continue
            print(f"[retest] {fid} -> {rv[0]}")
        print(f"[retest] summary: {res['summary']}")
        return 0
    if not a.id:
        ap.error("--id is required unless --all is given")
    verdict, receipt = retest_finding(store, a.id, base=a.base, fixed_version=a.fixed_version,
                                      conditions=a.conditions, record=not a.no_record)
    print(f"[retest] {a.id} -> {verdict}")
    for k in ("orig_status", "new_status", "body_similar", "quote_survives", "error"):
        if k in receipt:
            print(f"  {k}: {receipt[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
