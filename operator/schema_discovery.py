#!/usr/bin/env python3
"""schema_discovery.py -- learn an endpoint's REAL field contract so probes send WELL-FORMED payloads.

The payoff run showed the last ceiling: probes now execute (G26) against real endpoints (G25) but the
handlers reject them 400 SCHEMA-INVALID -- the coders don't know each endpoint's field shape, so they can't
build a payload the handler ACCEPTS (2xx) and then mis-processes. This closes that: authenticate, GET a real
record from the endpoint, and hand the coder the exact field shape + a redacted example, so it MUTATES a
valid record into the exploit ("read-then-mutate") instead of guessing the schema.

Doctrine: read-only discovery (GET), authenticated with the real accounts (same session as the harness),
contained mirror only, no secrets echoed (values are typed/trimmed, obvious secret-ish keys redacted).
Offline-safe: any failure -> None, and the driver simply proceeds without a schema hint.
"""
import os, json, re, time

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "schema_cache.json")
_SECRETISH = re.compile(r"pass|pin|secret|token|hash|salt|key|otp|card|cvv", re.I)


def endpoint_of(hypothesis):
    """Extract the /api/... path a hypothesis targets, from its surface/target/code_task."""
    for k in ("surface", "target", "code_task", "mechanism"):
        v = str((hypothesis or {}).get(k) or "")
        m = re.search(r"/api/[a-zA-Z0-9/_.-]+", v)
        if m:
            return re.sub(r"/+$", "", m.group(0).split("?")[0])
    return None


def _list_path(endpoint):
    """The collection path to GET a sample from (strip a trailing /:id or sub-action to the base collection)."""
    parts = [p for p in endpoint.split("/") if p]          # e.g. api, credit-notes, :id
    if len(parts) >= 2:
        return "/" + "/".join(parts[:2])                    # /api/credit-notes
    return endpoint


def _typ(v):
    if isinstance(v, bool): return "bool"
    if isinstance(v, int): return f"int(e.g. {v})"
    if isinstance(v, float): return f"number(e.g. {v})"
    if isinstance(v, str):
        s = "date" if re.match(r"\d{4}-\d\d-\d\d", v) else "str"
        return f"{s}(e.g. {v[:24]})" if len(v) <= 40 else f"{s}(len {len(v)})"
    if isinstance(v, list): return f"array[{_typ(v[0]) if v else 'any'}]"
    if isinstance(v, dict): return "object{" + ",".join(list(v.keys())[:6]) + "}"
    if v is None: return "null"
    return type(v).__name__


def _shape(rec):
    """Field shape of one record: key -> type/sample, with secret-ish values redacted."""
    out = {}
    for k, v in list(rec.items())[:40]:
        out[k] = "<redacted>" if _SECRETISH.search(k) else _typ(v)
    return out


def _load_cache():
    try:
        return json.load(open(CACHE, encoding="utf-8"))
    except Exception:
        return {}


def discover(endpoint, role="owner", ttl=1800):
    """Return {endpoint, list_path, fields:{k:type}, example:{...}} for an endpoint, or None. Cached per
    (list_path, role) for ttl seconds. GET-only, authenticated via the harness login (real accounts)."""
    if not endpoint:
        return None
    lp = _list_path(endpoint)
    key = f"{role}:{lp}"
    cache = _load_cache()
    hit = cache.get(key)
    if hit and (time.time() - hit.get("_ts", 0)) < ttl:
        return hit
    methods = []
    ids = []
    try:
        import test_suggestions as TS          # reuse the harness's exact auth (session cookie, real accts)
        import requests                          # noqa
        sess, ok = TS.login(role)
        if not ok:
            return None
        r = sess.get(TS.BASE + lp, timeout=20)
        if r.status_code != 200:
            return None
        data = r.json()
        # G33 METHOD/ROUTE CONTRACT: OPTIONS -> Allow header tells which methods the route accepts, so a
        # probe uses a REAL method instead of guessing (a 404/405 = wrong method/route, not a real test).
        try:
            o = sess.options(TS.BASE + lp, timeout=12)
            allow = o.headers.get("allow") or o.headers.get("Allow") or ""
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        except Exception:
            methods = []
    except Exception:
        return None
    rec = None
    items = data if isinstance(data, list) else (data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), list) else None)
    if items:
        rec = items[0]
        # G33 VALID IDs: real resource ids from the list, so IDOR/{id} probes hit REAL objects (not a guessed
        # id -> 404). Keep a couple DISTINCT ids so a cross-object/IDOR probe has a second target.
        for it in items[:8]:
            if isinstance(it, dict) and it.get("id") and it["id"] not in ids:
                ids.append(it["id"])
            if len(ids) >= 4:
                break
    elif isinstance(data, dict):
        rec = data
        if data.get("id"):
            ids.append(data["id"])
    if not isinstance(rec, dict):
        return None
    ex = {k: ("<redacted>" if _SECRETISH.search(k) else v) for k, v in list(rec.items())[:40]}
    result = {"endpoint": endpoint, "list_path": lp, "fields": _shape(rec),
              "example": ex, "methods": methods, "ids": ids,
              "item_path": lp + "/{id}", "_ts": time.time()}
    try:
        cache[key] = result
        json.dump(cache, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    except Exception:
        pass
    return result


def schema_text(hypothesis, role="owner"):
    """Render the read-then-mutate hint for the bench, or '' if discovery fails/no endpoint."""
    ep = endpoint_of(hypothesis)
    s = discover(ep, role=role) if ep else None
    if not s:
        return ""
    ex = json.dumps(s["example"], default=str)[:900]
    methods = s.get("methods") or []
    ids = s.get("ids") or []
    # G33 ROUTE CONTRACT block: real methods + real ids + the {id} path form, so probes hit a REAL route
    # (a 404 = wrong route/method, NOT a real test). Give a distinct 2nd id for IDOR/cross-object probes.
    contract = ""
    if methods or ids:
        contract = ("ROUTE CONTRACT (use a REAL method + REAL id -- a 404/405 means you guessed the route/method):\n"
                    + (f"methods accepted on {s['list_path']}: {methods}\n" if methods else "")
                    + (f"item path: {s['item_path']}  |  REAL ids you can use: {ids[:4]}\n" if ids else "")
                    + ("for an IDOR/cross-object probe use TWO distinct ids from that list; do NOT invent ids or "
                       "action sub-paths (e.g. /{id}/replay) -- they don't exist and return 404.\n" if len(ids) >= 2 else ""))
    return (f"REAL RECORD SHAPE for {s['list_path']} (this endpoint EXISTS and ACCEPTS this schema):\n"
            f"fields: {json.dumps(s['fields'], default=str)[:700]}\n"
            f"a real example record: {ex}\n"
            + contract +
            f"READ-THEN-MUTATE: build your payload from THIS valid shape (correct field names/types) so the "
            f"handler ACCEPTS it (2xx), then introduce ONLY the exploit mutation (e.g. duplicate/negative/"
            f"cross-tenant value) -- a schema-invalid payload just returns 400 and proves nothing.\n")


if __name__ == "__main__":
    import sys
    h = {"surface": sys.argv[1] if len(sys.argv) > 1 else "/api/credit-notes"}
    print(schema_text(h, role=os.environ.get("AEGIS_PROBE_ROLE", "owner")) or "(no schema discovered)")
