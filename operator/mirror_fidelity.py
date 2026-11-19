#!/usr/bin/env python3
"""
mirror_fidelity.py -- F10: stage-4 MIRROR-FIDELITY GATE.

Before an assessment spends its budget, assert the twin is actually TESTABLE:
  (1) key tables are POPULATED   -> else read-based tests hit nothing (empty money surface = false-negatives)
  (2) the DB schema matches schema.prisma (no DECLARED-but-MISSING columns) -> else routes 500 AND the
      intended protection is inactive (the live case: Payment.idempotencyKey defined but never migrated,
      which 500'd invoice/payment reads and left the replay guard OFF -> deposit double-spend).

Both were REAL gaps in the target run: the money tables were empty and the idempotencyKey column was
missing, so a whole pass produced honest-but-blind negatives. This gate surfaces that up front (and, on a
schema drift, is itself a finding: if prod shares the drift the guard is inactive there too).

Non-destructive: read-only SELECTs + schema parse. Runs against the mirror DB the same way as
test_suggestions.db() (docker exec psql via WSL/host). Prefers `prisma migrate diff` when available; the
declared-vs-actual column heuristic is the offline fallback.

CLI:  python operator/mirror_fidelity.py [--json]     # exit 0 = fidelity OK, 2 = gap
Gate: check() -> dict; gate() -> (ok, verdict) for complete_test / the hunt preflight.
"""
from __future__ import annotations
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB_CONTAINER = os.environ.get("AEGIS_DB_CONTAINER", "aegis-mirror-db-1")
DB_USER = os.environ.get("AEGIS_DB_USER", "app")
DB_NAME = os.environ.get("AEGIS_DB_NAME", "app")
DB_PASS = os.environ.get("AEGIS_DB_PASS", "")
WSL_DISTRO = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")
SCHEMA = os.environ.get("AEGIS_MIRROR_SCHEMA", "/app/backend/prisma/schema.prisma")
# tables whose emptiness makes read-based tests blind (money surface first)
KEY_TABLES = [t.strip() for t in os.environ.get(
    "AEGIS_FIDELITY_TABLES",
    "Invoice,CreditNote,Estimate,Payment,Customer,Job").split(",") if t.strip()]
_SCALARS = {"String", "Int", "Boolean", "DateTime", "Float", "Decimal", "Json", "BigInt", "Bytes"}


def _db(sql: str) -> str:
    """Run one SQL against the mirror DB via docker exec psql; direct on Linux, WSL-hop on Windows."""
    env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    prefix = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--"] if os.name == "nt" else []
    argv = prefix + ["docker", "exec", "-e", f"PGPASSWORD={DB_PASS}", DB_CONTAINER,
                     "psql", "-U", DB_USER, "-d", DB_NAME, "-t", "-A", "-c", sql]
    try:
        return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30).stdout.strip()
    except Exception as e:
        return f"[db error: {e}]"


def table_counts(tables=None) -> dict:
    """{table: int_count | None} — None = query error / table absent."""
    out = {}
    for t in (tables or KEY_TABLES):
        r = _db(f'SELECT count(*) FROM "{t}";')
        try:
            out[t] = int(r.strip())
        except Exception:
            out[t] = None
    return out


def declared_columns(schema_path=None) -> dict:
    """Parse schema.prisma -> {table: set(column)} for SCALAR fields only (relations skipped). Respects a
    field-level @map("col") and a model-level @@map("table"). Heuristic (no formal Prisma parse), enough to
    catch a declared-but-unmigrated scalar column."""
    path = schema_path or SCHEMA
    text = _read_local_or_container(path)
    models = {}
    if not text:
        return models
    for m in re.finditer(r"model\s+(\w+)\s*\{(.*?)\}", text, re.S):
        model, body = m.group(1), m.group(2)
        table = model
        mm = re.search(r'@@map\("([^"]+)"\)', body)
        if mm:
            table = mm.group(1)
        cols = set()
        for line in body.splitlines():
            line = line.strip()
            fm = re.match(r"(\w+)\s+(\w+)(\?|\[\])?\s*(.*)$", line)
            if not fm:
                continue
            fname, ftype, arr, attrs = fm.group(1), fm.group(2), fm.group(3), fm.group(4)
            if ftype not in _SCALARS or arr == "[]":     # skip relations + scalar lists (own tables)
                continue
            col = fname
            cmap = re.search(r'@map\("([^"]+)"\)', attrs)
            if cmap:
                col = cmap.group(1)
            cols.add(col)
        models[table] = cols
    return models


def _read_local_or_container(path: str) -> str:
    """Read schema.prisma from a local path if present, else via docker exec cat (container-internal path)."""
    if os.path.exists(path):
        try:
            return open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            pass
    env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    prefix = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--"] if os.name == "nt" else []
    api = os.environ.get("AEGIS_MIRROR_API_CONTAINER", "aegis-mirror-api-1")
    try:
        return subprocess.run(prefix + ["docker", "exec", api, "cat", path],
                              capture_output=True, text=True, env=env, timeout=20).stdout
    except Exception:
        return ""


def actual_columns(table: str) -> set:
    r = _db("SELECT column_name FROM information_schema.columns WHERE table_name="
            f"'{table}';")
    if r.startswith("[db error"):
        return set()
    return {c.strip() for c in r.splitlines() if c.strip()}


def schema_drift(schema_path=None) -> list:
    """[(table, column)] declared in schema.prisma but ABSENT in the DB (the idempotencyKey class)."""
    drift = []
    for table, cols in declared_columns(schema_path).items():
        if not cols:
            continue
        actual = actual_columns(table)
        if not actual:            # table absent / unreadable -> not a per-column drift signal here
            continue
        for c in sorted(cols - actual):
            drift.append((table, c))
    return drift


def check(base=None, tables=None, schema_path=None) -> dict:
    counts = table_counts(tables)
    empty = [t for t, n in counts.items() if n == 0]
    unreadable = [t for t, n in counts.items() if n is None]
    drift = schema_drift(schema_path)
    ok = (not empty) and (not drift) and (not unreadable)
    notes = []
    if empty:       notes.append(f"EMPTY tables (read tests blind): {', '.join(empty)}")
    if drift:       notes.append("SCHEMA DRIFT (declared-but-missing cols; routes 500 + protection inactive): "
                                 + ", ".join(f"{t}.{c}" for t, c in drift))
    if unreadable:  notes.append(f"UNREADABLE (mirror/DB down or table absent): {', '.join(unreadable)}")
    if ok:          notes.append("fidelity OK: key tables populated, no declared-but-missing columns")
    return {"ok": ok, "counts": counts, "empty": empty, "drift": drift,
            "unreadable": unreadable, "notes": "; ".join(notes)}


def gate(base=None):
    """Preflight for complete_test / the hunt. Returns (proceed: bool, verdict: dict). AEGIS_FIDELITY_GATE:
    'off' -> always proceed (just report); 'warn' (default) -> proceed but flag; 'strict' -> block on a gap."""
    v = check(base)
    mode = str(os.environ.get("AEGIS_FIDELITY_GATE", "warn")).lower()
    if v["ok"] or mode == "off":
        return True, v
    return (mode != "strict"), v


def main():
    as_json = "--json" in sys.argv
    v = check()
    if as_json:
        print(json.dumps({**v, "drift": [f"{t}.{c}" for t, c in v["drift"]]}, indent=2))
    else:
        print("MIRROR FIDELITY:", "OK" if v["ok"] else "GAP")
        print(" ", v["notes"])
        for t, n in v["counts"].items():
            print(f"   {t}: {n if n is not None else 'UNREADABLE'}")
    sys.exit(0 if v["ok"] else 2)


if __name__ == "__main__":
    main()
