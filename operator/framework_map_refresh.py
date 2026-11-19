#!/usr/bin/env python3
"""framework_map_refresh.py -- regenerate the AUTO-INVENTORY block of FRAMEWORK_MAP.md so the map never goes
stale. Rewrites ONLY the text between the AUTO-INVENTORY markers (module docstrings + every AEGIS_* env knob
+ entrypoints); the curated prose above is left untouched. Offline, idempotent -- safe in a pre-commit hook.

Run:  python operator/framework_map_refresh.py   (from the repo root or operator/)
"""
import ast, os, re, glob, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MAP = os.path.join(ROOT, "FRAMEWORK_MAP.md")
START = "<!-- AUTO-INVENTORY:START"
END = "<!-- AUTO-INVENTORY:END -->"


def _doc1(path):
    try:
        m = ast.parse(open(path, encoding="utf-8").read())
        d = (ast.get_docstring(m) or "").strip().split("\n")[0]
        return re.sub(r"^\w+\.py\s*--\s*", "", d)[:100]
    except Exception:
        return ""


def _modules():
    rows = []
    for d in ("operator", "orchestrator", "redteam", "shared", "rag"):
        for f in sorted(glob.glob(os.path.join(ROOT, d, "*.py"))):
            base = os.path.basename(f)
            if base.startswith("_") or base.startswith("bench_") or base.startswith("test_map"):
                continue
            doc = _doc1(f)
            if doc:
                rows.append(f"- `{d}/{base}` — {doc}")
    return rows


def _env_knobs():
    knobs = set()
    for f in glob.glob(os.path.join(ROOT, "operator", "*.py")) + glob.glob(os.path.join(ROOT, "*", "*.py")):
        try:
            knobs |= set(re.findall(r"AEGIS_[A-Z0-9_]+", open(f, encoding="utf-8", errors="ignore").read()))
        except Exception:
            pass
    return sorted(knobs)


def _entrypoints():
    eps = []
    for f in sorted(glob.glob(os.path.join(ROOT, "operator", "*.py"))):
        try:
            src = open(f, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if '__name__ == "__main__"' in src and "add_argument" in src:
            eps.append(os.path.basename(f))
    return eps


def build_block():
    mods = _modules(); env = _env_knobs(); eps = _entrypoints()
    import datetime
    out = [START + f" — regenerated {datetime.date.today().isoformat()} by operator/framework_map_refresh.py; "
           "do not hand-edit below this line -->",
           f"\n### AUTO: MODULES ({len(mods)}) — file :: first docstring line", ""]
    out += mods
    out += [f"\n### AUTO: RUNNABLE ENTRYPOINTS ({len(eps)}) — `python operator/<name> --help`", "",
            "  " + ", ".join(eps)]
    out += [f"\n### AUTO: ENV KNOBS ({len(env)})", "", "  " + " ".join(env)]
    out += ["", END]
    return "\n".join(out)


def main():
    if not os.path.exists(MAP):
        print("FRAMEWORK_MAP.md not found at", MAP); return 2
    txt = open(MAP, encoding="utf-8").read()
    block = build_block()
    if START in txt and END in txt:
        new = re.sub(re.escape(START) + r".*?" + re.escape(END), block, txt, flags=re.S)
    else:
        new = txt.rstrip() + "\n\n---\n" + block + "\n"
    open(MAP, "w", encoding="utf-8").write(new)
    mods = new.count("\n- `")
    print(f"FRAMEWORK_MAP.md AUTO-INVENTORY refreshed ({block.count(chr(10))} lines).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
