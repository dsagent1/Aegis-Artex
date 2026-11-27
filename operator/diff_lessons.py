"""diff_lessons.py -- a TRAINING corpus of CONFIRMED diff/advisory -> working-probe wins, used to tune the
board + coders for the "produce a working probe from a diff situation" task (in-context / few-shot, since the
coders are hosted models we can't fine-tune).

patch_diff_bench runs KNOWN, CONFIRMABLE cases; every time the code bench DEVELOPS a probe that reproduces the
known vuln, that (grounding -> working probe) pair is recorded here as a lesson. The n-day developer
(patch_differ grounding -> code bench) then injects the most relevant lessons as EXEMPLARS, so the coders
generalise from what actually worked before instead of starting cold each time. Ground-truth only: a lesson
is written exactly when an oracle confirmed the probe reproduced.

Append-only JSONL; offline-safe; gate AEGIS_DIFF_LESSONS=0 to disable injection.
"""
import os, json, time, re

HERE = os.path.dirname(os.path.abspath(__file__))
_PATH = os.environ.get("AEGIS_DIFF_LESSONS_PATH") or os.path.join(HERE, "diff_probe_lessons.jsonl")


def _enabled():
    return str(os.environ.get("AEGIS_DIFF_LESSONS", "1")).lower() not in ("0", "false", "no", "off")


def record(name, grounding, code, vuln_class="", component="", model="", oracle_note=""):
    """Record a CONFIRMED win (a probe that reproduced a known case). Dedups by (name, code signature)."""
    if not code or not str(code).strip():
        return False
    rec = {"ts": time.time(), "name": name, "vuln_class": (vuln_class or "").lower(),
           "component": (component or "").lower(), "model": model,
           "grounding": (grounding or "")[:600], "code": str(code)[:1600], "oracle_note": (oracle_note or "")[:200]}
    sig = str(name) + "::" + re.sub(r"\s+", "", str(code))[:120]
    try:
        for line in open(_PATH, encoding="utf-8", errors="ignore"):
            try:
                o = json.loads(line)
            except Exception:
                continue
            if str(o.get("name")) + "::" + re.sub(r"\s+", "", str(o.get("code", "")))[:120] == sig:
                return False                                  # already have this exact lesson
    except FileNotFoundError:
        pass
    try:
        with open(_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        return True
    except Exception:
        return False


def _all():
    out = []
    try:
        for line in open(_PATH, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return out


def brief(vuln_class="", component="", k=2):
    """A few-shot EXEMPLAR block of the most relevant past wins, to prepend to a diff/advisory code brief.
    Ranks lessons sharing the vuln_class or component first, then most recent. Empty if none / disabled."""
    if not _enabled():
        return ""
    vc = (vuln_class or "").lower()
    comp = (component or "").lower()
    lessons = _all()
    if not lessons:
        return ""
    def score(l):
        s = 0
        if vc and vc in (l.get("vuln_class", "")):
            s += 2
        if comp and comp in (l.get("component", "")):
            s += 2
        return (s, l.get("ts", 0))
    lessons.sort(key=score, reverse=True)
    top = [l for l in lessons if score(l)[0] > 0][:k] or lessons[:1]
    blocks = ["WORKED-BEFORE EXEMPLARS (confirmed probes that reproduced a similar known gap -- adapt the "
              "PATTERN, not the literal target):"]
    for l in top:
        blocks.append("# %s (%s)\n%s" % (l.get("name", "?"), l.get("vuln_class", ""), l.get("code", "")[:500]))
    return "\n".join(blocks)


def stats():
    lessons = _all()
    by_class = {}
    for l in lessons:
        by_class[l.get("vuln_class", "?")] = by_class.get(l.get("vuln_class", "?"), 0) + 1
    return {"total": len(lessons), "by_class": by_class, "path": _PATH}


if __name__ == "__main__":
    print(json.dumps(stats(), indent=2))
