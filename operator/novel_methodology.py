"""novel_methodology.py -- training grounding for the NOVEL (zero-day) lane, where NO known gap/CVE/diff
exists so the probe cannot be copied -- it must be reasoned out.

Two parts, mirroring diff_lessons.py (which trains the KNOWN-gap lane):
  * A curated METHODOLOGY seed -- best practices for finding novel gaps, distilled from how real 0-day
    discovery works AND how LLM agents (including non-frontier models) have found 0-days on their own:
    systematic surface enumeration + a falsifiable hypothesis per input + differential observation +
    chaining small anomalies -- NOT one clever payload.
  * A learning store -- every time the novel lane produces an ORACLE-CONFIRMED finding, that approach is
    recorded and later injected as an exemplar, so the coders generalise from what actually worked here.

brief() returns methodology + the most relevant confirmed novel wins, to ground the code-bench prompt on the
novel/behavioral/scaffold direction. Offline-safe; gate AEGIS_NOVEL_METHOD=0 to disable.
"""
import os, json, time, re

HERE = os.path.dirname(os.path.abspath(__file__))
_PATH = os.environ.get("AEGIS_NOVEL_LESSONS_PATH") or os.path.join(HERE, "novel_probe_lessons.jsonl")

# Distilled, actionable methodology -- not fabricated specifics, the GENERAL practice of novel-gap discovery.
METHODOLOGY = (
    "NOVEL-GAP METHODOLOGY (no public CVE/diff exists -> reason it out, do not guess a payload):\n"
    "1. MAP every input + trust boundary: query/body/header/cookie params, JSON keys, file names, "
    "content-types, each parser and each place one component's output is another's input.\n"
    "2. One FALSIFIABLE HYPOTHESIS per input: 'if this value reaches sink X unsanitised, I observe signal Y'. "
    "Prefer inputs feeding SQL/template/command/deserialise/path/SSRF/redirect sinks, and object IDs.\n"
    "3. DIFFERENTIAL observation: send malformed / oversized / type-confused / encoding-variant / boundary "
    "values and COMPARE responses (status, length, timing, error text, reflected content) against a clean "
    "baseline. A deviation is a lead; a stack trace or an out-of-scope row is a hit.\n"
    "4. STATE & LOGIC: replay, reorder or skip steps in multi-step flows; race a state-changing endpoint "
    "(TOCTOU); access the SAME object as two different roles/accounts and diff (broken object/function "
    "authz is the richest novel class).\n"
    "5. THINK LIKE THE DEV IN REVERSE: a forgotten check hides in the NEWEST feature, an admin path reachable "
    "unauth, import/export, file upload, webhooks, password-reset/email flows, and anything added after the "
    "last audit.\n"
    "6. CHAIN small anomalies into impact (info leak -> predictable id -> object takeover). Confirm with an "
    "INDEPENDENT oracle (not a self-printed SUCCESS). STRICTLY NON-DESTRUCTIVE: plant/read for proof, never "
    "erase.\n"
    "7. COLLABORATIVE DISCOVERY (how agents actually find novel bugs, per published write-ups): propose "
    "several distinct hypotheses, then BUILD ON EACH OTHER -- one agent's partial anomaly (an error, a "
    "leaked path, an odd status) is the NEXT hypothesis's starting point. Breadth first to find the live "
    "thread, then DEPTH on it. This is a non-frontier-capable loop: disciplined enumeration + relentless "
    "follow-through beats one clever guess.\n"
    "8. DRIVE TO DISCOVERY WITHIN BUDGET: spend the ~40 attempts on the HIGHEST-SIGNAL surface first "
    "(newest/most-complex/most-privileged), keep 2-3 mechanism-distinct live threads, and escalate a "
    "confirmed anomaly immediately rather than spreading thin -- reach a provable gap inside the run.")


def _enabled():
    return str(os.environ.get("AEGIS_NOVEL_METHOD", "1")).lower() not in ("0", "false", "no", "off")


def record(name, approach, code, vuln_class="", direction="", model="", oracle_note=""):
    """Record an ORACLE-CONFIRMED novel win so the novel lane learns the approach that worked here."""
    if not code or not str(code).strip():
        return False
    rec = {"ts": time.time(), "name": name, "vuln_class": (vuln_class or "").lower(),
           "direction": (direction or "").lower(), "model": model, "approach": (approach or "")[:400],
           "code": str(code)[:1600], "oracle_note": (oracle_note or "")[:200]}
    sig = re.sub(r"\s+", "", str(code))[:120]
    try:
        for line in open(_PATH, encoding="utf-8", errors="ignore"):
            try:
                if re.sub(r"\s+", "", str(json.loads(line).get("code", "")))[:120] == sig:
                    return False
            except Exception:
                continue
    except FileNotFoundError:
        pass
    try:
        with open(_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        return True
    except Exception:
        return False


def _wins(vuln_class="", k=2):
    vc = (vuln_class or "").lower()
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
        return []
    out.sort(key=lambda l: ((2 if vc and vc in l.get("vuln_class", "") else 0), l.get("ts", 0)), reverse=True)
    return out[:k]


def brief(vuln_class="", direction="", k=2):
    """Methodology + the most relevant confirmed novel wins, to prepend to the code-bench prompt."""
    if not _enabled():
        return ""
    parts = [METHODOLOGY]
    wins = _wins(vuln_class, k)
    if wins:
        parts.append("WORKED-BEFORE NOVEL EXEMPLARS (confirmed here -- adapt the PATTERN):")
        for w in wins:
            parts.append("# %s (%s)\n%s" % (w.get("name", "?"), w.get("vuln_class", ""), w.get("code", "")[:500]))
    return "\n".join(parts)


def stats():
    try:
        n = sum(1 for _ in open(_PATH, encoding="utf-8", errors="ignore"))
    except FileNotFoundError:
        n = 0
    return {"novel_wins": n, "path": _PATH}


if __name__ == "__main__":
    print(brief(direction="code"))
