"""cf_health.py -- quick liveness/latency ping of the Cloudflare board models, to identify FLAKY members
(read-timeouts / empty responses) that should be pruned from the roster so board rounds stay fast. Pings
each model with a trivial prompt under AEGIS_CF_TIMEOUT and prints latency + OK/EMPTY/FAIL. Read-only."""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cf_agent

# Live CF roster as of 2026-11-20 (post Cloudflare deprecation batch). Verify anytime: python cf_health.py
DEFAULT = ["deepseek-cf", "gpt-oss-120b", "gpt-oss-20b", "mistral-small-24b", "llama-3.3-70b",
           "llama-4-scout", "qwen2.5-coder-32b", "glm-5.3"]


def _ping(m, big=False):
    t = time.time()
    # a BIG prompt better simulates the board fan-out (which is what triggered the throttle-timeouts)
    user = ("Reply with the single word OK." if not big
            else ("Context:\n" + ("lorem ipsum dolor sit amet " * 400) + "\nReply with the single word OK."))
    try:
        r = cf_agent.ask(m, "You are a test.", user, max_tokens=20, temperature=0)
        ok = bool(r and str(r).strip())
        return (m, time.time() - t, "OK" if ok else "EMPTY", (str(r) or "").strip()[:24])
    except Exception as e:
        return (m, time.time() - t, "FAIL", str(e)[:44])


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    concurrent = "--concurrent" in sys.argv
    big = "--big" in sys.argv
    models = args or DEFAULT
    rows = []
    if concurrent:
        import concurrent.futures as cf
        t0 = time.time()
        with cf.ThreadPoolExecutor(max_workers=len(models)) as ex:  # fire ALL at once (like the board)
            rows = list(ex.map(lambda m: _ping(m, big), models))
        wall = time.time() - t0
        for m, dt, status, txt in rows:
            print("%-28s %6.1fs  %-5s  %r" % (m, dt, status, txt))
        print("\n[concurrent] wall=%.1fs  (CF_CONCURRENCY=%s)" % (wall, os.environ.get("AEGIS_CF_CONCURRENCY", "4")))
    else:
        for m in models:
            row = _ping(m, big)
            rows.append(row)
            print("%-28s %6.1fs  %-5s  %r" % row)
    good = [m for m, _, s, _ in rows if s == "OK"]
    flaky = [m for m, _, s, _ in rows if s != "OK"]
    print("\nRELIABLE (%d): %s" % (len(good), ", ".join(good)))
    print("FLAKY   (%d): %s" % (len(flaky), ", ".join(flaky)))


if __name__ == "__main__":
    main()
