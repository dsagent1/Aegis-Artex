# Autonomous Reachability, Grounded Discovery & ARTEX-ported Disciplines

Capabilities that let a hunt **reach the real target** behind modern defenses, **stay on the real
surface** instead of hallucinated endpoints, and **drive further** without giving up. All are
**opt-in + fail-open** (a failure degrades to prior behavior, never crashes a run) and for
**authorized, owner-controlled targets only**.

## 1. Autonomous reachability (reach the real app past a WAF/ban)

A hardened site is often Cloudflare-fronted (edge 403s everything) with the real **origin exposed**
via a leaky subdomain, and may rate-limit/ban the tester IP. The hunt now self-diagnoses this:

- **`origin_resolver.py`** — probes the front door; if it's WAF'd, enumerates origin-leaking subdomains
  (`mail`/`ftp`/`cpanel`/`webmail`/CT logs) → non-CDN IPs, confirms which serves the *real* app with
  `Host: <domain>`, and **rebinds the hunt to the origin** + sets `AEGIS_HOST_HEADER`. Gate `AEGIS_AUTO_ORIGIN=0`.
- **`proxy_guard.py`** — owner opt-in (`AEGIS_AUTO_PROXY=1`): routes the hunt's egress through a forward
  proxy inside the operator's VPN so a target IP-ban can't blind the probes (reachability of an *owned*
  asset; authorized-egress lane, not third-party evasion).
- **`vpn_guard.py`** — the hunt rotates its own egress **country** on a sustained ban streak (drives the
  VPN client itself). Gate `AEGIS_VPN_ROTATE=1`.
- **`session_factory` / `planner` `AEGIS_HOST_HEADER`** — every probe + the crawler send the right `Host`,
  so origin-IP requests hit the real vhost.

Wired into **both** the single-pass (`run_hunt`) and the parallel multi-agent (`agent_hunt`) paths, so
either self-drives to the real origin with no manual config.

## 2. Grounded discovery (stay on the real surface, no phantoms)

- **Reality gate** (`vectors.dispatch`) — a web move at a surface matching the target's
  known-nonexistent (**soft-404**, redirect-followed) baseline is skipped cheaply instead of running the
  full probe battery, so budget flows to real surfaces. Gate `AEGIS_REALITY_GATE=0`.
- **`wp_enum.py`** — version-obfuscated WordPress scrubs the *core* version but leaks **plugin/theme
  versions** (`?ver=` + `readme.txt` *Stable tag*); harvests them as concrete CVE/patch-diff leads and
  seeds them into the hunt. Auto-runs on a WP target. Gate `AEGIS_WP_ENUM=0`.
- **`discovery.cohost`** — shared-host / co-hosted lateral: reverse-IP the **origin** (not the CDN) to find
  the owner's co-hosted portfolio; ranks soft neighbors (`staging`/`forum`/`dev`) first; fingerprints only
  `AEGIS_OWNED_DOMAINS` (scope-gated).
- **`discovery.credential_exposure`** — recon-first breach-dump / GitHub / HIBP check for leaked creds of
  an owned domain; seeds `credential_replay`.
- **`patch_differ.py`** — n-day ladder: public-exploit check → version/**commit-diff** of the component →
  extract the security hunks → hand to the code bench → novel fallback; plus a **content-authenticity +
  TLS fingerprint-trust gate** (byte-match a version-pinned asset vs genuine source) that defeats spoofed
  version headers.

## 3. ARTEX-ported disciplines (find more, verify harder, don't give up)

- **`prompt_registry.py`** — role-specialized prompts keyed by stage (decomposer/planner/**executor**/
  retester/reporter) with the executor **finding-quality gates** (PoC proves the goal, measured impact
  with its denominator, proof-basis, priority discipline) + per-role wrap-ups + **code-owned guardrail
  tails** an override can't strip.
- **`retester.py`** — independent re-verification → **reproduced / fixed / inconclusive** (unreachable/
  WAF/error ⇒ *inconclusive*, never "fixed") + opt-in 5-axis *argue-the-opposite* (`AEGIS_RETEST_LLM=1`).
- **`ask_operator.py`** — pause-and-ask human unblock for captcha/OTP/2FA/decisions and environmental
  blocks ("one copy-pastable command, then wait"), headless-safe via a request/reply file. `AEGIS_ASK_OPERATOR=0` to skip.
- **`frontier.py`** — open exploration frontier: fact-synthesized **intents** (not a fixed menu) + a
  **hint** channel the planner reads next round + a **hard floor** (never idle while the goal is unmet).
- **`tool_forge.py`** — self-extending tooling: register a command/python/http tool at runtime and reuse
  it (persisted, non-destructive-gated); `skill_gaps` backlog.
- **`digest.py`** — cold-memory compression: keep the hot frontier full-fidelity, fold settled findings
  into retrievable per-class digests so long runs don't blow context.

## 4. Live execution monitor

- **`hunt_monitor.py`** — a live CLI of what the loop is doing *right now* (current attempt/leg/surface,
  verified findings, the latest novel-code attempt), from the RunMonitor heartbeat + ledger + coder_events.
  `python operator/hunt_monitor.py` (live) or `--once`. Pairs with `board/live_board.ps1` (the board *chat*
  view); this is the *execution* view.

---
All of the above are **non-destructive by default** and intended for **authorized, contained** assessment
of your own / explicitly-authorized targets. See `README.md` → Responsible use.
