<div align="center">

# Aegis-Artex

**A self-hosted, LLM-driven defensive security-research platform.**

*A multi-model board proposes, one operator executes and verifies — and only oracle-verified findings count.*

[Architecture](docs/ARCHITECTURE.md) · [Install](INSTALL.md) · [Pipeline](docs/PIPELINE.md) · [Planner](docs/PLANNER.md) · [Board](docs/BOARD.md)

</div>

---

Aegis-Artex runs authorized, **contained** security assessments against a local mirror/twin of a target.
It is not a chat wrapper around a scanner: a **Planner** devises a plan, a budgeted **iterative-hunt loop**
drives genuinely-different attempts through shared **attack vectors**, and every candidate finding is moved
`candidate → verified` only by an out-of-band **ground-truth oracle**. Findings are immutable, hash-chained,
and carry **durable, replayable HTTP evidence**.

- **Many suggest, one executes + verifies.** A multi-model *board* (DeepSeek / Cloudflare Workers AI /
  any OpenAI-compatible provider) brainstorms and writes candidate exploit code; the operator is the single
  seat that runs it and lets the oracle decide.
- **Evidence, not prose.** Live oracles capture the real request/response pair into a content-addressed
  store, bind it to the finding by role (baseline/proof/verification), and can **replay** and **retest** it
  (`still_reproducible | fixed`) — with a Proof-of-Exploitation grade (PoE 0–4).
- **Three modes, one engine.** Operator (live co-pilot), **ExploitGym** (contained benchmark), and
  **Red-Team** (scope-enforcing, fail-closed) share the same loop and vectors.
- **Defensive by doctrine.** Authorized/owned targets only, contained-by-default, non-destructive, stay in
  scope, only oracle-verified findings count. See `operator/aegis_operator.py::_DOCTRINE`.
- **Self-contained.** No external scheduler; the bridge + `planner_core` are the whole engine.

## What makes it different
Most LLM security tools either (a) scan and let a model *narrate* the output, or (b) let an agent *claim*
findings it can't prove. Aegis-Artex is built around the opposite premise — **a finding is an object, not a
sentence** — and that shows up end to end:

| | Typical LLM-pentest tool / scanner | Aegis-Artex |
|---|---|---|
| **Findings** | model prose; over-claims common | **first-class, oracle-verified objects** — `candidate → verified` only via ground-truth checks; over-claims auto-dropped |
| **Evidence** | a log line or a screenshot | **durable, content-addressed request/response** bound to the finding by role, **replayable** after the run |
| **Confidence** | "high" (self-rated) | **PoE 0–4** + **≥2 independent confirmations** for HIGH (or one ground-truth oracle) |
| **Regression** | re-run the whole thing | **automated retest** → `still_reproducible | fixed`, append-only |
| **Integrity** | mutable report | **append-only, hash-chained** findings log with `verify_chain()` |
| **Reasoning** | single model | **multi-model board proposes, one operator verifies** (many suggest, one executes) |
| **Rigor** | ad-hoc | a contained **benchmark** (ExploitGym) scores the engine itself, reproducibly |
| **Safety** | prompt-only guardrails | code-level **fail-closed scope/authorization**, non-destructive doctrine, noise governor, untrusted-output boundary |

The headline: **confirmable findings you can trust, re-fire, and retest** — not a transcript of a model's
guesses. That is what makes it comparable to (and in verification rigor, ahead of) commercial and
open-source offensive tooling.

## Features
- Oracle-gated, append-only **hash-chained findings** with tamper detection (`verify_chain`).
- **Durable evidence capture + replay + automated retest** and **PoE** grading.
- **Planner** with a techniques DB (curated + learned + MITRE ATT&CK) and a closed write-back loop.
- **6-model code bench** that emits runnable `TARGET/CODE/ORACLE` blocks, run + confirmed by the operator.
- **Grey-box fuzzer** (libFuzzer / AFL++ / Honggfuzz / Atheris / Jazzer.js) — crashes verified on reproduce.
- **Offline vuln RAG** (NVD/KEV/EPSS/Exploit-DB/MSF/nuclei) + a **remediation** closed loop.
- **Autonomous discover→evaluate→attack loop** with a parallel `content_discovery` sweep (one pass over a
  curated high-value endpoint list, surfacing unlinked endpoints) and budget-aware **execution discipline**
  — simplest-probe-first, every lead checked against the oracle, no `finish()` from recon.
- **Record-before-finish gate** — the operator records a *candidate*; an independent **out-of-band oracle**
  promotes it to verified, so a run can never self-certify a finding.
- **Resilient model routing** — DeepSeek-direct → **DeepSeek-over-OpenRouter** auto-failover plus a
  Cloudflare-Workers-AI leg, so a provider 402/quota/5xx fails *over* instead of halting the hunt. The DS
  brain is reachable over **three live-selectable routes** — `/ds` (direct), `/ds-or` (OpenRouter),
  `/ds-cf` (Cloudflare Workers AI) — swappable mid-chat so the model stays up when one provider is down.
- **Forced-stack discipline (optional)** — by default the operator runs its own tool loop; set
  `AEGIS_REQUIRE_STACK=1` (or `/forcedstack` live, `-RequireStack` on standby) to **refuse `finish()` until
  a proven stack tool** (discovery / planner / RAG / Kali / oracle) has actually run, and keep the
  verify/execute/record finish-gates armed in chat. `/freestack` returns to the free loop.
- **Standby discipline (optional)** — for interactive `--chat`, set `AEGIS_STANDBY_DISCIPLINE=1`
  (or `/discipline on` live, `-Discipline` on standby) to drive the co-pilot to *execution* instead of
  clever talk: the finish-gates become **persistent** (re-fire every premature `finish()` until a probe
  ran and a finding was recorded), the out-of-band **oracle runs at finish** in chat, and a **Hard Floor**
  refuses a prose-only hand-back while the objective is unmet and nothing was dispatched — forcing one
  concrete probe. Genuine scope/authorization questions stay exempt, and it is capped per turn so
  interactivity is never trapped. Default **off** (plain conversational chat); `/discipline off` to free it.
  Discipline drives *execution*, not the stack: it is **decoupled from forced-stack**, so a disciplined
  run may freely pursue novel-code / custom probes — add `/forcedstack` only when you also want the
  proven machinery.
- **Frontier delegation (`hunt`)** — for a *broad* objective ("find/verify vulns across the surface/roles"),
  the chat co-pilot delegates to the budgeted autonomous **frontier** (one novelty-brain fans distinct
  `(angle, surface, vuln-class, mechanism)` intents to N concurrent workers, each **oracle-verified**)
  rather than hand-rolling probes — breadth **and** verification in one call, returning only ground-truth
  findings. Use direct probes for a single targeted check. Dispatch it directly in chat with
  **`/hunt <objective> [--budget N] [--agents N]`** (or just ask broadly and the co-pilot calls it).
  Structure the objective as a **result across a surface/roles**, not one payload — e.g.
  `find and verify access-control vulnerabilities across the mirror and its roles` — because the frontier
  plans its own angles; for one specific check use a direct `run_tool`/`run_command` probe instead.
- **Autonomous reachability + grounded discovery** ([docs/AUTONOMOUS_REACHABILITY.md](docs/AUTONOMOUS_REACHABILITY.md))
  — the hunt self-diagnoses a WAF'd/IP-banned target: finds the leaked **origin** behind a CDN, routes
  egress through the owner's VPN, rotates country on a ban, and sends the right `Host:` — reaching the
  *real* app with no manual config (single-pass **and** multi-agent paths). It then **stays on the real
  surface**: a **reality gate** skips soft-404 phantom endpoints, **WordPress plugin-version harvest**
  turns version-obfuscation's leak into CVE leads, **shared-host / reverse-IP** + **credential-exposure**
  routes are first-class in the Planner, and a **patch-diff n-day ladder** (+ content-authenticity /
  TLS fingerprint-trust gate) defeats spoofed version headers.
- **ARTEX-ported disciplines** — **role-specialized prompts** with executor finding-quality gates, an
  **adversarial retester** (reproduced/fixed/inconclusive), **`ask_operator`** human-unblock, an open
  **intent/hint frontier** with a hard-floor (never idle), **self-extending tooling** (forge a tool at
  runtime), **cold-digest** long-run memory, and a live **execution monitor** (`hunt_monitor.py`).
- **Grounded exploit development, coverage & self-training** ([docs/GROUNDED_EXPLOIT_DEVELOPMENT.md](docs/GROUNDED_EXPLOIT_DEVELOPMENT.md))
  — a known gap is developed, not guessed: the **n-day developer** diffs the patched vs vulnerable release
  (+ **live advisory research**) to build a targeted probe, grounded in the real fix; **CVE-clumpiness**
  spends budget on the densest components first; the **novel lane** reasons out a probe from a 0-day
  methodology; both lanes **self-train** from oracle-confirmed wins (few-shot), measured by a confirmable
  **reproduction benchmark**. Plus a first-class **JWT** vector, an adversarial **retester**, and a
  **relevant** (MITRE-enriched) coverage-denominator whose gaps feed the frontier to hunt.
- Runtime safety: **noise governor** (per-host pacing + 429/503 backoff), **untrusted-output nonce
  boundary**, signed **scope/authorization** gates (fail-closed).

## Quick start
```bash
git clone https://github.com/dsagent1/Aegis-Artex.git
cd Aegis-Artex
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium             # for the browser_use executor

cp secret.env.example secret.env                  # add your LLM key(s) — see INSTALL.md §Providers
#   AEGIS_LLM_API_KEY=...  AEGIS_LLM_ENDPOINT=https://api.deepseek.com/v1  AEGIS_MODEL=...

# start the executors (Kali/Arch toolset + browser), then talk to the operator:
./start-all.ps1                                   # or run the three orchestrator/*.py servers
python operator/aegis_operator.py --chat --provider deepseek
```

See **[INSTALL.md](INSTALL.md)** for a full bare-bones setup (Kali or Arch Linux, the executors, the
contained mirror, and connecting board providers), and **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for
the complete design with diagrams.

## Responsible use
This is a **defensive** research platform for systems you own or are **explicitly authorized** to test.
Red-Team mode is fail-closed and requires a signed `authorization.json`. Keep assessments contained to a
mirror, stay in scope, act non-destructively, and handle findings under responsible disclosure.

## License
MIT — see [LICENSE](LICENSE).
