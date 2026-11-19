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
