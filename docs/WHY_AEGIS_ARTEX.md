# Why Aegis-Artex — what makes it different

Aegis-Artex is built on one premise that most LLM-driven security tools get wrong:

> **A finding is an object, not a sentence.** It is only real when a deterministic, out-of-band oracle
> says so against ground truth — never because a model asserted it.

Everything below follows from that. This is what makes it comparable to — and in verification rigor,
ahead of — commercial and open-source offensive tooling.

---

## 1. Trustworthy, confirmable findings (the core)
- **Oracle-gated truth.** A finding moves `candidate → verified | rejected | inconclusive` **only** via an
  out-of-band verifier running a ground-truth oracle (DB/HTTP/state check). Over-claims are *auto-dropped*,
  so the report never inflates.
- **No single-model self-rating.** HIGH/critical requires **≥2 independent** oracle confirmations — unless a
  single **high-confidence ground-truth** oracle (canary/OOB callback, DB witness, SSRF-to-metadata,
  DB-confirmed SQL/filter injection) confirms it alone. A lone HTTP-status/timing signal is capped, never
  promoted.
- **Tamper-evident ledger.** Findings live in an append-only, **SHA-256 hash-chained** JSONL log;
  `verify_chain()` detects any after-the-fact edit. Status and evidence are never mutated in place.
- **Immutable history.** Transitions, retests and remediations are *appended* — the original proof survives
  even after a finding is later marked fixed.

## 2. Durable evidence, replay & automated retest
- **Real evidence, not a screenshot.** Live oracles capture the actual request/response pair into a
  **content-addressed `EvidenceStore`** (id = sha256 of the exchange) and bind it to the finding by **role**
  (baseline / proof / verification / supporting).
- **Replay.** Any stored proof can be **re-fired byte-for-byte** (optionally rebased to a new host) long
  after the run — proof is durable and independently auditable.
- **Retest loop.** `retest_finding` replays a finding's bound proof against the current target and records
  `still_reproducible | fixed | cannot_confirm` — the closed loop for confirming a fix (regression testing
  for vulnerabilities).
- **Proof-of-Exploitation grade (PoE 0–4).** Every finding carries a graded proof strength
  (0 unverified · 1 claim · 2 + replayable proof · 3 ground-truth/corroborated · 4 both) shown in every
  report, so reviewers see *how far* exploitation actually reached.

## 3. The multi-model board + code writing
- **Many suggest, one executes + verifies.** A panel of models (DeepSeek / Cloudflare Workers AI / any
  OpenAI-compatible provider) brainstorms; the **operator is the single seat** that runs their ideas and
  lets the oracle decide. Model output is never auto-applied to protected files.
- **6-model code bench.** Coder seats emit **runnable `TARGET/CODE/ORACLE` blocks**; the operator *executes*
  each against the mirror behind a non-destructive guard and keeps only what the oracle confirms — so the
  platform writes and *proves* novel exploit code, not just known-CVE replays.
- **Analyst/consultant review + named dissent.** A consultant seat ranks and consolidates into one answer
  **plus a named dissent section** — disagreement is surfaced, not averaged away.
- **Board data-hygiene.** Privileged context (creds/secrets) is sanitized before generalist models see it.

## 4. Fuzzing (first-class, not bolted on)
- **Grey-box, coverage-guided** fuzzing of the mirror's own buildable source via self-hosted OSS-Fuzz
  tooling: **libFuzzer / AFL++ / Honggfuzz**, **Atheris** (Python), Go/Rust/JVM, and **Jazzer.js** (JS/TS).
- **Reproduce-gated.** A crash is a *candidate* finding; it is verified only when it **reproduces** — same
  evidence bar as every other finding, so fuzzing output is trustworthy too.
- Both a black-box `fuzz` vector and a coverage-guided loop vector feed the same verification spine.

## 5. Knowledge & planning that learns
- **Offline vuln RAG** — NVD / KEV / EPSS / Exploit-DB / Metasploit / PoC-GitHub / nuclei, queryable without
  network egress.
- **Techniques DB** — curated + **MITRE ATT&CK** + *learned*. The **Planner** ranks prior-successful
  `(technique, tool)` pairs, has the board keep only what fits the environment and invent novel approaches,
  and **writes verified wins back** — a closed self-improving loop.
- **Multi-scenario planning** with a bounded mid-run **re-open** so a stall advances to the next plan instead
  of thrashing one idea.

## 6. Benchmarked — the engine rates itself
- **ExploitGym** is a contained, reproducible **benchmark** with deterministic targets and scored scenarios
  (discovery / weaponization / intended-path / chain-depth / progression). The platform doesn't just make
  claims about quality — it measures its own engine under audit, repeatably.

## 7. Audit & accountability features
- **Append-only hash-chained findings** (`verify_chain`) — see §1.
- **Approval-gate audit log** — every mutating/outward action is gated (ask/safe/auto), **fail-closed** on
  interrupt, and logged with **secret redaction**; each decision records who/what approved it.
- **Coverage ledger & gap grid** — `CoverageTracker` records tested/clean/finding per
  surface×method×role×technique; `breadth_audit` compares demanded vs. supplied vs. exercised; an **ATT&CK
  Navigator layer** visualizes technique coverage.
- **Cost metering** — per-task/per-stage token + USD accounting, replayable from the ledger.
- **Attribution** — every finding is tagged to its source (which oracle/model produced it).

## 8. Safety as code, not just prompts
- **Fail-closed scope/authorization** (`scope.py`, `redteam/authorization.py`) — signed, contained-by-
  default, wildcards refused; Red-Team refuses to run without a valid, in-date authorization naming the
  hosts. Probes are classified recon/active/destructive and blocked accordingly.
- **Non-destructive doctrine** — prove with a benign marker; never erase/exfiltrate/DoS.
- **Noise governor** — per-host rate/jitter/in-flight pacing + 429/503 backoff, applied to the **target
  host only** (never to LLM/board APIs).
- **Untrusted-output boundary** — tool output is nonce-framed so the model treats it as data, not
  instructions (prompt-injection defense).

---

## Feature comparison (at a glance)

| Capability | Classic scanner | LLM-pentest agent | **Aegis-Artex** |
|---|:--:|:--:|:--:|
| Finds issues | ✅ (signatures) | ✅ (model-driven) | ✅ (board + vectors + fuzz) |
| **Confirmable, oracle-verified findings** | ⚠️ (rule match) | ❌ (prose claims) | ✅ **ground-truth oracle** |
| Over-claim suppression | ⚠️ | ❌ | ✅ auto-drop + severity cap |
| **Replayable evidence** bound to finding | ❌ | ❌ | ✅ content-addressed + replay |
| **Automated retest** (still-reproducible/fixed) | ❌ | ❌ | ✅ |
| Proof-of-exploitation grade | ❌ | ⚠️ (self-rated) | ✅ PoE 0–4 |
| Tamper-evident findings log | ❌ | ❌ | ✅ hash-chained |
| Novel exploit **code writing + proving** | ❌ | ⚠️ (unproven) | ✅ code bench + oracle |
| First-class fuzzing (reproduce-gated) | ⚠️ (external) | ❌ | ✅ multi-engine |
| Self-improving technique DB | ❌ | ❌ | ✅ learned + ATT&CK |
| **Reproducible benchmark of the engine** | ❌ | ❌ | ✅ ExploitGym |
| Fail-closed authorization/scope | ⚠️ | ❌ | ✅ code-level |
| Coverage ledger / gap grid | ⚠️ | ❌ | ✅ |

> Legend: ✅ first-class · ⚠️ partial/varies · ❌ typically absent.

**Bottom line:** other tools tell you what a model *thinks* it found. Aegis-Artex gives you findings you can
**trust, re-fire, and retest** — with graded proof, a tamper-evident trail, a benchmark behind the engine,
and safety enforced in code. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.
