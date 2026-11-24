# Why Aegis-Artex — what makes it different

Aegis-Artex is built on one premise that most LLM-driven security tools get wrong:

> **A finding is an object, not a sentence.** It is only real when a deterministic, out-of-band oracle
> says so against ground truth — never because a model asserted it.

Everything below follows from that. This is what makes it comparable to — and in verification rigor and
architecture, ahead of — commercial and open-source offensive tooling. It is **self-contained and
standalone**: no external scheduler or SaaS backend — the bridge + the hunt engine are the whole thing, run
against a **contained mirror** of your own authorized target.

---

## 1. Trustworthy, confirmable findings (the core)
- **Oracle-gated truth.** A finding moves `candidate → verified | rejected | inconclusive` **only** via an
  out-of-band verifier running a ground-truth oracle (DB / HTTP / state check). Over-claims are *auto-dropped*,
  so the report never inflates.
- **No single-model self-rating.** HIGH/critical requires **≥2 independent** oracle confirmations — unless a
  single **high-confidence ground-truth** oracle (canary/OOB callback, DB witness, SSRF-to-metadata,
  DB-confirmed SQL/filter injection) confirms it alone. A lone HTTP-status/timing signal is capped, never
  promoted.
- **Tamper-evident ledger.** Findings live in an append-only, **SHA-256 hash-chained** JSONL log;
  `verify_chain()` detects any after-the-fact edit. Status and evidence are never mutated in place.

## 2. Durable evidence, replay & automated retest
- **Real evidence, not a screenshot.** Live oracles capture the actual request/response pair into a
  **content-addressed `EvidenceStore`** (id = sha256 of the exchange) and bind it to the finding by **role**
  (baseline / proof / verification / supporting).
- **Replay.** Any stored proof can be **re-fired byte-for-byte** (optionally rebased to a new host) long
  after the run — proof is durable and independently auditable.
- **Retest loop.** `retest_finding` replays a finding's bound proof against the current target and records
  `still_reproducible | fixed | cannot_confirm` — the closed loop for confirming a fix.
- **Proof-of-Exploitation grade (PoE 0–4).** Every finding carries a graded proof strength
  (0 unverified · 1 claim · 2 + replayable proof · 3 ground-truth/corroborated · 4 both), so reviewers see
  *how far* exploitation actually reached.

## 3. The multi-model board — *many suggest, one executes + verifies*
This is the signature of the system, and the opposite of a single-agent chatbot.

- **A real blackboard, not an ensemble vote.** A panel of models — **DeepSeek, Cloudflare Workers AI, and
  any OpenAI-compatible provider** (OpenRouter / Groq / Cerebras / local) — share a file-based board. They
  are consulted at the **decision points of the pipeline** (scope, threat-model, mirror-build, known-vuln,
  novel-discovery, remediation), not just once at the start.
- **One seat executes.** The models *propose*; a **single operator** is the only seat that runs anything and
  lets the **oracle** decide. Model output is **never auto-applied** to protected/doctrine files — code-level
  guards are the control, not the models' good behaviour.
- **Named dissent, not averaging.** A consultant/analyst seat consolidates the panel into **one answer plus a
  named dissent section** — disagreement is surfaced and attributed, never blended away. Every finding is
  **attributed to the source** (which model/oracle produced it).
- **Board data-hygiene.** Privileged context (creds/secrets) is **sanitized before generalist models see it**;
  outbound prompts are scrubbed. The board can reason about a target without being handed its secrets.
- **Writes *and proves* novel exploit code.** A **code bench** of coder seats emits runnable
  `TARGET / CODE / ORACLE` blocks; the operator *executes* each against the mirror behind a non-destructive
  guard and keeps only what the oracle confirms — the platform produces **proven** novel exploit code, not
  just known-CVE replays or unverified snippets.

## 4. One engine, three modes
A single budgeted, adaptive **iterative-hunt loop** drives three doctrines over the **same fact-finding
vectors** (`web · recon · supply_chain · static · fuzz · misconfig · rag`), so no mode is blind to a class
the others can see:

- **Operator** — the co-pilot / autonomous hunt, non-destructive guard.
- **ExploitGym** — the contained, scored benchmark (see §12).
- **Red-Team** — authorization-gated adversary emulation (see §7).

The loop also runs **in parallel**: one central novelty-brain owns dedup/direction/budget and hands N worker
threads distinct hypotheses, with a **single-writer oracle** serializing the hash-chained ledger so
parallelism can never race or double-count.

## 5. Novelty over convergence — the hunt doesn't repeat itself
Most agents spend a budget doing forty variations of one idea. Aegis-Artex spends it on forty **genuinely
different** attempts:
- Each attempt is a **falsifiable hypothesis**, fingerprinted by `(angle, surface, vuln-class, mechanism,
  oracle-signal)` — and the **payload value is excluded** from the fingerprint, so a value-only tweak
  *collides* and is rejected as lazy.
- **Breadth-first scheduling + a hard per-angle cap** spread the budget; **novelty is awarded over
  convergence** (escalating a confirmed foothold is a small, capped, novel-only slice).
- The budget counts **only information-gaining attempts** — generic 404s, transport errors and repeats are
  noise, bounded separately, and can't pad the count.

## 6. Adversary emulation: Red-Team with lateral movement
The third mode is a first-class pentest, not a scan:
- **Fail-closed authorization.** Red-Team refuses to run without a valid, in-date authorization naming the
  hosts; scope is signed, contained-by-default, wildcards refused.
- **Cross-host lateral movement.** On an oracle-confirmed foothold a host is marked *owned* in the attack
  graph, and **scope-gated pivot moves** are proposed to reachable in-scope hosts (from a RoE topology, else
  a flat model) — chaining web → internal → crown-jewel goal, with the chain reconstructed and scored.
- **Deeper, disciplined escalation.** Red-Team uses a deeper per-mode escalation budget (each pivot is a
  novel confirm on a *new* host) while Operator/ExploitGym keep the breadth-biased defaults.

## 7. Knowledge & planning that learns
- **Offline vuln RAG** — NVD / KEV / EPSS / Exploit-DB / Metasploit / PoC-GitHub / nuclei, queryable
  **without network egress** (online refresh is opt-in).
- **The Planner** fingerprints the target, ranks prior-successful `(technique, tool)` pairs from a
  techniques DB (curated + **MITRE ATT&CK**, live-refreshable), has the board **keep only what fits this
  environment and invent novel approaches** beyond the DB, emits anchor seed-moves into the loop, builds
  multi-scenario plans (fast-track / thorough / covert) with a bounded mid-run **re-open** on a stall, and
  **writes verified wins back** — a closed, self-improving loop.

## 8. Fuzzing — first-class, not bolted on
- **Grey-box, coverage-guided** fuzzing of the mirror's own buildable source via self-hosted OSS-Fuzz
  tooling: **libFuzzer / AFL++ / Honggfuzz**, **Atheris** (Python), Go/Rust/JVM, and **Jazzer.js** (JS/TS).
- **Reproduce-gated.** A crash is a *candidate*; it is verified only when it **reproduces** — the same
  evidence bar as every other finding. Both a black-box `fuzz` vector and the coverage-guided loop vector
  feed the one verification spine.

## 9. Remediation that closes the loop
Most tools stop at "found it." Aegis-Artex has a **stage-10 remediation round**:
- Reads **only oracle-verified** findings; the whole panel proposes each fix, attributed to source, split to
  **two audiences** — *known-CVE* → RAG-filled fixed-version/KEV update **for admins**; *novel* →
  panel-designed **code fix for the code writer/improver**.
- **Closed-loop verify-on-mirror:** snapshot → apply the fix → **re-run the finding's exploit/oracle on the
  patched system** → `CLOSED | STILL-OPEN | BROKE-AFTER-UPDATE` → restore. Mirror-side only; the real target
  is never patched or re-tested.

## 10. Resilient model access + forced-stack discipline
- **Three live-selectable DeepSeek routes** — `/ds` (direct), `/ds-or` (OpenRouter), `/ds-cf` (Cloudflare
  Workers AI) — swappable mid-chat, with **auto-failover** (direct → OpenRouter → CF) so a provider
  402/quota/5xx fails *over* instead of halting the hunt. Each driving model reports its own identity.
- **Forced-stack discipline (optional).** By default the operator runs its own loop; set
  `AEGIS_REQUIRE_STACK=1` (or `/forcedstack` live, `-RequireStack` on standby) to **refuse `finish()` until a
  proven stack tool** (discovery / planner / RAG / Kali / oracle) has actually run — turning "narrate and
  quit" into "map → exploit → verify." `/freestack` returns to the free loop.

## 11. Benchmarked — the engine rates itself
**ExploitGym** is a contained, reproducible benchmark with deterministic targets and scored scenarios
(discovery / weaponization / intended-path / chain-depth / progression). The platform doesn't just claim
quality — it **measures its own engine under audit, repeatably**.

## 12. Safety as code, not just prompts
- **Fail-closed scope/authorization** (`scope.py`, `redteam/authorization.py`) — signed, contained-by-
  default, wildcards refused; probes classified recon/active/destructive and blocked accordingly.
- **Doctrine-edit gate** — edits to doctrine/guardrail/authorization files are **human-gated even under
  `/auto`** (default on).
- **Non-destructive doctrine** — prove with a benign marker; never erase/exfiltrate/DoS.
- **Noise governor** — per-host rate/jitter/in-flight pacing + 429/503 backoff, applied to the **target host
  only** (never to LLM/board APIs).
- **Untrusted-output boundary** — tool output is nonce-framed so the model treats it as data, not
  instructions (prompt-injection defense).
- **Append-only hash-chained findings + approval-gate audit log** (secret-redacted) + **coverage ledger /
  ATT&CK-Navigator gap grid** + **per-task cost metering**.

---

## At a glance

| Capability | Classic scanner | LLM-pentest agent | **Aegis-Artex** |
|---|:--:|:--:|:--:|
| Finds issues | ✅ (signatures) | ✅ (model-driven) | ✅ (board + vectors + fuzz) |
| **Confirmable, oracle-verified findings** | ⚠️ (rule match) | ❌ (prose claims) | ✅ **ground-truth oracle** |
| Over-claim suppression | ⚠️ | ❌ | ✅ auto-drop + severity cap |
| **Replayable evidence** bound to finding | ❌ | ❌ | ✅ content-addressed + replay |
| **Automated retest** (reproducible/fixed) | ❌ | ❌ | ✅ |
| Proof-of-exploitation grade | ❌ | ⚠️ (self-rated) | ✅ PoE 0–4 |
| Tamper-evident findings log | ❌ | ❌ | ✅ hash-chained |
| **Multi-model board** (propose) + one verifier | ❌ | ❌ (single agent) | ✅ board + named dissent |
| Novel exploit **code writing + proving** | ❌ | ⚠️ (unproven) | ✅ code bench + oracle |
| **One engine, three modes** (incl. Red-Team) | ❌ | ⚠️ | ✅ shared vectors |
| Novelty-aware budget (no repeats) | ❌ | ❌ | ✅ hypothesis fingerprinting |
| Lateral movement / pivot chains | ⚠️ (manual) | ❌ | ✅ scope-gated |
| First-class fuzzing (reproduce-gated) | ⚠️ (external) | ❌ | ✅ multi-engine |
| Self-improving technique DB | ❌ | ❌ | ✅ learned + ATT&CK |
| **Closed-loop remediation + verify-on-mirror** | ❌ | ❌ | ✅ two-audience |
| **Reproducible benchmark of the engine** | ❌ | ❌ | ✅ ExploitGym |
| Resilient multi-provider routing / failover | ❌ | ⚠️ | ✅ 3 routes + auto-failover |
| Fail-closed authorization/scope in code | ⚠️ | ❌ | ✅ |

> Legend: ✅ first-class · ⚠️ partial/varies · ❌ typically absent.

**Bottom line:** other tools tell you what a model *thinks* it found. Aegis-Artex gives you findings you can
**trust, re-fire, and retest** — produced by a **multi-model board that proposes and a single oracle that
decides**, driven by one engine across operator / benchmark / red-team modes, with graded proof, a
tamper-evident trail, a closed remediation loop, a benchmark behind the engine, and safety enforced in code.
See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full design, **[BOARD.md](BOARD.md)** for the board, and
**[PLANNER.md](PLANNER.md)** for the planning loop.
