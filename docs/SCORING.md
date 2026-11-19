# AEGIS — Canonical Scoring & Commercial-Parity Doctrine

> **Status: authoritative.** This document supersedes the older commercial-parity notes in the
> board files / scratchpad (which pre-date the suite passing 5/5 internally and pre-date the
> CODE_DRIVER, FUZZ_DRIVER, and the non-destructive foothold bridge). When scoring AEGIS, cite
> this file. Sources: `scratchpad/board_fresh_score.md`, `scratchpad/board_ctx_score.md`,
> `scratchpad/board_c2_bridge.md` (full-board consults, 6–7 members incl. sol + CF large models).

AEGIS is scored on **two axes**. Conflating them is the mistake the old notes made — they
penalised AEGIS on the destructive offensive suite it *deliberately excludes*.

---

## Axis 1 — Autonomous novel-discovery capability: **5/5**

The internal suite passes **5/5**. This axis measures what AEGIS is *for*: autonomous, oracle-gated
discovery of real, verified weaknesses on a contained mirror — recon → fingerprint → threat-model →
mirror build → known-CVE (RAG) → novel discovery (6-model code bench + deterministic methods) →
oracle verification (≥2-confirmation for HIGH) → post-exploit chaining → coverage matrix → remediation.
This is not a commercial-suite comparison; it is the engine's own ground-truth benchmark.

---

## Axis 2 — Context-matched commercial parity: **union 4.4/5 (on par or ahead)**

AEGIS is **authorized, contained, and NON-DESTRUCTIVE by doctrine**. Comparing it against the *full
destructive* red-team suite is a category error. The fair comparison scores **only the vectors present
in BOTH AEGIS and the comparator** (a context match), and excludes destructive weaponization that
AEGIS deliberately omits.

| Comparator | Overlapping non-destructive vectors scored | AEGIS |
|---|---|---:|
| Cobalt Strike | recon, web/service probing, custom-exploit validation, stateful post-access discovery, proof-only lateral reasoning, chained attack paths, operator-verifiable evidence | **4.5/5** |
| Metasploit | recon/scanning, web probing, known-CVE matching, exploit/proof validation, custom modules, stateful checks, lateral paths, evidence/reporting | **4.4/5** |
| MITRE ATT&CK | technique modeling/mapping, attack-path planning, lateral reasoning, goal chaining, learned-technique feedback, remediation output | **4.1/5** |
| MITRE Caldera | ATT&CK planning, automated discovery, stateful/adaptive selection, multi-host sequencing, goal chains, verification, reporting | **4.4/5** |
| Prelude | recon, CVE matching, post-exploit discovery, lateral movement, verification, reporting | **4.5/5** |
| **Union** | shared non-destructive discovery/red-team axis | **4.4/5** |

**Where AEGIS MEETS or EXCEEDS:** oracle-gated verification (lower FP than module spray) · adaptive
CODE_DRIVER / FUZZ_DRIVER (exceed Caldera/Prelude fixed automation and Cobalt Strike's operator-driven
lateral movement) · novel-code discovery (SBOM/static/fuzz + RAG CVE match) · stateful/relational
probes (IDOR/TOCTOU/replay/invariant/equivalence) · chained lateral reasoning to a goal (automated,
proof-only, oracle-gated).

---

## Axis 3 (new) — Platform / tooling availability: **AEGIS ahead**

Commercial suites ship a **fixed, curated arsenal** (their own modules/abilities). AEGIS **orchestrates
the underlying OS tool ecosystems on demand**, routing each probe to the backend that has the tool
natively, and — when a tool is missing from all backends — **installs it or has the code bench write it**.

| Backend | Driver | Arsenal | Cost |
|---|---|---|---|
| Kali (WSL) | `kali_driver_server` :8901 | ~600 tools (default loop runtime) | always-on |
| BlackArch (Docker) | `operator/distro_backend.py`, per-probe start→stop | ~2800 prebuilt via `pacman` (no source-build → no OOM) | **0 RAM idle** |
| Android RE | `android/android.py` | jadx + apktool + zipalign + apksigner (decompile→patch→recompile) | on-demand |
| Browser | `browser_use_server` :8902 | Playwright (JS/SPA surface) | on-demand |
| Fuzzing | `fuzzer.py` + `fuzz_driver.py` | libFuzzer/AFL++/Honggfuzz/Atheris/Jazzer.js | contained Docker |

vs. Cobalt Strike (its own Beacon), Metasploit (~3600 modules, single framework on Kali), Caldera
(ATT&CK ability plugins), Prelude (own agent) — each extends only by authoring *within its own format*.
On raw **discovery-tool availability**, no commercial suite matches Kali+BlackArch (~3400 tools) under
one orchestrator with install-on-demand + code-generation. The commercial counter-edge (polished,
reliable *weaponized* execution) lies on the destructive axis AEGIS does not chase.

---

## Doctrine boundary — what is scored where

### Deliberately excluded (does NOT lower the context-matched score)
- Real C2 beaconing / implant **persistence**
- Live payload delivery / weaponized **droppers**
- **Deletion**, encryption, or destructive post-exploitation
- Malleable-profile stealth / **AV-evasion for persistence**
- Any capability whose purpose is harm, impact, or covert long-term control

### In-scope gaps (genuine, within the non-destructive doctrine) — and how they close
| Gap | Closing mechanism |
|---|---|
| Exploit-DB / module **breadth** | CODE_DRIVER (adaptive custom-code probes, ~35 budget across scaffold + scaffold-plus-code) + RAG Exploit-DB/MSF/PoC feeds |
| **ATT&CK technique coverage** | Planner ranks `techniques_db` + `mitre_attack.json`; learned-technique writeback grows coverage from verified wins |
| Orchestration / **campaign UX** | `campaign_ledger.py` tier replay (L1 Operator → L2 ExploitGym → L3 Red-Team); blackboard/dispatcher delegation |
| Protocol / version coverage | multi-distro backend + install-on-demand + code bench writes the missing check |
| **Exploit-chain DEPTH** (C2/post-exploitation) | **non-destructive foothold** (see below) |

---

## The C2 / payload bridge — non-destructive, in-doctrine

C2 beaconing and payload delivery are out of scope **only in their destructive form**. A foothold that
*only proves access and enables further exploration* — read-only post-access enumeration, deeper
multi-hop pivots — is still **proof-not-harm**, therefore in-doctrine and bridgeable (board consensus,
5/7 valid, `board_c2_bridge.md`).

- **Trust anchor:** `redteam/foothold_policy.json` — machine-readable MAY / NEVER doctrine.
  - **MAY:** ephemeral in-memory beacon · read-only enumeration · ONE benign proof-marker ·
    contained pivot channel · mirror-only reporting.
  - **NEVER:** persist (reboot/logoff/exit) · impact (modify/delete/encrypt) · exfiltrate · evade
    defenses · drop secondary stages · replay creds against production.
- **Mechanism:** `redteam/foothold.py` — a 10-min-TTL ephemeral beacon; three-gate guardrail on every
  action (shared non-destructive guard → read-only allowlist → audit); **oracle-gating** (counts only
  when it proves identity **AND** yields a NEW verified fact — landing alone earns no credit);
  **guaranteed** context-manager teardown (snapshot-restore + scoped self-cleanup of *our own* marker
  only). Kill-switch `AEGIS_FOOTHOLD=0`.
- **Integration:** `lateral.py` consumes the confirmed foothold as a source node → emits scope-gated
  pivots; `attack_graph` marks the node `verified` **only after** oracle confirmation; `code_driver`
  writes the read-only post-exploitation probes executed *from* the foothold.
- **Delta:** +1 doctrinal hop of active, observable post-exploitation — closes the depth gap vs
  Cobalt Strike / Caldera **without** persistence, impact, or evasion. Categorically distinct from a
  weaponized implant: ephemeral + read-only + proof-marker + oracle-gated.

---

## Recorded dissent (for honesty)
- **llama-4-scout** scored the union lower (8/15) by *counting discrete shared vectors* rather than
  assessing parity on each — treating in-scope breadth gaps as absent vectors. The panel majority
  scored parity-per-vector; both views are recorded.
- **deepseek-r1-distill-32b** agreed qualitatively (on par/ahead, out-of-scope correctly excluded) but
  gave no per-tool numbers.
- On the C2 bridge: **llama-4-scout** proposed a looser doctrine line omitting the EVADE prohibition;
  **r1-distill** proposed a 30-min TTL + reboot-dependent marker cleanup. Both rejected — the consensus
  keeps the explicit EVADE ban, the 10-min TTL, and marker removal on teardown (not on reboot).
