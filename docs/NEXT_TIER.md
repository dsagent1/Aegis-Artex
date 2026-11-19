# DS-Orchestrator — next-tier roadmap (deployment / hardening beyond the smoke-closed gaps)

All smoke- and chaos-derived gaps are closed (see `AUTO_MODE_GAPS.md`). These three items remain — they
are deployment-grade or architectural, not bugs, and each is scoped here so it can be picked up cleanly.

## T1 — Full per-role authentication provisioning (G6-heavy)  [HIGHEST VALUE]
**Why:** unauthenticated, the hunt only sees the public surface (~10%); the real findings (authz grid,
money-integrity, IDOR) live behind login. Today the loop records an honest UNAUTHENTICATED coverage note
(G6-light) but does not provision auth.
**Design:**
- A role map `AEGIS_ROLE_MAP` (role -> {ident, pin|password}) supplied in `secret.env`/`set-env.local`
  (deployment-specific creds, NEVER in code). The engine's `session_factory` already consumes it.
- Before DISCOVER, the AutoLoop **verifies each role logs in** (a login oracle: authenticated request
  returns the role's own data) and records **which roles authenticated** as per-role coverage.
- A role that fails to authenticate -> coverage omission for that role (honest), not a silent gap.
- Fail-closed: if NO role authenticates and the objective needs auth, GATE/《STUCK》 rather than pretend.
**Effort:** small-medium (mostly wiring + a login-verify probe); blocked only on having the mirror's creds.

## T2 — Concurrent PROBE / CONSULT scheduler slots
**Why:** v1 runs a single PRIMARY slot sequentially, so a long `deep_consult`/Support call or a background
health probe blocks `decide()`. The board specified three slots.
**Design (board):** one decider (only the tick mutates `AutoState`); three supervised slots —
- **PRIMARY (1):** the mutating leg / target-changing action — the ONLY campaign writer (single-mutator).
- **PROBE (1):** background reachability/health re-checks (~60s), non-mutating, reports incidents only.
- **CONSULT (1):** `deep_consult`/Support/`_ds` on an immutable snapshot, no execution authority.
Resource locks (`target: shared|exclusive`, `ledger: write`) prevent races; recovery needs target
exclusivity (cancel+join conflicting activities first). Tag results with action-id + campaign-revision +
target-generation; discard stale results from cancelled attempts.
**Effort:** medium (the scheduler + lock manager); highest payoff is unblocking CONSULT from PRIMARY.

## T3 — Typed-argv Tier-B proposals (board dissent: gpt-6-astra)
**Why:** the Support line's `_rescue_cli` returns a free-form shell command gated by an allowlist + the
`_guard` denylist. A denylist leaks; a model proposing arbitrary shell run unattended is the residual risk.
**Design:** the Support line returns a **typed structured proposal** from a CLOSED schema
(`{verb, args:[...]}`, verb in the Tier-A vocabulary + a small extension set), which the loop compiles to
a **fixed argument vector** (never `bash -lc <text>`), validated against the allowlist. Dry-run where the
tool supports it (`docker --dry-run`, `bash -n`). This removes the "arbitrary shell from a model" surface
while keeping the rescue capability.
**Effort:** small-medium; makes the unattended-execution path defensible rather than merely guarded.

## ROOT-CAUSE CORRECTION (the "OOM" was mostly a harness artifact)
The repeated "OOM kills" this session were the **Claude-Code harness's background-task memory watchdog**
culling `run_in_background` tasks under host memory pressure — **NOT an absolute RAM wall.** Proof: the
SAME `--auto` run, at the SAME ~850 MB free, **COMPLETED end-to-end in the FOREGROUND** (all 4 stages,
AUTO COMPLETE) where every backgrounded copy was culled. That watchdog is a *harness* feature and does
**not** exist when the orchestrator runs standalone (its actual deployment: launched by the user /
`start-ds-orchestrator.ps1` / a scheduler, not by Claude's background executor). So in production the
full-budget run is not blocked by this at all. In-session, the only real limit is the 10-min FOREGROUND
window (≈ budget 3 fits foreground; larger budgets get auto-backgrounded and then watchdog-culled).
T4 below (self-throttle + resume) still adds value on genuinely small hosts, but it is now SECONDARY.

## T4 — Host-resource self-throttling + resume-after-own-death  [secondary; real limit was the harness watchdog]
**Why:** a full-budget run (budget 15) on an 8 GB host was OOM-killed by the host watchdog — the run's own
Python + step-runner children + DS/board calls, ON TOP of WSL/vmmem + the mirror's docker stack + the
driving session, exceeded RAM. The orchestrator cannot recover from its OWN process being killed (it is
the dead process); the G13 fix was validated first (the operator leg ran for real and produced 22
records before the host killed everything).
**Design:**
- **Resume-after-death (mostly there):** `progress.json` + the append-only store already make a run
  resumable; add a `--resume <campaign>` path in `orchestrate()`/`AutoLoop` that reloads state, skips
  completed phases, and continues — so an OOM/kill is a pause, not a loss.
- **Self-throttling:** before dispatching a stage, read host free memory (psutil or `wmic`/`free`); if
  below a floor, reduce concurrency (already sequential) and/or lower the per-leg budget, and cap
  vmmem via `.wslconfig` at deploy time. Back off rather than let the watchdog kill mid-leg.
- **Right-sizing:** a full-budget run wants a host with headroom (>= 16 GB, or WSL memory-capped + fewer
  concurrent LLM calls). On an 8 GB box, budget <= ~5 completes; budget 15 does not.
**Effort:** small (resume flag) + small (a memory-floor check); the real fix is running on adequate RAM.

---
### Sequencing
T1 first (unlocks real findings, needs only creds), then T2 (unblocks the loop under load), then T3
(hardens the unattended-execution surface). None blocks a run today — the loop runs correctly without
them; they raise depth (T1), throughput (T2), and safety-assurance (T3).
