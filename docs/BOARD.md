# The AEGIS board — members, roles & tuning (agent handoff)

The "board" is the multi-model panel AEGIS consults for design decisions, code review, and exploit-code
generation. Claude (this coordinator seat) is a first-class member. This doc is the authoritative roster +
tuning so another agent can drive/extend it. Source of truth in code: `operator/board_roster.json`,
`operator/cf_models.json`, `operator/board_ask.py` (`_MEMBERS`, `_PRESETS`, `_STAGE_PROFILES`),
`operator/code_suggester.py` (`CODE_SUGGESTERS`, `ANALYST_MODEL`), `operator/code_driver.py` (`BENCH_WRITERS`).

## Roles (a model can wear more than one hat)
- **always_include** — the constant panel queried every consult round.
- **code_suggesters** — emit runnable `TARGET/CODE/ORACLE` probes (and review code); the coordinator RUNS + oracle-confirms them.
- **consultant/consolidator** — analyst / second-opinion / merges the panel into one ranked plan.
- **code-WRITER roster** — the ordered bake-off-tuned writers the live novel-code driver rotates through.

## Providers & credentials (secrets in `ask-board/secret.env`, gitignored)
- **DeepSeek direct** (`api.deepseek.com`, `DEEPSEEK_API_KEY`) — `ds` = deepseek-v4-pro (writer/coder), `deepseek-v4-flash` (board chat, `AEGIS_BOARD_MODEL`). Reliable; billed separately.
- **Cloudflare Workers-AI** (CF creds, spends Neurons) — all `@cf/...` models (slugs in `cf_models.json`). Any 403/absent model skips gracefully.
- **Claude** — the coordinator answers DIRECTLY via `board_ask --claude "<take>"` (NO API key); as a code WRITER it's the `claude -p` CLI (`AEGIS_CLAUDE_BENCH_MODEL=claude-sonnet-5`, haiku fallback).

## ACTIVE roster (lean, data-backed 2026-09-14; trimmed 16→10 on per-consult on-task rate + latency)
**always_include:** `claude` (overseer/verifier, highest signal, no key) · `deepseek-direct` (concise/broad, 5/5) · `gpt-oss-120b` (`@cf/openai/gpt-oss-120b`, OpenAI-lineage dissent; sole gpt-oss) · `mistral-small-24b` (`@cf/mistralai/mistral-small-3.1-24b-instruct`, distinct lineage, fast non-reasoning).

**code_suggesters (review + exploit code), 6:** `qwen2.5-coder-32b` · `ds` (deepseek-direct) · `kimi-k2.7-code` (reasoning, ≥1500 tok) · `llama-3.3-70b` (fast, best price/latency) · `llama-4-scout` (MoE; TOPPED the code-review bake-off) · `deepseek-r1-distill-32b` (reasoning, 4000 tok, ~8s).

**consultant/consolidator:** `qwq-32b` (`@cf/qwen/qwq-32b`, deep-reasoning analyst/verifier — the board's consolidator; verbose/slower). Final merge in `code_review` uses a NON-reasoning consolidator (`AEGIS_CONSOLIDATOR=ds`, think-stripped) so it emits a plan not raw CoT.

**live code-WRITER roster (`BENCH_WRITERS`, ordered, bake-off-tuned):** `llama-3.3-70b` (LEAD — only clean 4/4 easy→very-hard) → `ds` (fast fallback, 7-8s, 4/4 except very-hard) → `qwen2.5-coder-32b` → `claude` (=sonnet-5). kimi/r1/qwq are NOT writers (leak raw CoT as "code", slow) — they stay reviewers/analyst.

## Per-member tuning (`board_ask._MEMBERS`: provider, model, max_tokens)
| member | provider | max_tokens | notes |
|---|---|---|---|
| ds | deepseek direct | 2200 | thinking DISABLED by default |
| qwen2.5-coder-32b, llama-3.3-70b, llama-4-scout | CF | 1600 | non-reasoning, fast |
| kimi-k2.7-code | CF | ~1600+ | reasoning → needs ≥1500 |
| deepseek-r1-distill-32b, qwq-32b | CF | 4000 | reasoning, slower (~8s) |
| gpt-oss-120b, mistral-small-24b | CF | ~1600 | breadth/dissent |
| claude | coordinator (no key) / CLI writer | — | sonnet-5 (haiku fallback) |

**Global tuning knobs:**
- **`AEGIS_DS_THINKING`** (default 0) — DeepSeek + reasoning models send `thinking:{type:disabled}`; else `content` returns empty and raw `reasoning_content` leaks. Set 1 only if a model needs reasoning on.
- **temperature** ~0.3 (review) / ~0.4 (code-gen) — low, near-deterministic.
- **`AEGIS_CF_TIMEOUT`** — per-member hard timeout; reasoning models (qwq/r1) run 4-8s, longer under load → bound it.
- **`AEGIS_NOVEL_CODE=0`** — skip the code-bench for latency-sensitive runs.
- **`REFINE_CAP=5`** (`AEGIS_CODE_REFINE_CAP`) — per-hypothesis depth in the writer loop.
- **`AEGIS_ANALYST_MODEL`** (qwq-32b) · **`AEGIS_CONSOLIDATOR`** (ds) · **`AEGIS_BENCH_WRITERS`** · **`AEGIS_BOARD_MODEL`** (deepseek-v4-flash).

## Consult presets (`board_ask --members <preset|csv>`)
- **fast:** ds, gpt-oss-120b, qwen2.5-coder-32b, llama-3.3-70b, llama-4-scout, glm-5.2, mistral-small-24b.
- **deep:** ds, qwq-32b, kimi-k2.6, deepseek-r1-distill-32b, glm-5.2, gpt-oss-120b, nemotron-120b.
- **full:** every member in `_MEMBERS`.

## Per-stage profiles (`_STAGE_PROFILES`: preset · budget_scale · timeout · quorum · cost_cap)
- operator: fast · 0.7 · 60s · quorum 3 · $0.15
- exploitgym: fast · 1.0 · 90s · quorum 3 · $0.30
- redteam: deep · 1.3 · 120s · quorum 4 · $0.60
- remediation: deep · 1.2 · 120s · quorum 3 · $0.60
- default: fast · 1.0 · 90s · quorum 2 · no cap

## Dropped / unavailable (kept for the record)
- **dropped:** gpt-oss-20b (redundant w/120b), kimi-k2.6 (0/5, timeouts), gemma-4-26b (1/5), nemotron-120b (1/5, pricey), glm-5.2 (1/4 generic), sea-lion-27b (redundant), qwen3-30b (redundant), **sol** (GPT-5.6 — BOOTED: content-gated refusals on security content, worst cost/value; its dissent covered by gpt-oss-120b).
- **unavailable:** glm-5.3 (403), deepseek-v4-pro-cf (403 → DeepSeek reached directly), qwen3.8-27b (empty replies).

## How to invoke
```bash
# consult the panel (record Claude's own answer as a first-class member):
python operator/board_ask.py "<question>" --consult --members deep --claude "<Claude's take>" --report out.md
# code review of the repo (6 coders + qwq/ds consolidator), bounded so LLMs don't choke:
python operator/code_review.py --paths operator/<file> --max-bundle-chars 12000 --max-bundles 14 --out review.md
# fan out exploit-code proposals + qwq review:
python operator/code_suggester.py all "<prompt>" --review
```
Add a member: key→`ask-board/secret.env` (or CF), model→`board_roster.json` (+ `cf_models.json`/`cf_agent.ROLE_PROMPTS` for CF), then bake it off before trusting it.
