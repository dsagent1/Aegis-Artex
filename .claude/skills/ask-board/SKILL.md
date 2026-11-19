---
name: ask-board
description: Consult the Aegis multi-model board about the code or a decision in THIS repo — code review, "what should I add next", design second opinions, or any question that benefits from several models' takes consolidated into one answer plus named dissent. Trigger on "ask the board", "/ask-board", "get a panel review", or when you want more than one model's view on the current project.
---

# ask-board — consult the Aegis board

The board is a file-based, multi-model blackboard: many models **suggest**, one operator **executes and
verifies**. Use it for a panel opinion on the code or a decision. It is **advisory** — it writes to the
board/report, it does not change code or touch targets.

## Mechanisms (all in this repo)

- **Ask the panel a question** — the human's channel into the board:
  ```bash
  python operator/board_ask.py "which surface should we prioritise next: the auth flow or the payment path?"
  python operator/board_ask.py "..." --panel ds,coders     # limit who answers (ds + the coder bench)
  python operator/board_ask.py "..." --no-panel            # just post the question, don't fan out
  ```
  Each answer lands on the board; watch it live:
  ```bash
  board/live_board.ps1        # ~20-30s refresh (board/board_view.py prints it on non-Windows)
  ```

- **Board code-review of this repo** — the coder panel reviews the source in bundles and a consultant
  consolidates a ranked improvement plan (`code_review_report.md`):
  ```bash
  python operator/code_review.py --paths operator shared rag redteam exploitgym
  ```

- **Fan out the code bench** — models emit runnable `TARGET/CODE/ORACLE` blocks the operator runs + verifies:
  ```bash
  python operator/code_suggester.py all "<prompt>" --review
  ```

## Who is on the board

Configured in `operator/board_roster.json` (`always_include` = constant seats; `code_suggesters` = the code
bench; `consultants` = analyst/second-opinion). Seats reach their models three ways — a direct provider key,
Cloudflare Workers AI (`cf_models.json`), or any OpenAI-compatible relay — plus **Claude via the Claude CLI**
(`claude -p`, no API key). Any seat lacking a configured key is skipped gracefully. See
`docs/ARCHITECTURE.md §8` and `§14`.

## Rules

- **Data hygiene:** send the board only a framed question — **no secrets/credentials**. External seats see
  sanitized prompts; secret-looking lines are redacted before any model sees a file (`code_review.py`).
- **Advisory only:** the board proposes; the operator is the single seat that executes and lets the oracle
  decide. Board output is never auto-applied to protected files.
- Keys live only in a gitignored `secret.env`. Defensive doctrine applies throughout.
