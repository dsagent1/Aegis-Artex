#!/usr/bin/env python3
"""Render the contained multi-agent blackboard (any *.md).

Default view is RECENT-FIRST and bounded so the live window stays scannable:
  - newest post at the TOP (right under the header), each tagged with its age;
  - only the most recent N posts shown (older ones summarized as a count);
  - each post body truncated to a few lines so one message can't fill the screen.

Env knobs (all optional):
  AEGIS_BOARD_DIR      board directory (default ./board_files next to this script)
  AEGIS_BOARD_LIMIT    how many recent posts to show in full      (default 12; 0 = all)
  AEGIS_BOARD_ORDER    "new" = newest first (default) | "old" = oldest->newest (legacy)
  AEGIS_BOARD_MAXLINES max body lines per post before truncating  (default 30; 0 = no cap)
  AEGIS_BOARD_MAXCHARS max body chars per post before truncating  (default 1600; 0 = no cap)
"""
import os, sys, glob, time

# The live window / piped stdout may be a legacy codepage (cp1252) that can't encode Unicode in a post
# body (arrows, box chars, emoji) -> a crash mid-render. Emit UTF-8 and replace anything unencodable so
# the viewer never dies on message content.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BOARD = os.environ.get("AEGIS_BOARD_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "board_files")

def _int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default

LIMIT    = _int("AEGIS_BOARD_LIMIT", 12)
MAXLINES = _int("AEGIS_BOARD_MAXLINES", 30)
MAXCHARS = _int("AEGIS_BOARD_MAXCHARS", 1600)
ORDER    = (os.environ.get("AEGIS_BOARD_ORDER", "new") or "new").lower()

def _age(mtime, now):
    d = int(max(0, now - mtime))
    if d < 5:   return "just now"
    if d < 60:  return f"{d}s ago"
    if d < 3600: return f"{d//60}m ago"
    if d < 86400: return f"{d//3600}h {(d%3600)//60}m ago"
    return f"{d//86400}d ago"

def _clip(body):
    """Truncate a post body by lines then chars; return (text, n_hidden_lines)."""
    lines = body.splitlines()
    hidden = 0
    if MAXLINES and len(lines) > MAXLINES:
        hidden = len(lines) - MAXLINES
        lines = lines[:MAXLINES]
    text = "\n".join(lines)
    if MAXCHARS and len(text) > MAXCHARS:
        text = text[:MAXCHARS].rstrip() + " ..."
    return text, hidden

posts = sorted(glob.glob(os.path.join(BOARD, "*.md")), key=os.path.getmtime)   # oldest -> newest
if not posts:
    print("[board empty -- no messages yet]"); raise SystemExit

now = time.time()
total = len(posts)

if ORDER == "old":
    shown = posts[-LIMIT:] if LIMIT else posts          # legacy: oldest->newest, last N
    hidden_posts = total - len(shown)
    print(f"=== BLACKBOARD: {total} messages"
          + (f" (showing oldest-kept {len(shown)}; {hidden_posts} earlier hidden)" if hidden_posts else "")
          + " ===")
    seq = shown
    newest_path = posts[-1]
else:
    recent = list(reversed(posts))                      # newest -> oldest
    shown = recent[:LIMIT] if LIMIT else recent
    hidden_posts = total - len(shown)
    print(f"=== BLACKBOARD: {total} messages  --  newest first"
          + (f"  (showing {len(shown)} recent; {hidden_posts} older hidden -- AEGIS_BOARD_LIMIT to change)"
             if hidden_posts else "") + " ===")
    seq = shown
    newest_path = posts[-1]

for p in seq:
    mt = os.path.getmtime(p)
    ts = time.strftime("%H:%M:%S", time.localtime(mt))
    marker = "  >>> NEWEST" if p == newest_path else ""
    body, hidden_lines = _clip(open(p, encoding="utf-8", errors="replace").read().strip())
    more = f"\n    ... ({hidden_lines} more lines -- open {os.path.basename(p)} for the full post)" if hidden_lines else ""
    print(f"\n--- [{ts} | {_age(mt, now)}] {os.path.basename(p)}{marker} ---\n{body}{more}")

if ORDER != "old" and hidden_posts:
    print(f"\n[... {hidden_posts} older message(s) not shown. Set AEGIS_BOARD_LIMIT=0 for all, "
          f"AEGIS_BOARD_ORDER=old for the legacy oldest-first view.]")
