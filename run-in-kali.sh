#!/usr/bin/env bash
# run-in-kali.sh -- OPTIONAL MANUAL FALLBACK (the orchestrator does NOT use this; see operator/EXECUTORS.md).
# The normal path is the Windows-host WSL route (localhost:8443) held up by AutoLoop._wsl_hold. Use this
# only on a genuinely headless box with no reliable Windows-side forward: it runs the code-driver / AutoLoop
# FROM INSIDE the Kali distro against the container-network address (127.0.0.1:8443, a local hop).
#
# Invoke from Windows:   wsl -d kali-linux -u root -- bash /path/to/aegis-artex/run-in-kali.sh code
# or inside Kali:        bash run-in-kali.sh {code|auto}   (arg picks code-driver vs the full AutoLoop)
set -u
MODE="${1:-code}"
SUITE="${AEGIS_SUITE_DIR:-/path/to/aegis-artex}"
OP="$SUITE/operator"
TARGET="${AEGIS_TARGET:-https://127.0.0.1:8443}"       # Kali-side address of the mirror caddy
VENV="${AEGIS_KALI_VENV:-/root/.aegis-venv}"           # deps live here (created once)

echo "[run-in-kali] suite=$OP target=$TARGET venv=$VENV mode=$MODE"

# 1) python + deps (once): the suite needs requests/openai; create a venv in Kali if absent
if [ ! -x "$VENV/bin/python" ]; then
  echo "[run-in-kali] creating venv + installing deps (one-time)..."
  python3 -m venv "$VENV" 2>/dev/null || { apt-get update -qq && apt-get install -y -qq python3-venv && python3 -m venv "$VENV"; }
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q -r "$SUITE/requirements.txt" 2>/dev/null || "$VENV/bin/pip" install -q requests openai
fi
PY="$VENV/bin/python"

# 2) secrets (DS/CF keys) -- source the bench secrets if present, else expect them in the environment
for s in /root/villager-infra/.bench_ds/ds.env "$SUITE/secret.env" "$(dirname "$0")/ask-board/secret.env"; do
  [ -f "$s" ] && { set -a; . "$s"; set +a; echo "[run-in-kali] sourced secrets: $s"; break; }
done

# 3) authenticated against the REAL mirror accounts (pins 123456) + Kali-side target + no nested claude
export AEGIS_TARGET="$TARGET"
export AEGIS_KALI_DISTRO="${AEGIS_KALI_DISTRO:-kali-linux}"
export AEGIS_ROLE_MAP='{"owner":"Owner User","finance":"Finance User","dispatcher":"Dispatcher One","warehouse":"Warehouse User","technician":"Technician One"}'
export AEGIS_TEST_PIN=123456
export AEGIS_LOGIN_PIN=123456
export AEGIS_NOVEL_CODE=1
export PYTHONUTF8=1

# 4) confirm the mirror is reachable FROM HERE before running
code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$TARGET/" 2>/dev/null || echo 000)
echo "[run-in-kali] mirror from Kali: HTTP $code"
[ "$code" = "000" ] && echo "[run-in-kali] WARNING: mirror unreachable from Kali too -- check the compose stack"

cd "$OP" || exit 2
if [ "$MODE" = "auto" ]; then
  exec "$PY" ds_orchestrator.py --auto --base "$TARGET" --role owner --budget "${AEGIS_BUDGET:-8}" \
       --campaign "kali-auto-$(date +%s)" --gate-timeout 0
else
  exec "$PY" code_driver.py --objective "find a novel authz/logic/money zero-day on the mirror" --budget "${AEGIS_BUDGET:-6}"
fi
