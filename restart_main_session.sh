#!/usr/bin/env bash
# Restart a Claude Code session inside tmux, optionally with the voice channel attached.
#
#   bash restart_main_session.sh              # resume the session with the voice channel
#   bash restart_main_session.sh --no-voice   # resume it without the voice channel (also the right
#                                             # call for a reboot hook: the development-channel
#                                             # prompt below needs a human)
#
# After a start with voice: `tmux attach -t <tmux session>`, confirm the development-channel prompt
# if one is shown, then detach with Ctrl-b d.
#
# Settings. Each comes from the environment if set, otherwise from the matching KEY= line in
# $VOICE_DIR/env (default /root/.voice/env). That file is parsed for these keys only, never sourced.
#   CLAUDE_SESSION_ID  id of the session to resume                            (required)
#   TMUX_SESSION       name of the tmux session                               (default: claude)
#   CLAUDE_WORKDIR     directory the session runs in                          (default: $HOME)
#   CLAUDE_BIN         claude executable                                      (default: $HOME/.local/bin/claude)
#   CLAUDE_CHANNELS    value of --channels                                    (default: plugin:telegram@claude-plugins-official)
#   TELEGRAM_ENV_FILE  .env of the Telegram plugin, used by the final check   (default: $HOME/.claude/channels/telegram/.env)
#
# Before starting it removes the entries of the Telegram plugin and of the voice server from Claude Code's
# MCP failure cache (<config dir>/mcp-needs-auth-cache.json): a failed start of either by ANY session makes
# Claude Code skip it silently for 15 minutes. After starting it checks that both came up (exit 1 if not).
# With voice it also passes --settings $VOICE_DIR/session-settings.json (progress hooks, written by deploy.sh) if that file exists.
# Process environment only (mainly for tests): RESTART_LIB_ONLY=1 (define the functions and return),
# RESTART_WAIT_TRIES (default 30) and RESTART_WAIT_STEP (default 2) for the post-start waits.
set -euo pipefail

HOME="${HOME:-$(getent passwd "$(id -u)" | cut -d: -f6)}"
VOICE_DIR="${VOICE_DIR:-/root/.voice}"

# conf KEY DEFAULT: the environment first, then the last KEY= line of $VOICE_DIR/env, then DEFAULT.
# An empty value counts as unset.
conf() {
  local v="${!1:-}"
  if [ -z "$v" ] && [ -r "$VOICE_DIR/env" ]; then
    v=$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$VOICE_DIR/env" | tail -n 1)
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
      \"*\") v="${v#\"}"; v="${v%\"}" ;;
      \'*\') v="${v#\'}"; v="${v%\'}" ;;
    esac
  fi
  printf '%s' "${v:-$2}"
}

# clear_mcp_cache: drop the top-level keys of the MCP failure cache that name the Telegram plugin (they start with
# "plugin:telegram") or the voice server (exactly "voice" or "server:voice"); nothing else, so another server whose name merely
# contains those words keeps its entry.
# Other keys are never touched; the file is rewritten atomically with its old mode; a backup (<file>.bak) is
# kept only when the original is private (mode 600). A missing, unreadable or non-object file is left alone.
clear_mcp_cache() {
  local f="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/mcp-needs-auth-cache.json" n
  [ -f "$f" ] || return 0
  n=$(python3 -I -c '
import json, os, shutil, sys, tempfile
f = sys.argv[1]
try:
    data = json.load(open(f))
except Exception:
    print(0); sys.exit(0)
if not isinstance(data, dict):
    print(0); sys.exit(0)
stale = [k for k in data if k.startswith("plugin:telegram") or k in ("voice", "server:voice")]
if not stale:
    print(0); sys.exit(0)
mode = os.stat(f).st_mode & 0o777
for k in stale:
    del data[k]
d = os.path.dirname(os.path.abspath(f))
fd, tmp = tempfile.mkstemp(prefix=".mcp-cache.", dir=d)
try:
    with os.fdopen(fd, "w") as o:
        json.dump(data, o)
    os.chmod(tmp, mode)
    if mode == 0o600:
        shutil.copyfile(f, f + ".bak"); os.chmod(f + ".bak", 0o600)
    os.replace(tmp, f)
except Exception:
    try: os.unlink(tmp)
    except OSError: pass
    print(0); sys.exit(0)
print(len(stale))
' "$f" 2>/dev/null || echo 0)
  case "$n" in
    ''|0) echo "mcp cache: nothing to clear" ;;
    1) echo "mcp cache: removed 1 entry" ;;
    *) echo "mcp cache: removed $n entries" ;;
  esac
}

# bun_under PANE_PID COMM MARKER: print the pid of a process named COMM whose command line contains MARKER and
# which descends from PANE_PID; exit 1 if there is none.
bun_under() {
  local pane="$1" comm="$2" marker="$3" p a
  for p in $(pgrep -x "$comm" 2>/dev/null || true); do
    case "$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)" in *"$marker"*) ;; *) continue ;; esac
    a=$p
    while [ "${a:-1}" -gt 1 ] && [ "$a" != "$pane" ]; do a=$(ps -o ppid= -p "$a" 2>/dev/null | tr -d ' ' || true); done
    if [ "$a" = "$pane" ]; then echo "$p"; return 0; fi
  done
  return 1
}

# voice_target MCP_JSON: print "<process name>|<marker>" of the voice server: its command and first script argument
# from the mcp.json (the "voice" server), else the defaults (bun, channel/dist/server.js).
voice_target() {
  python3 -I -c '
import json, os, sys
comm, marker = "bun", "channel/dist/server.js"
try:
    s = json.load(open(sys.argv[1]))["mcpServers"]["voice"]
    comm = os.path.basename(s.get("command") or comm)[:15] or comm
    for a in s.get("args") or []:
        if isinstance(a, str) and a.endswith("server.js"):
            marker = a; break
except Exception:
    pass
print(comm + "|" + marker)
' "$1" 2>/dev/null || echo "bun|channel/dist/server.js"
}

# wait_voice PANE_PID MCP_JSON: wait for the voice channel server below the pane; print the verdict line.
wait_voice() {
  local pane="$1" t comm marker pid i
  t=$(voice_target "$2"); comm="${t%%|*}"; marker="${t#*|}"
  for i in $(seq 1 "${RESTART_WAIT_TRIES:-30}"); do
    if pid=$(bun_under "$pane" "$comm" "$marker"); then echo "voice channel: OK (process $pid)"; return 0; fi
    sleep "${RESTART_WAIT_STEP:-2}"
  done
  echo "voice channel: FAIL (no $comm process running $marker under the tmux pane; a development-channel prompt may be waiting in tmux)"
  return 1
}

[ -z "${RESTART_LIB_ONLY:-}" ] || return 0

SESSION_ID=$(conf CLAUDE_SESSION_ID "")
if [ -z "$SESSION_ID" ]; then
  echo "CLAUDE_SESSION_ID is not set: export it, or add a CLAUDE_SESSION_ID= line to $VOICE_DIR/env" >&2
  exit 1
fi
case "$SESSION_ID" in
  *[!A-Za-z0-9-]*) echo "CLAUDE_SESSION_ID may only contain letters, digits and '-'" >&2; exit 1 ;;
esac
TMUX_SESSION=$(conf TMUX_SESSION claude)
WORKDIR=$(conf CLAUDE_WORKDIR "$HOME")
[ "$WORKDIR" = "/" ] || WORKDIR="${WORKDIR%/}"
CLAUDE_BIN=$(conf CLAUDE_BIN "$HOME/.local/bin/claude")
CHANNELS=$(conf CLAUDE_CHANNELS plugin:telegram@claude-plugins-official)
TELEGRAM_ENV_FILE=$(conf TELEGRAM_ENV_FILE "$HOME/.claude/channels/telegram/.env")

# Claude Code keeps the transcript of a session in <config dir>/projects/<workdir with every
# non-alphanumeric character replaced by "-">/<session id>.jsonl, e.g. -root for /root.
PROJECT_DIR=$(printf '%s' "$WORKDIR" | sed 's/[^A-Za-z0-9]/-/g')
TRANSCRIPT="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/projects/$PROJECT_DIR/${SESSION_ID}.jsonl"
[ -f "$TRANSCRIPT" ] || { echo "transcript not found: $TRANSCRIPT" >&2; exit 1; }

CMD="$(printf '%q' "$CLAUDE_BIN") --resume $SESSION_ID --channels $CHANNELS"
if [ "${1:-}" != "--no-voice" ]; then
  [ -f "$VOICE_DIR/mcp.json" ] || { echo "$VOICE_DIR/mcp.json missing (run deploy.sh)" >&2; exit 1; }
  systemctl is-active --quiet voice-web || { echo "voice-web is not running" >&2; exit 1; }
  CMD="$CMD --mcp-config $(printf '%q' "$VOICE_DIR/mcp.json") --dangerously-load-development-channels server:voice"
  # progress hooks for the Voice app (written by deploy.sh); a session without the file simply has no hooks
  [ ! -f "$VOICE_DIR/session-settings.json" ] || CMD="$CMD --settings $(printf '%q' "$VOICE_DIR/session-settings.json")"
fi

# -u TELEGRAM_BOT_TOKEN: if the global environment of the tmux server carries the TELEGRAM_BOT_TOKEN of
# another bot (for example tmux was started by a different Telegram bot service), the Telegram plugin
# prefers that real environment variable over its own .env, and the session would poll the wrong bot.
ENVCLEAN="env -u TELEGRAM_BOT_TOKEN -u CLAUDECODE -u CLAUDE_CODE_CHILD_SESSION -u CLAUDE_CODE_ENTRYPOINT -u CLAUDE_CODE_EXECPATH -u CLAUDE_CODE_SESSION_ID -u CLAUDE_EFFORT -u CLAUDE_PID"

clear_mcp_cache

if tmux has-session -t "=$TMUX_SESSION" 2>/dev/null; then
  tmux respawn-pane -k -t "=$TMUX_SESSION:" -c "$WORKDIR" "$ENVCLEAN $CMD"
else
  tmux new-session -d -s "$TMUX_SESSION" -x 200 -y 50 -c "$WORKDIR" "$ENVCLEAN $CMD"
fi
echo "started: $CMD"

# Check that the Telegram plugin of the new session uses the bot from its own .env.
EXPECTED=$(grep -oE '^TELEGRAM_BOT_TOKEN=[0-9]+' "$TELEGRAM_ENV_FILE" 2>/dev/null | cut -d= -f2 || true)
PANE_PID=$(tmux display-message -p -t "=$TMUX_SESSION:" '#{pane_pid}')
VERDICT="not seen yet (a prompt may be waiting in tmux)"
if [ -z "$EXPECTED" ]; then
  VERDICT="check skipped (no TELEGRAM_BOT_TOKEN in $TELEGRAM_ENV_FILE)"
else
  for _ in $(seq 1 "${RESTART_WAIT_TRIES:-30}"); do
    for p in $(pgrep -x bun); do
      case "$(readlink /proc/$p/cwd 2>/dev/null)" in *plugins*telegram*) ;; *) continue ;; esac
      a=$p
      while [ "${a:-1}" -gt 1 ] && [ "$a" != "$PANE_PID" ]; do a=$(ps -o ppid= -p "$a" 2>/dev/null | tr -d ' ' || true); done
      [ "$a" = "$PANE_PID" ] || continue
      got=$(tr '\0' '\n' < /proc/$p/environ | grep -oE '^TELEGRAM_BOT_TOKEN=[0-9]+' | cut -d= -f2 || true)
      if [ -z "$got" ] || [ "$got" = "$EXPECTED" ]; then VERDICT="OK (bot $EXPECTED)"; else VERDICT="WRONG BOT $got, expected $EXPECTED"; fi
      break 2
    done
    sleep "${RESTART_WAIT_STEP:-2}"
  done
fi
echo "telegram plugin: $VERDICT"
FAILED=""
case "$VERDICT" in OK*|"check skipped"*) ;; *) FAILED="telegram plugin" ;; esac
if [ "${1:-}" != "--no-voice" ]; then
  wait_voice "$PANE_PID" "$VOICE_DIR/mcp.json" || FAILED="${FAILED:+$FAILED and }voice channel"
fi
echo "now: tmux attach -t $TMUX_SESSION   (confirm prompts, then Ctrl-b d)"
if [ -n "$FAILED" ]; then
  echo "FAILED: $FAILED did not come up; see the lines above and the tmux session" >&2
  exit 1
fi
