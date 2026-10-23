#!/usr/bin/env bash
# Auth watchdog: notices that the main Claude Code session cannot work (authentication failed, usage limit
# reached) or is gone, and tells the owner once in Telegram. It makes no Claude or API calls.
#
# Source of truth is the session transcript (JSONL), not the screen: Claude Code writes an API error as an
# assistant entry with "isApiErrorMessage":true and "error":"<kind>". Only the LAST assistant entry of the
# transcript counts:
#   error authentication_failed -> incident "auth":  the session needs /login
#   error rate_limit            -> incident "limit": the usage limit was hit (Anthropic's own text, cut to 120 characters)
#   error billing_error         -> incident "billing": a billing/credit problem
#   anything else (a normal reply, another error kind) -> no incident; a stored one is forgotten
# The incident is keyed by the uuid of that entry, so it is reported once. A tmux session that does not exist
# is an incident too ("nosession"). Pane text is never read, so talking about errors in the session cannot
# trigger it. Only the last 2 MB of the transcript are read; lines that do not parse are skipped.
#
# The same transcript gives the context fill: when it reaches VOICE_CONTEXT_WARN of VOICE_CONTEXT_WINDOW one
# message is sent (message only, nothing is restarted), and again only after the fill fell below 0.5.
#
# One run = one check (a systemd timer starts it every few minutes).
#
# Settings come from the process environment first, then from KEY= lines in $VOICE_DIR/env (parsed, never sourced):
#   TMUX_SESSION         name of the tmux session to watch                  (default: claude)
#   CLAUDE_SESSION_ID    id of the session whose transcript is read; if unset or its file is missing, only the tmux
#                        check is made (a warning is logged once); nothing is guessed
#   CLAUDE_WORKDIR       directory the session runs in                      (default: $HOME)
#   VOICE_CHAT_ID        chat to notify (or VOICE_ALLOWED_USER); numeric; required
#   VOICE_BOT_TOKEN      bot token; if empty, TELEGRAM_BOT_TOKEN is read from VOICE_TG_ENV_FILE
#                        (or TELEGRAM_ENV_FILE; default $HOME/.claude/channels/telegram/.env)
#   VOICE_CONTEXT_WINDOW context window of the session in tokens; no default: unset or invalid = no context check
#                        (logged once); a fill above 105% of it is treated as a wrong setting (warning, no message)
#   VOICE_CONTEXT_WARN   fraction of the window that triggers one warning   (default: 0.8; re-armed below 0.5)
#   VOICE_AUTH_STATE_DIR where the incident state is kept                   (default: $STATE_DIRECTORY, else /var/lib/voice-auth-watch)
# Process environment only (mainly for tests): VOICE_DIR (default /root/.voice), VOICE_ENV_FILE, CLAUDE_CONFIG_DIR
# (default $HOME/.claude), VOICE_TG_API (default https://api.telegram.org).
# Exit status: 0 = checked (reported or not), 1 = could not notify or misconfigured.
set -euo pipefail
umask 077
HOME="${HOME:-$(getent passwd "$(id -u)" | cut -d: -f6)}"
VDIR="${VOICE_DIR:-/root/.voice}"
ENV_FILE="${VOICE_ENV_FILE:-$VDIR/env}"
TG_API="${VOICE_TG_API:-https://api.telegram.org}"
# The bot token is sent to this address, so it may only be Telegram's own API (or a loopback stub in the tests).
if ! [[ "$TG_API" =~ ^(https://api\.telegram\.org|http://127\.0\.0\.1:[0-9]{1,5})$ ]]; then
  echo "VOICE_TG_API must be https://api.telegram.org (or http://127.0.0.1:<port> for tests)" >&2
  exit 1
fi

conf() {
  local v="${!1:-}"
  if [ -z "$v" ] && [ -r "$ENV_FILE" ]; then
    v=$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$ENV_FILE" | tail -n 1)
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
      \"*\") v="${v#\"}"; v="${v%\"}" ;;
      \'*\') v="${v#\'}"; v="${v%\'}" ;;
    esac
  fi
  printf '%s' "$v"
}

SESSION=$(conf TMUX_SESSION); SESSION="${SESSION:-claude}"
CHAT=$(conf VOICE_CHAT_ID)
[ -n "$CHAT" ] || CHAT=$(conf VOICE_ALLOWED_USER)
if ! [[ "$CHAT" =~ ^-?[0-9]+$ ]]; then
  echo "VOICE_CHAT_ID (or VOICE_ALLOWED_USER) must be a numeric Telegram id: put it in $ENV_FILE or the environment" >&2
  exit 1
fi
TOKEN=$(conf VOICE_BOT_TOKEN)
if [ -z "$TOKEN" ]; then
  TG_ENV=$(conf VOICE_TG_ENV_FILE)
  [ -n "$TG_ENV" ] || TG_ENV=$(conf TELEGRAM_ENV_FILE)
  TG_ENV="${TG_ENV:-$HOME/.claude/channels/telegram/.env}"
  TOKEN=$(grep -E '^TELEGRAM_BOT_TOKEN=' "$TG_ENV" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'" || true)
fi
# The token goes to curl through a config on stdin, quoted: refuse anything not shaped like a bot token.
if ! [[ "$TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
  echo "no usable bot token (VOICE_BOT_TOKEN, or TELEGRAM_BOT_TOKEN in the Telegram plugin .env)" >&2
  exit 1
fi
STATE_DIR=$(conf VOICE_AUTH_STATE_DIR)
STATE_DIR="${STATE_DIR:-${STATE_DIRECTORY:-/var/lib/voice-auth-watch}}"
mkdir -p "$STATE_DIR"
STATE="$STATE_DIR/incident"

# notify TEXT: one sendMessage, plain text. The token is in the stdin config only, never in a command line.
notify() {
  local r
  r=$(printf 'url = "%s/bot%s/sendMessage"\n' "$TG_API" "$TOKEN" |
      curl -s -m 20 --data-urlencode "chat_id=$CHAT" --data-urlencode "text=$1" -K - || true)
  case "$r" in *'"ok":true'*) return 0 ;; esac
  echo "auth watch: Telegram did not accept the message" >&2
  return 1
}

prev=""
[ -f "$STATE" ] && prev=$(head -n 1 "$STATE" || true)

if ! tmux has-session -t "=$SESSION" 2>/dev/null; then
  if [ "$prev" != "nosession" ]; then
    notify "⚠️ Claude Code session '$SESSION' does not exist (no such tmux session), nothing is answering." || exit 1
    echo "nosession" > "$STATE"
    echo "auth watch: session missing, reported"
  fi
  exit 0
fi

# The session is there again: an earlier "does not exist" incident is over.
if [ "$prev" = "nosession" ]; then rm -f "$STATE"; prev=""; echo "auth watch: session is back, state cleared"; fi

# No default window: the size depends on the model, and a wrong one gives wrong warnings. Unset or invalid = no context check.
CTX_WINDOW=$(conf VOICE_CONTEXT_WINDOW)
if ! [[ "$CTX_WINDOW" =~ ^[1-9][0-9]*$ ]]; then
  CTX_WINDOW=0
  [ -f "$STATE_DIR/context-skip-logged" ] || { echo "auth watch: VOICE_CONTEXT_WINDOW is not set (a number of tokens): the context check is skipped" >&2; : > "$STATE_DIR/context-skip-logged"; }
else
  rm -f "$STATE_DIR/context-skip-logged"
fi
CTX_WARN=$(conf VOICE_CONTEXT_WARN); [[ "$CTX_WARN" =~ ^(0(\.[0-9]+)?|1(\.0+)?)$ ]] || CTX_WARN=0.8

# Where the transcript is: <config dir>/projects/<workdir, non-alphanumerics replaced by "-">/<id>.jsonl, of the session
# CLAUDE_SESSION_ID names. There is no guessing: without that id, or without its file, only the tmux check above is made.
WORKDIR=$(conf CLAUDE_WORKDIR); WORKDIR="${WORKDIR:-$HOME}"
[ "$WORKDIR" = "/" ] || WORKDIR="${WORKDIR%/}"
PROJ="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/projects/$(printf '%s' "$WORKDIR" | sed 's/[^A-Za-z0-9]/-/g')"
SID=$(conf CLAUDE_SESSION_ID)
case "$SID" in *[!A-Za-z0-9-]*) SID="" ;; esac

# Two lines out. Line 1: "NONE" (no transcript), "OK" (the last assistant entry is normal or there is none),
# "auth|limit|billing<TAB>key<TAB>text". Line 2: "ctx<TAB>none" (no usage found, or no window set), "ctx<TAB>bad<TAB>percent<TAB>used"
# (more than 105% of the window: the window is set too small, no message) or
# "ctx<TAB>hi|mid|lo<TAB>percent<TAB>used" (hi: at or above WARN, lo: below the re-arm level, mid: in between).
# The context in use is input + cache read + cache creation tokens of the last assistant entry that has a usage
# (an API error entry carries a zero usage and is skipped).
verdict=$(python3 -I -c '
import hashlib, json, os, re, sys
proj, sid, window, warn = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
def main():
    path = os.path.join(proj, sid + ".jsonl") if sid else ""
    if not (path and os.path.isfile(path)):
        return "NONE", "ctx\tnone"
    try:
        with open(path, "rb") as f:
            size = f.seek(0, 2)
            start = max(0, size - 2 * 1024 * 1024)
            f.seek(start)
            data = f.read()
    except OSError:
        return "NONE", "ctx\tnone"
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]                      # the first line is cut in the middle
    last = None
    used = None
    for raw in lines:
        try:
            e = json.loads(raw)
        except Exception:
            continue
        if not (isinstance(e, dict) and e.get("type") == "assistant"):
            continue
        last = (e, raw)
        try:
            u = e["message"]["usage"]
            n = sum(int(u.get(k) or 0) for k in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"))
        except Exception:
            continue
        if n > 0 and e.get("isApiErrorMessage") is not True:
            used = n
    if used is None or window <= 0:
        ctx = "ctx\tnone"
    else:
        ratio = used / window
        level = "bad" if ratio > 1.05 else "hi" if ratio >= warn else ("lo" if ratio < min(0.5, warn) else "mid")
        ctx = "ctx\t%s\t%d\t%d" % (level, int(ratio * 100), used)
    if last is None:
        return "OK", ctx
    e, raw = last
    err = e.get("error") if e.get("isApiErrorMessage") is True else None
    if err not in ("authentication_failed", "rate_limit", "billing_error"):
        return "OK", ctx
    key = e.get("uuid")
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key):
        key = hashlib.sha256(raw).hexdigest()
    text = ""
    if err == "rate_limit":
        c = (e.get("message") or {}).get("content")
        if isinstance(c, list):
            c = " ".join(b.get("text", "") for b in c if isinstance(b, dict))
        if isinstance(c, str):
            text = re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]", " ", c)).strip()[:120]
    return {"authentication_failed": "auth", "rate_limit": "limit", "billing_error": "billing"}[err] + "\t" + key + "\t" + text, ctx
print("\n".join(main()))
' "$PROJ" "$SID" "$CTX_WINDOW" "$CTX_WARN" 2>/dev/null || printf 'NONE\nctx\tnone\n')

# Context fill: one message per crossing of CTX_WARN; armed again only after the fill falls below 0.5 (a compaction).
CTX_STATE="$STATE_DIR/context"
CTX_RC=0
trap '[ "$?" -ne 0 ] || exit "$CTX_RC"' EXIT
IFS=$'\t' read -r _ clevel cpct cused <<< "$(printf '%s\n' "$verdict" | sed -n 2p)"
case "${clevel:-none}" in
  bad)
    [ -f "$STATE_DIR/context-bad-logged" ] || { echo "auth watch: the context in use ($cused tokens) is above VOICE_CONTEXT_WINDOW ($CTX_WINDOW): the window is set too small, no context message is sent" >&2; : > "$STATE_DIR/context-bad-logged"; } ;;
  hi)
    if [ ! -f "$CTX_STATE" ]; then
      if notify "⚠️ Claude Code session '$SESSION': context is ${cpct}% full ($cused of $CTX_WINDOW tokens). Consider /compact or a fresh session."; then
        echo warned > "$CTX_STATE"; echo "auth watch: context warning sent (${cpct}%)"
      else CTX_RC=1; fi
    fi ;;
  lo) [ ! -f "$CTX_STATE" ] || { rm -f "$CTX_STATE"; echo "auth watch: context below the re-arm level, re-armed"; } ;;
esac
[ "${clevel:-none}" = bad ] || rm -f "$STATE_DIR/context-bad-logged"
verdict=$(printf '%s\n' "$verdict" | sed -n 1p)

IFS=$'\t' read -r kind id text <<< "$verdict"
if [ "$kind" = NONE ]; then
  # no transcript to read: only the tmux check above is made (said once, until the file is there again)
  [ -f "$STATE_DIR/transcript-missing-logged" ] || { echo "auth watch: no transcript for CLAUDE_SESSION_ID='${SID}' in $PROJ: only the tmux session is checked" >&2; : > "$STATE_DIR/transcript-missing-logged"; }
  exit 0
fi
rm -f "$STATE_DIR/transcript-missing-logged"
case "$kind" in
  auth|limit|billing) ;;
  OK) if [ -n "$prev" ]; then rm -f "$STATE"; echo "auth watch: back to normal, state cleared"; fi; exit 0 ;;
  *) exit 0 ;;
esac
key="$kind:$id"
if [ "$prev" = "$key" ]; then exit 0; fi
case "$kind" in
  auth) notify "⚠️ Claude Code session '$SESSION': authentication error, the session needs /login." || exit 1 ;;
  billing) notify "⚠️ Claude Code session '$SESSION': billing/credit problem." || exit 1 ;;
  *) notify "⏳ Claude Code session '$SESSION': usage limit reached. ${text:-No details.}" || exit 1 ;;
esac
echo "$key" > "$STATE"
echo "auth watch: reported ($kind)"
