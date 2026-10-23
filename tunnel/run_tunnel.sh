#!/bin/bash
# Quick Cloudflare tunnel to voice-web: publishes the public URL and sets the Telegram menu button.
#
# Settings come from the process environment first, then from KEY= lines in $VOICE_DIR/env (the file
# is parsed, never sourced):
#   VOICE_PORT           port of voice-web                         (default 18200)
#   VOICE_ALLOWED_USER   Telegram user id whose chat gets the menu button (or VOICE_CHAT_ID); required
#   VOICE_MENU_TEXT      label of the menu button                  (default "Voice")
#   VOICE_BOT_TOKEN      bot token; if empty, TELEGRAM_BOT_TOKEN is read from VOICE_TG_ENV_FILE
#                        (default /root/.claude/channels/telegram/.env)
# Process environment only (mainly for tests): VOICE_DIR (default /root/.voice), VOICE_ENV_FILE,
# VOICE_CLOUDFLARED (path of cloudflared), VOICE_TG_API (default https://api.telegram.org).
# The public URL is written to $VOICE_DIR/url with mode 0600. Under systemd VOICE_DIR is the runtime directory
# of the unit (/run/voice-tunnel) and HOME points there too; the bot token never appears in a command line.
set -u
umask 077
VDIR="${VOICE_DIR:-/root/.voice}"
ENV_FILE="${VOICE_ENV_FILE:-$VDIR/env}"
CLOUDFLARED="${VOICE_CLOUDFLARED:-$(command -v cloudflared || echo /usr/local/bin/cloudflared)}"
TG_API="${VOICE_TG_API:-https://api.telegram.org}"

# conf KEY: value from the environment, else from the last KEY= line of the env file.
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

PORT=$(conf VOICE_PORT); PORT="${PORT:-18200}"
CHAT=$(conf VOICE_ALLOWED_USER)
[ -n "$CHAT" ] || CHAT=$(conf VOICE_CHAT_ID)
if [ -z "$CHAT" ]; then
  echo "VOICE_ALLOWED_USER (or VOICE_CHAT_ID) is not set: put it in $ENV_FILE or the environment" >&2
  exit 1
fi
if ! [[ "$CHAT" =~ ^-?[0-9]+$ ]]; then
  echo "VOICE_ALLOWED_USER must be a numeric Telegram user id" >&2
  exit 1
fi
MENU_TEXT=$(conf VOICE_MENU_TEXT); MENU_TEXT="${MENU_TEXT:-Voice}"
TOKEN=$(conf VOICE_BOT_TOKEN)
if [ -z "$TOKEN" ]; then
  TG_ENV=$(conf VOICE_TG_ENV_FILE); TG_ENV="${TG_ENV:-/root/.claude/channels/telegram/.env}"
  TOKEN=$(grep -E '^TELEGRAM_BOT_TOKEN=' "$TG_ENV" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'")
fi
# The token goes to curl through a config on stdin, quoted: refuse anything that is not shaped like a bot token.
if [ -n "$TOKEN" ] && ! [[ "$TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
  echo "the bot token does not look like a Telegram bot token: menu button not set" >&2
  TOKEN=""
fi

CF=""
LOG=$(mktemp /tmp/voice-tunnel.XXXXXX)
trap 'rm -f "$LOG"; [ -n "$CF" ] && kill "$CF" 2>/dev/null' EXIT

"$CLOUDFLARED" tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$LOG" 2>&1 &
CF=$!

URL=""
for _ in $(seq 1 60); do
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG" | head -1)
  [ -n "$URL" ] && break
  kill -0 $CF 2>/dev/null || { echo "cloudflared exited early" >&2; exit 1; }
  sleep 1
done
[ -n "$URL" ] || { echo "no tunnel URL after 60s" >&2; exit 1; }
echo "tunnel up: $URL"
echo "$URL" > "$VDIR/url"

if [ -z "$TOKEN" ]; then
  echo "no bot token (VOICE_BOT_TOKEN or TELEGRAM_BOT_TOKEN): menu button not set" >&2
else
  BODY=$(python3 -I -c 'import json,sys;print(json.dumps({"chat_id":int(sys.argv[2]),"menu_button":{"type":"web_app","text":sys.argv[3],"web_app":{"url":sys.argv[1]+"/"}}}))' "$URL" "$CHAT" "$MENU_TEXT")
  OK=0
  for _ in 1 2 3; do
    # the URL (it holds the token) is passed on stdin (-K -), never in argv: /proc/<pid>/cmdline is world-readable
    R=$(printf 'url = "%s/bot%s/setChatMenuButton"\n' "$TG_API" "$TOKEN" | curl -s -m 20 -H 'Content-Type: application/json' -d "$BODY" -K -)
    if echo "$R" | grep -q '"ok":true'; then OK=1; break; fi
    sleep 3
  done
  if [ $OK = 1 ]; then echo "menu button set"; else echo "setChatMenuButton failed" >&2; fi
fi

# Keep cloudflared in the foreground for systemd.
wait $CF
