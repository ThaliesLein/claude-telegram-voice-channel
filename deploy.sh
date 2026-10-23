#!/bin/bash
# Deploy Voice Channel from this repo to /opt/voice and (re)start the services. Idempotent. Run as root.
#
# Instance configuration lives outside the repo, in $VOICE_DIR (default /root/.voice):
#   env             settings. Created from env.example on the first run; later runs only append the
#                   keys that are missing and never touch an existing line.
#   internal_token  secret for the internal API (generated once).
#   glossary.txt    recognition glossary (created with a comment header on the first run, never overwritten).
#   mcp.json        MCP config that lets Claude Code start the channel server (rewritten on every run).
#   url             link to the current public tunnel URL (made by the tunnel unit).
# voice-web and voice-tunnel run as throw-away unprivileged users (systemd DynamicUser) in a sandbox. The files above
# reach them as credentials, copied when a unit starts. The state of voice-web (inbox, last_id, reply audio and the
# kill switch file DISABLED) lives in its StateDirectory /var/lib/voice (physically /var/lib/private/voice). A state
# directory left by an older version in $VOICE_DIR/state is moved there once (migrate_state.sh).
# Live mode needs third-party browser files (voice activity detection). web/vendor.lock pins them by sha256;
# this script downloads what is missing into /opt/voice/web/vendor/ and rejects any file that does not match.
# The channel server is built here: bun install --frozen-lockfile (channel/bun.lock pins every dependency), then one
# bundle, /opt/voice/channel/dist/server.js, which mcp.json runs. Nothing is installed when a Claude Code session starts.
# voice-web is restarted on every run. voice-tunnel is restarted only when run_tunnel.sh, its unit file or its
# credentials changed since it was last started (the checksum is kept in $VOICE_DIR/.tunnel-sum), or when it is not
# running, because every tunnel restart gives the Mini App a new public URL. The tunnel gets a reduced copy of the
# settings ($VOICE_DIR/tunnel.env, regenerated on every run), so cloudflared can never read the API keys.
# If the new voice-web does not come up, the previous unit files are put back and the previous voice-web is started again;
# if the new tunnel does not run, the previous tunnel unit goes back.
#
# VOICE_DIR and BUN can be overridden. Test hooks (environment only): VOICE_OPT_DIR (/opt/voice), VOICE_UNIT_DIR
# (/etc/systemd/system), VOICE_STATE_PRIVATE (/var/lib/private/voice), VOICE_READY_WAIT (30: seconds to wait for
# voice-web), VOICE_URL_WAIT (60: seconds to wait for the new tunnel URL), VOICE_MENU_WAIT (20: seconds to wait for the
# menu-button line in the journal of the tunnel).
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
V="${VOICE_DIR:-/root/.voice}"
BUN="${BUN:-/root/.bun/bin/bun}"
OPT="${VOICE_OPT_DIR:-/opt/voice}"
UNIT_DIR="${VOICE_UNIT_DIR:-/etc/systemd/system}"
STATE_PRIVATE="${VOICE_STATE_PRIVATE:-/var/lib/private/voice}"
READY_WAIT="${VOICE_READY_WAIT:-30}"
URL_WAIT="${VOICE_URL_WAIT:-60}"
MENU_WAIT="${VOICE_MENU_WAIT:-20}"
OLD_STATE="$V/state"
MIGRATE="$SRC/migrate_state.sh"

die() { echo "ERROR: $*" >&2; exit 1; }

for c in rsync python3 systemctl curl; do
  command -v "$c" >/dev/null || { echo "missing required command: $c" >&2; exit 1; }
done
[ -x "$BUN" ] || { echo "bun not found at $BUN (install it, or run with BUN=/path/to/bun)" >&2; exit 1; }
command -v cloudflared >/dev/null || [ -x /usr/local/bin/cloudflared ] ||
  echo "WARNING: cloudflared not found; voice-tunnel will not start until it is installed" >&2
# bun install --frozen-lockfile succeeds without a lock file, which would leave the dependencies unpinned
no_lock() { echo "ERROR: $1/channel/bun.lock is missing or empty: the channel server's dependencies are pinned by it. Run 'bun install' in channel/ and commit bun.lock; $2" >&2; exit 1; }
[ -s "$SRC/channel/bun.lock" ] || no_lock "$SRC" "nothing has been changed."

# val KEY: the last KEY= line of the env file as written; cfgval KEY: the same without quotes and trailing blanks.
val() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$V/env" | tail -n 1; }
cfgval() {
  local v; v=$(val "$1")
  v="${v%"${v##*[![:space:]]}"}"
  case "$v" in
    \"*\") v="${v#\"}"; v="${v%\"}" ;;
    \'*\') v="${v#\'}"; v="${v%\'}" ;;
  esac
  printf '%s' "$v"
}

# Checksum of everything whose change requires a tunnel restart (its credentials are copied when it starts). Taken
# before anything is changed, so it also sees a change of tunnel.env made below.
tunnel_sum() {
  local f
  for f in "$OPT/tunnel/run_tunnel.sh" "$UNIT_DIR/voice-tunnel.service" "$V/tunnel.env"; do
    if [ -f "$f" ]; then sha256sum < "$f"; else echo missing; fi
  done | sha256sum | cut -d' ' -f1
}
tunnel_before=$(tunnel_sum)

# ---- instance config, outside the repo ----
install -d -m 700 "$V"
if [ ! -f "$V/env" ]; then
  install -m 600 "$SRC/env.example" "$V/env"
  echo "created $V/env from env.example"
else
  # Make sure the last line is terminated, then append every active KEY=VALUE line of env.example
  # whose key is not in the file yet.
  [ -z "$(tail -c1 "$V/env")" ] || echo >> "$V/env"
  added=""
  while IFS= read -r line; do
    case "$line" in [A-Za-z_]*=*) ;; *) continue ;; esac
    key="${line%%=*}"
    if ! grep -q "^[[:space:]]*${key}[[:space:]]*=" "$V/env"; then
      printf '%s\n' "$line" >> "$V/env"
      added="$added $key"
    fi
  done < "$SRC/env.example"
  [ -z "$added" ] || echo "added missing keys to $V/env:$added"
fi
if [ ! -s "$V/internal_token" ]; then
  (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$V/internal_token")
fi
if [ ! -f "$V/glossary.txt" ]; then
  cat > "$V/glossary.txt" <<'TXT'
# Recognition glossary: one term per line, spelled the way it should appear in transcripts
# (names, product names, jargon). Blank lines and lines starting with # are ignored.
# Restart voice-web after editing: systemctl restart voice-web
TXT
fi
chmod 600 "$V/env" "$V/internal_token" "$V/glossary.txt"
# The tunnel needs the port, the chat for the menu button and its text, and (if the bot token is set here instead of
# in the Telegram plugin's .env) the bot token. It does not get the rest of env, the API keys above all: its unit loads
# this file instead of env. The lines are copied as written, so run_tunnel.sh reads them the way it reads env. An
# unfinished file is never put in place.
(
  umask 077
  : > "$V/tunnel.env.new"
  for key in VOICE_PORT VOICE_ALLOWED_USER VOICE_CHAT_ID VOICE_MENU_TEXT VOICE_BOT_TOKEN; do
    line=$(val "$key")
    if [ -n "$line" ]; then printf '%s=%s\n' "$key" "$line" >> "$V/tunnel.env.new"; fi
  done
  chmod 600 "$V/tunnel.env.new"
  mv -f "$V/tunnel.env.new" "$V/tunnel.env"
)

# ---- vendor files of Live mode ----
# Every line of web/vendor.lock: sha256, file name, npm path. A file that is present and matches is kept;
# otherwise it is downloaded (jsdelivr, then unpkg), checked, and only then moved into place.
# This runs before anything is copied or restarted, so a failure leaves the running installation untouched.
VENDOR="$OPT/web/vendor"
fetch_vendor() {
  local lock="$SRC/web/vendor.lock" sum name path tmp base got ok f keep=" "
  [ -f "$lock" ] || { echo "missing $lock" >&2; return 1; }
  install -d "$VENDOR" || return 1
  while read -r sum name path; do
    case "$sum" in ''|'#'*) continue ;; esac
    if ! [[ "$sum" =~ ^[0-9a-f]{64}$ && "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && -n "$path" ]]; then
      echo "bad line in $lock: $sum $name" >&2; return 1
    fi
    keep="$keep$name "
    if [ -f "$VENDOR/$name" ] && [ "$(sha256sum < "$VENDOR/$name" | cut -d' ' -f1)" = "$sum" ]; then continue; fi
    tmp=$(mktemp "$VENDOR/.download.XXXXXX") || return 1
    ok=0
    for base in https://cdn.jsdelivr.net/npm https://unpkg.com; do
      curl -fsSL --retry 2 --connect-timeout 15 --max-time 300 -o "$tmp" "$base/$path" 2>/dev/null || continue
      got=$(sha256sum < "$tmp" | cut -d' ' -f1)
      if [ "$got" = "$sum" ]; then ok=1; break; fi
      echo "vendor: $name from $base has sha256 $got, expected $sum: rejected" >&2
    done
    if [ "$ok" != 1 ]; then rm -f "$tmp"; echo "ERROR: could not fetch a verified copy of $name ($path)" >&2; return 1; fi
    chmod 644 "$tmp" && mv -f "$tmp" "$VENDOR/$name" || { rm -f "$tmp"; return 1; }
    echo "vendor: fetched $name"
  done < "$lock"
  for f in "$VENDOR"/* "$VENDOR"/.[!.]*; do   # files that are no longer pinned, and leftovers of failed downloads
    [ -f "$f" ] || continue
    case "$keep" in *" ${f##*/} "*) ;; *) rm -f "$f"; echo "vendor: removed ${f##*/}" ;; esac
  done
}
fetch_vendor || { echo "deploy aborted: the vendor files of Live mode could not be prepared" >&2; exit 1; }

# ---- code ----
install -d "$OPT"
# web/vendor/ is managed by fetch_vendor above (a copy in the source tree is ignored by git and by this sync).
rsync -a --delete --exclude __pycache__ --exclude /vendor "$SRC/web/" "$OPT/web/"
# channel/: node_modules and dist/ are never copied (and never deleted here): they are built below.
rsync -a --delete --exclude __pycache__ --exclude node_modules --exclude /dist --exclude bun.lockb "$SRC/channel/" "$OPT/channel/"
rsync -a --delete "$SRC/tunnel/" "$OPT/tunnel/"
chmod +x "$OPT/tunnel/run_tunnel.sh"
# session/: the auth watchdog (run by voice-auth-watch.timer). Its failure never touches voice-web or voice-tunnel.
AUTH_WATCH=1
if install -d "$OPT/session" && rsync -a --delete --exclude __pycache__ "$SRC/session/" "$OPT/session/" && chmod +x "$OPT/session/auth_watch.sh" "$OPT/session/progress_hook.sh"; then :
else AUTH_WATCH=0; echo "WARNING: the auth watchdog (session/) could not be copied to $OPT/session: it is skipped" >&2; fi

# The channel server runs from one bundle, so a session start installs and downloads nothing. The dependencies come
# from the lock file (exact versions, integrity hashes); install scripts are not run. node_modules is removed again.
build_channel() {
  local ch="$OPT/channel" reply
  [ -s "$ch/bun.lock" ] || no_lock "$OPT" "the code is already copied to $OPT, but nothing has been restarted."
  (cd "$ch" && "$BUN" install --frozen-lockfile --ignore-scripts --no-summary >/dev/null) || return 1
  install -d "$ch/dist" || return 1
  (cd "$ch" && "$BUN" build server.ts --target=bun --outfile=dist/server.new.js >/dev/null) || return 1
  # node_modules goes before the smoke test, so a bundle that still needs it is caught here and not by the next session start
  rm -rf "$ch/node_modules" || return 1
  # smoke test of the bundle: it must answer an MCP initialize. VOICE_PORT=1 keeps it away from the real voice-web
  # (it would take an utterance out of the queue). --no-install: without it bun quietly resolves missing packages from its
  # global cache, and a bundle that still needs node_modules would pass here.
  reply=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"deploy","version":"0"}}}' \
    | VOICE_PORT=1 VOICE_ENV_FILE=/dev/null VOICE_TOKEN_FILE=/dev/null timeout 30 "$BUN" --no-install "$ch/dist/server.new.js" 2>/dev/null | head -c 4000 || true)
  case "$reply" in *'"name":"voice"'*) ;; *) rm -f "$ch/dist/server.new.js"; echo "the channel bundle does not answer an MCP initialize without node_modules" >&2; return 1 ;; esac
  mv -f "$ch/dist/server.new.js" "$ch/dist/server.js" || return 1
}
build_channel || die "the channel server could not be built; nothing has been restarted"
cat > "$V/mcp.json" <<JSON
{"mcpServers":{"voice":{"command":"$BUN","args":["$OPT/channel/dist/server.js"]}}}
JSON
chmod 600 "$V/mcp.json"
# Hooks for the main session (restart_main_session.sh passes this file with --settings when the voice channel is
# attached): the progress hook tells voice-web what the session is doing. Rewritten on every run, atomically, mode 600.
# A failure is a warning: the session then simply starts without progress hooks. Without an executable hook script
# there is no such file at all (a stale one is removed), so restart_main_session.sh does not pass --settings.
if [ ! -x "$OPT/session/progress_hook.sh" ]; then
  rm -f "$V/session-settings.json" "$V/session-settings.json.new"
  echo "WARNING: $OPT/session/progress_hook.sh is missing or not executable: no progress hooks (session-settings.json removed)" >&2
elif python3 -I -c '
import json, os, sys
hook, dest = sys.argv[1], sys.argv[2]
cmd = {"type": "command", "command": hook, "timeout": 2}
doc = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [cmd]}], "Stop": [{"hooks": [dict(cmd)]}]}}
tmp = dest + ".new"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(doc, f, indent=1); f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, dest)
' "$OPT/session/progress_hook.sh" "$V/session-settings.json"; then :
else echo "WARNING: $V/session-settings.json could not be written: the main session will start without progress hooks" >&2; fi

# ---- units ----
# The unit files in the repo name the default paths. They are rendered for this instance: the instance directory,
# the code directory and the Telegram plugin's .env (VOICE_TG_ENV_FILE; an empty file if there is none, because a
# credential whose source is missing keeps the unit from starting; the bot token can then be VOICE_BOT_TOKEN).
TG_ENV=$(cfgval VOICE_TG_ENV_FILE); TG_ENV="${TG_ENV:-/root/.claude/channels/telegram/.env}"
if [ ! -r "$TG_ENV" ]; then
  echo "NOTE: $TG_ENV does not exist: the units get an empty file. Put VOICE_BOT_TOKEN into $V/env."
  TG_ENV="$V/telegram.env"
  [ -e "$TG_ENV" ] || install -m 600 /dev/null "$TG_ENV"
fi
case "$TG_ENV$V$OPT" in *[!A-Za-z0-9_./-]*) die "a path (VOICE_DIR, the code directory or VOICE_TG_ENV_FILE) has characters outside A-Za-z0-9_./-: it cannot be put into a unit file" ;; esac
render_unit() {
  sed -e "s|/root/.claude/channels/telegram/.env|$TG_ENV|g" -e "s|/root/.voice|$V|g" -e "s|/opt/voice|$OPT|g" "$SRC/systemd/$1" > "$2"
}
rendered=$(mktemp -d)
trap 'rm -rf "$rendered"' EXIT
render_unit voice-web.service "$rendered/voice-web.service"
render_unit voice-tunnel.service "$rendered/voice-tunnel.service"
if command -v systemd-analyze >/dev/null; then   # a directive systemd does not know is only a warning there: refuse those too
  bad=$(systemd-analyze verify "$rendered/voice-web.service" "$rendered/voice-tunnel.service" 2>&1 | grep -E 'voice-(web|tunnel)\.service' || true)
  [ -z "$bad" ] || { printf '%s\n' "$bad" >&2; die "systemd does not accept the unit files; nothing has been restarted"; }
fi

# The auth watchdog's units are rendered and checked the same way, but a problem here is only a warning: it is skipped
# and voice-web and voice-tunnel are deployed as usual.
if [ "$AUTH_WATCH" = 1 ]; then
  if render_unit voice-auth-watch.service "$rendered/voice-auth-watch.service" && render_unit voice-auth-watch.timer "$rendered/voice-auth-watch.timer"; then
    if command -v systemd-analyze >/dev/null; then
      bad=$(systemd-analyze verify "$rendered/voice-auth-watch.service" "$rendered/voice-auth-watch.timer" 2>&1 | grep -E 'voice-auth-watch\.(service|timer)' || true)
      if [ -n "$bad" ]; then printf '%s\n' "$bad" >&2; AUTH_WATCH=0; echo "WARNING: systemd does not accept the auth watchdog units: it is skipped" >&2; fi
    fi
  else AUTH_WATCH=0; echo "WARNING: the auth watchdog units could not be rendered: it is skipped" >&2; fi
fi

# ---- is voice-web up? (the state step and the services step both ask) ----
PORT=$(cfgval VOICE_PORT); PORT="${PORT:-18200}"
# wait_ready SECONDS: voice-web is active and answers on its port.
wait_ready() {
  local _
  for _ in $(seq 1 "$1"); do
    if systemctl is-active --quiet voice-web.service && curl -fs -o /dev/null -m 3 "http://127.0.0.1:$PORT/"; then return 0; fi
    sleep 1
  done
  return 1
}

# ---- state of voice-web: from $VOICE_DIR/state to its StateDirectory ----
# The old unit is still the installed one here. The state is copied (never moved) while the service is stopped; if the
# copy fails the old service is started again (the unit files and the state are unchanged; the new code is already in
# place, and the old unit runs it). The old directory is removed only after the new service has started and has been
# checked (see below). migrate_state.sh explains what it does with each file.
migrating=0
if bash "$MIGRATE" pending "$OLD_STATE"; then
  migrating=1
  echo "moving the state of voice-web from $OLD_STATE to its StateDirectory ($STATE_PRIVATE)"
  # A unit that is not loaded cannot be stopped (exit 5), and there is nothing running to stop: go on. One that is still
  # active after a failed stop is another matter: its state must not be copied while it writes.
  if ! systemctl stop voice-web.service; then
    systemctl is-active --quiet voice-web.service && die "voice-web could not be stopped, so its state is not copied. Nothing has been restarted; the new code is already in $OPT, and the unit files and the state are unchanged."
    echo "NOTE: voice-web.service could not be stopped (it is not loaded or not running): the state is copied anyway."
  fi
  if ! bash "$MIGRATE" copy "$OLD_STATE" "$STATE_PRIVATE"; then
    systemctl start voice-web.service || true
    if wait_ready "$READY_WAIT"; then
      die "the state could not be copied; $OLD_STATE is untouched and the old voice-web is running again (the new code is already in $OPT and runs under the old unit file; the unit files and the state are unchanged)."
    fi
    echo "ERROR: the state could not be copied, and the old voice-web did not come up when it was started again: VOICE IS DOWN." >&2
    echo "$OLD_STATE is untouched and the unit files are unchanged. Look at: journalctl -u voice-web; then start it by hand: systemctl start voice-web" >&2
    exit 1
  fi
fi

# ---- services ----
# The previous unit files are kept until the new voice-web has been checked. If the new units cannot start it (an exec-time
# failure such as 243/CREDENTIALS or 226/NAMESPACE, or no answer in time, or a last id below the old state's), they are
# put back and the previous voice-web is started again. That works because the previous unit file runs the new server.py
# unchanged (its defaults are the old paths: $VOICE_DIR/state, env, internal_token) and the old state is not removed
# before this check.
saved="$rendered/saved"
mkdir "$saved"
for u in voice-web voice-tunnel; do
  if [ -f "$UNIT_DIR/$u.service" ]; then cp -p "$UNIT_DIR/$u.service" "$saved/$u.service"; fi
done
# put_back UNIT: restore the saved unit file; a link to the runtime directory of the new tunnel that dangles now would
# break the previous run_tunnel.sh, which writes the URL through $VOICE_DIR/url, so it goes.
put_back() {
  if [ -f "$saved/$1.service" ]; then install -m 644 "$saved/$1.service" "$UNIT_DIR/$1.service" || true; fi
}
drop_dangling_url() {
  if [ -L "$V/url" ] && [ ! -e "$V/url" ]; then rm -f "$V/url"; fi
}
# keep_saved_units: the temporary directory goes when the script ends, so when a way back did not work the previous unit
# files are copied to $VOICE_DIR/units.saved for the manual steps.
keep_saved_units() {
  local d="$V/units.saved" f
  if install -d -m 700 "$d"; then
    for f in "$saved"/*.service; do
      if [ -f "$f" ]; then install -m 600 "$f" "$d/${f##*/}" || true; fi
    done
    echo "The previous unit files are kept in $d (mode 600)." >&2
  fi
}
# fail_back REASON: the new voice-web did not work out. Say why, put the previous unit files back, start the previous
# voice-web again, and stop the deploy. Voice is never left down without a message.
fail_back() {
  echo "ERROR: $1" >&2
  if [ ! -f "$saved/voice-web.service" ]; then
    echo "There was no previous voice-web unit to go back to (a first install). Look at: journalctl -u voice-web" >&2
    exit 1
  fi
  echo "Going back: the previous unit files are put back and the previous voice-web is started again." >&2
  put_back voice-web
  put_back voice-tunnel
  systemctl daemon-reload || true
  drop_dangling_url
  systemctl restart voice-web.service || true
  if wait_ready "$READY_WAIT"; then
    echo "The previous voice-web is running again on the previous unit files." >&2
    # An older unit does not set VOICE_STATE_DIR, so the new server.py keeps its state where the old code did.
    if ! grep -q 'VOICE_STATE_DIR' "$saved/voice-web.service"; then
      echo "Its kill switch is the file $OLD_STATE/DISABLED, not /var/lib/voice/DISABLED (the previous unit does not set VOICE_STATE_DIR)." >&2
    fi
    [ "$migrating" != 1 ] || echo "The old state is untouched in $OLD_STATE; this run's copy in $STATE_PRIVATE is merged by the next deploy (an older file there is kept as <name>.premigration)." >&2
    echo "The new code is already in $OPT and the previous unit file runs it. Fix the cause (journalctl -u voice-web), then run deploy.sh again." >&2
  else
    echo "The previous voice-web did not come up either: VOICE IS DOWN. Look at: journalctl -u voice-web" >&2
    keep_saved_units
    echo "To go back by hand: put the previous unit files into $UNIT_DIR ($V/units.saved/*.service, or git show <previous commit>:systemd/voice-web.service, the same for voice-tunnel), rm -f $V/url, systemctl daemon-reload, systemctl restart voice-web voice-tunnel." >&2
  fi
  exit 1
}
# fail_back_tunnel REASON: only the tunnel unit is put back (voice-web keeps the new units: its old state is gone by now).
# Order: the previous unit file, daemon-reload, stop (the new unit may be in a restart loop; its runtime directory goes
# with it), drop the link into that directory if it dangles, start, and look at the state a moment later (voice-tunnel is
# Type=simple: a start that returns 0 proves nothing).
fail_back_tunnel() {
  echo "ERROR: $1" >&2
  if [ -f "$saved/voice-tunnel.service" ]; then
    put_back voice-tunnel
    systemctl daemon-reload || true
    systemctl stop voice-tunnel.service || true
    drop_dangling_url
    systemctl start voice-tunnel.service || true
    sleep 1
    if systemctl is-active --quiet voice-tunnel.service; then
      echo "The previous voice-tunnel unit is running again. Its public URL is new: reopen the Mini App from the bot menu. voice-web runs on the new units." >&2
    else
      echo "The previous voice-tunnel unit did not start either: the Mini App has no public URL now. Look at: journalctl -u voice-tunnel" >&2
      keep_saved_units
    fi
  else
    echo "There was no previous voice-tunnel unit to go back to. Look at: journalctl -u voice-tunnel" >&2
  fi
  exit 1
}

# The watchdog's unit files go in first, so that the daemon-reload below loads them too (nothing is started here).
if [ "$AUTH_WATCH" = 1 ] && ! { install -m 644 "$rendered/voice-auth-watch.service" "$UNIT_DIR/voice-auth-watch.service" &&
                                 install -m 644 "$rendered/voice-auth-watch.timer" "$UNIT_DIR/voice-auth-watch.timer"; }; then
  AUTH_WATCH=0; echo "WARNING: the auth watchdog units could not be installed: it is skipped" >&2
fi
install -m 644 "$rendered/voice-web.service" "$UNIT_DIR/voice-web.service" &&
  install -m 644 "$rendered/voice-tunnel.service" "$UNIT_DIR/voice-tunnel.service" &&
  systemctl daemon-reload &&
  systemctl enable voice-web.service voice-tunnel.service &&
  systemctl restart voice-web.service ||
  fail_back "systemd could not install or start the new unit files (journalctl -u voice-web)."
tunnel_after=$(tunnel_sum)
wait_ready "$READY_WAIT" || fail_back "voice-web did not come up on port $PORT within $READY_WAIT s (journalctl -u voice-web)."

if [ -d "$OLD_STATE" ]; then
  if [ "$migrating" = 1 ]; then
    # The service must have read the migrated state: its last id may not be lower than the highest id of the old one.
    want=$(bash "$MIGRATE" maxid "$OLD_STATE")
    got=$(printf 'header = "X-Internal-Token: %s"\nurl = "http://127.0.0.1:%s/internal/inbox?after=-1"\n' "$(cat "$V/internal_token")" "$PORT" \
      | curl -fs -m 5 -K - | python3 -I -c 'import json,sys; print(int(json.load(sys.stdin)["last_id"]))' 2>/dev/null || echo "")
    if ! [[ "$got" =~ ^[0-9]+$ ]] || [ "$got" -lt "$want" ]; then
      # (a channel server that is already running would never see an utterance with an id below its own)
      fail_back "voice-web reports last id '${got:-?}' but the old state had $want: it did not read the migrated state, so $OLD_STATE is not removed"
    fi
    echo "voice-web is up on the migrated state (last id $got)"
  fi
  bash "$MIGRATE" cleanup "$OLD_STATE"
fi

# What the tunnel was last started with (run_tunnel.sh, its unit, tunnel.env) is recorded in $VOICE_DIR/.tunnel-sum after a
# successful start, or when the tunnel was found unchanged and running at the end of a run. Compared with that, a change an
# earlier run left behind (it wrote tunnel.env and the script and then failed before this step) is applied by the next run
# instead of being taken for "unchanged". Without the file (the first run of this logic) the checksum taken at the start of
# this run is the reference, as it was before: a missing file alone restarts nothing.
TUNNEL_SUM_FILE="$V/.tunnel-sum"
record_tunnel_sum() {
  (umask 077; printf '%s\n' "$tunnel_after" > "$TUNNEL_SUM_FILE.new" && mv -f "$TUNNEL_SUM_FILE.new" "$TUNNEL_SUM_FILE") ||
    echo "WARNING: could not write $TUNNEL_SUM_FILE: the next run may restart the tunnel for nothing" >&2
}
tunnel_ref=$(cat "$TUNNEL_SUM_FILE" 2>/dev/null || true)
[ -n "$tunnel_ref" ] || tunnel_ref="$tunnel_before"
if [ "$tunnel_ref" != "$tunnel_after" ] || ! systemctl is-active --quiet voice-tunnel.service; then
  old_url=$(cat "$V/url" 2>/dev/null || true)
  restarted_at=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart voice-tunnel.service || fail_back_tunnel "voice-tunnel did not start (journalctl -u voice-tunnel)."
  echo "voice-tunnel restarted: the public URL has changed, reopen the Mini App from the bot menu"
  new_url=""
  for _ in $(seq 1 "$URL_WAIT"); do
    new_url=$(cat "$V/url" 2>/dev/null || true)
    if [ -n "$new_url" ] && [ "$new_url" != "$old_url" ]; then break; fi
    sleep 1
  done
  # voice-tunnel is Type=simple: the restart above returns 0 even when the unit dies at exec time (243/CREDENTIALS,
  # 226/NAMESPACE) or run_tunnel.sh exits at once, and systemd then keeps trying every 5 s. A unit that is not running
  # now has not come up: the previous one goes back. A unit that runs but has no new URL yet is only a warning.
  if ! systemctl is-active --quiet voice-tunnel.service; then
    fail_back_tunnel "voice-tunnel is not running after its restart: it died while starting (journalctl -u voice-tunnel)."
  fi
  if [ -n "$new_url" ] && [ "$new_url" != "$old_url" ]; then echo "new public URL: $new_url"; else echo "WARNING: no new tunnel URL after $URL_WAIT s (journalctl -u voice-tunnel)" >&2; fi
  record_tunnel_sum
  # The tunnel script sets the Telegram menu button right after the URL is known and logs "menu button set". Not fatal:
  # the URL works either way, but a button that points at the old URL is why the Mini App then does not open. (grep reads
  # all of the output: with -q it would quit early and journalctl, killed by SIGPIPE, would fail the pipeline under pipefail.)
  if command -v journalctl >/dev/null; then
    seen=0
    for _ in $(seq 1 "$MENU_WAIT"); do
      if { journalctl -u voice-tunnel.service --since "$restarted_at" --no-pager -o cat 2>/dev/null || true; } | grep 'menu button set' >/dev/null; then seen=1; break; fi
      sleep 1
    done
    if [ "$seen" = 1 ]; then echo "the menu button was set (journal of voice-tunnel)"; else echo "WARNING: no 'menu button set' line in the journal of voice-tunnel after $MENU_WAIT s: the bot menu may still open the old URL (journalctl -u voice-tunnel)" >&2; fi
  fi
else
  echo "voice-tunnel unchanged: left running, public URL kept"
  record_tunnel_sum
fi

# ---- auth watchdog timer (the last step; a failure is a warning) ----
# The units are always installed; the timer runs only with VOICE_AUTH_WATCH=1 in the env file (opt-in), and is
# switched off again when that line is removed or is not 1.
if [ "$AUTH_WATCH" = 1 ]; then
  if [ "$(val VOICE_AUTH_WATCH)" = 1 ]; then
    if systemctl enable --now voice-auth-watch.timer; then echo "auth watchdog: voice-auth-watch.timer enabled"
    else echo "WARNING: voice-auth-watch.timer could not be enabled: the auth watchdog is not running (voice is unaffected)" >&2; fi
  elif systemctl is-enabled --quiet voice-auth-watch.timer 2>/dev/null; then
    if systemctl disable --now voice-auth-watch.timer; then echo "auth watchdog: voice-auth-watch.timer disabled (VOICE_AUTH_WATCH is not 1)"
    else echo "WARNING: voice-auth-watch.timer could not be disabled" >&2; fi
  else
    echo "auth watchdog: off (set VOICE_AUTH_WATCH=1 in $V/env and run deploy.sh to turn it on)"
  fi
fi

# ---- reminders about required settings ----
[ -n "$(val VOICE_ALLOWED_USER)" ] ||
  echo "NOTE: VOICE_ALLOWED_USER is empty in $V/env: voice-web rejects everyone until you set it."
[ -n "$(val OPENROUTER_API_KEY)" ] ||
  echo "NOTE: no API key in $V/env: speech recognition and synthesis run in FAKE mode."
echo "deployed"
