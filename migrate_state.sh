#!/bin/bash
# Moves the state of voice-web from its old directory (/root/.voice/state, where voice-web used to run as root)
# into its new one: the StateDirectory of the hardened unit (/var/lib/voice, physically /var/lib/private/voice).
# deploy.sh calls it; it can also be run by hand. The state is inbox.jsonl, last_id, the kill switch file DISABLED
# and the reply audio in audio/. systemd hands the copied files to the unit's dynamic user when the unit starts.
#
#   migrate_state.sh copy    OLD NEW   copy what OLD holds into NEW. Nothing in OLD is changed. Nothing in NEW is
#                                      overwritten: a file that exists in NEW and differs stays, and the old one is
#                                      saved next to it as <name>.premigration. last_id becomes the larger of the two.
#                                      On success OLD gets a marker file saying that it has been copied.
#                                      The *.premigration files hold whole old transcripts and are not pruned here: voice-web
#                                      deletes them at start and daily once they are older than VOICE_INBOX_DAYS (by
#                                      modification time, which they keep from the file they copy).
#   migrate_state.sh pending OLD       exit 0 if OLD holds state that would be copied, 1 if not
#   migrate_state.sh maxid   DIR       print the highest utterance id recorded in DIR (last_id and inbox.jsonl), 0 if none
#   migrate_state.sh cleanup OLD       remove what was copied out of OLD, then OLD itself if nothing else is in it.
#                                      Refuses (exit 1) when OLD has state but the marker is missing.
#
# Safe to run any number of times. Exit status: 0 done (or nothing to do), 1 failed (nothing was removed), 2 usage.
set -u

MARKER=.copied-to-state-directory
KNOWN="inbox.jsonl last_id DISABLED audio"

say() { printf 'migrate_state: %s\n' "$*"; }
fail() { printf 'migrate_state: ERROR: %s\n' "$*" >&2; }

# is_count STR: a plain number that fits comfortably into shell arithmetic
is_count() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "${#1}" -le 15 ]; }

# atomic_copy SRC DST: copy keeping the modification time (the audio retention goes by it), mode 600, then rename
atomic_copy() {
  local tmp="$2.tmp.$$"
  if cp --preserve=timestamps -- "$1" "$tmp" && chmod 600 -- "$tmp" && mv -f -- "$tmp" "$2"; then return 0; fi
  rm -f -- "$tmp"
  return 1
}

# preserve SRC DST: make sure the content of SRC is in the new place. DST (the file that is already there) wins;
# if it differs, SRC is saved as DST.premigration. Returns 0 when SRC's content is safe in the new directory.
preserve() {
  local src="$1" dst="$2" side
  if [ ! -e "$dst" ]; then
    atomic_copy "$src" "$dst" && cmp -s -- "$src" "$dst"
    return
  fi
  cmp -s -- "$src" "$dst" && return 0
  side="$dst.premigration"
  if [ -e "$side" ] && ! cmp -s -- "$src" "$side"; then side="$side.$(date +%s)"; fi
  if [ -e "$side" ] && cmp -s -- "$src" "$side"; then return 0; fi
  say "$dst exists and differs: it stays, the old file is saved as $side"
  atomic_copy "$src" "$side" && cmp -s -- "$src" "$side"
}

cmd_copy() {
  local old="$1" new="$2" item f b o n best present=0 rc=0
  [ -d "$old" ] || { say "nothing to migrate: $old does not exist"; return 0; }
  for item in $KNOWN; do [ -e "$old/$item" ] && present=1; done
  [ "$present" = 1 ] || { say "nothing to migrate: $old holds no state"; return 0; }
  [ -d "$(dirname -- "$new")" ] || install -d -m 700 -- "$(dirname -- "$new")" || { fail "cannot create $(dirname -- "$new")"; return 1; }
  [ -d "$new" ] || install -d -m 700 -- "$new" || { fail "cannot create $new"; return 1; }

  for item in inbox.jsonl DISABLED; do
    [ -f "$old/$item" ] || continue
    if preserve "$old/$item" "$new/$item"; then say "$item: in place"; else fail "could not copy $old/$item"; rc=1; fi
  done

  if [ -f "$old/last_id" ]; then
    o=$(tr -d ' \t\r\n' < "$old/last_id"); n=""
    [ -f "$new/last_id" ] && n=$(tr -d ' \t\r\n' < "$new/last_id")
    is_count "$o" || { [ -z "$o" ] || say "ignoring $old/last_id: not a number"; o=""; }
    is_count "$n" || n=""
    best="$o"
    if [ -n "$n" ] && { [ -z "$best" ] || [ "$n" -gt "$best" ]; }; then best="$n"; fi
    if [ -n "$best" ] && [ "$best" != "$n" ]; then
      if printf '%s\n' "$best" > "$new/last_id.tmp.$$" && chmod 600 -- "$new/last_id.tmp.$$" && mv -f -- "$new/last_id.tmp.$$" "$new/last_id"; then
        say "last_id: $best"
      else
        rm -f -- "$new/last_id.tmp.$$"; fail "could not write $new/last_id"; rc=1
      fi
    else
      say "last_id: ${best:-none}, already in place"
    fi
  fi

  if [ -d "$old/audio" ]; then
    install -d -m 700 -- "$new/audio" || { fail "cannot create $new/audio"; rc=1; }
    for f in "$old"/audio/*; do
      [ -f "$f" ] || continue
      b=${f##*/}
      [ -e "$new/audio/$b" ] && continue     # the same name is the same recording (random UUID)
      if ! { atomic_copy "$f" "$new/audio/$b" && cmp -s -- "$f" "$new/audio/$b"; }; then fail "could not copy $f"; rc=1; fi
    done
    say "audio: in place"
  fi

  [ "$rc" = 0 ] || return 1
  date -u +%Y-%m-%dT%H:%M:%SZ > "$old/$MARKER" || { fail "cannot write the marker in $old"; return 1; }
  say "state of $old is in $new (the old files stay until cleanup)"
}

cmd_pending() {
  local item
  [ -d "$1" ] || return 1
  for item in $KNOWN; do [ -e "$1/$item" ] && return 0; done
  return 1
}

cmd_maxid() {
  python3 -I - "$1" <<'PY'
import json, os, sys
d, top = sys.argv[1], 0
try:
    top = max(top, int(open(os.path.join(d, "last_id")).read().strip() or 0))
except (OSError, ValueError):
    pass
try:
    with open(os.path.join(d, "inbox.jsonl"), encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                top = max(top, int(json.loads(line)["id"]))
            except (ValueError, KeyError, TypeError):
                pass
except OSError:
    pass
print(top)
PY
}

cmd_cleanup() {
  local old="$1" item any=0
  [ -d "$old" ] || { say "nothing to clean up: $old does not exist"; return 0; }
  for item in $KNOWN; do [ -e "$old/$item" ] && any=1; done
  if [ "$any" = 1 ] && [ ! -f "$old/$MARKER" ]; then
    fail "refusing to remove $old: its state was not copied (no $MARKER there)"
    return 1
  fi
  rm -f -- "$old/inbox.jsonl" "$old/last_id" "$old/DISABLED" "$old/$MARKER"
  rm -f -- "$old"/audio/*.mp3 "$old"/audio/*.wav
  rmdir -- "$old/audio" 2>/dev/null
  if rmdir -- "$old" 2>/dev/null; then
    say "removed $old"
  else
    say "$old still holds other files and was kept: $(ls -A -- "$old" | tr '\n' ' ')"
  fi
}

case "${1:-}" in
  copy)    [ $# = 3 ] || { echo "usage: $0 copy OLD NEW" >&2; exit 2; };  cmd_copy "$2" "$3" ;;
  pending) [ $# = 2 ] || { echo "usage: $0 pending OLD" >&2; exit 2; };   cmd_pending "$2" ;;
  maxid)   [ $# = 2 ] || { echo "usage: $0 maxid DIR" >&2; exit 2; };     cmd_maxid "$2" ;;
  cleanup) [ $# = 2 ] || { echo "usage: $0 cleanup OLD" >&2; exit 2; };   cmd_cleanup "$2" ;;
  *)       echo "usage: $0 copy OLD NEW | pending OLD | maxid DIR | cleanup OLD" >&2; exit 2 ;;
esac
