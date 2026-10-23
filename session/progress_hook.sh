#!/bin/bash
# Claude Code hook (PreToolUse and Stop): tells voice-web what the session is doing, so the Voice app can show live
# progress. It sends ONLY {"kind":"<k>"} with k one of read edit run search web agent telegram voice other idle:
# no tool input, no path, no command, no output ever leaves this script.
#
# It must never affect the session: it prints nothing (the stdout of some hooks reaches the model), always exits 0,
# swallows every error and returns at once: it reads only the first 4096 bytes of the hook JSON (the event and tool names
# come first, before the tool input, which can be megabytes), drains the rest of its input so that Claude Code never
# gets a broken pipe, and sends the request from a detached background process (bounded: connect 0.5 s, whole request
# 1 s, alarm at 2 s).
#
# Settings: VOICE_PORT (default 18200) and VOICE_TOKEN_FILE (default $VOICE_DIR/internal_token) come from the
# process environment, else from KEY= lines of $VOICE_DIR/env (parsed, never sourced). VOICE_DIR defaults to /root/.voice.
# The token is sent as the X-Internal-Token header of an HTTP request made in-process: it is in no command line.
# Test hook (environment only): VOICE_PROGRESS_HOST, only 127.0.0.1, localhost or ::1 are accepted (default 127.0.0.1): the
# token must never be sent anywhere else.
exec >/dev/null 2>&1
first=$(head -c 4096)
cat >/dev/null
ev="" tool=""
[[ "$first" =~ \"hook_event_name\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9_]+)\" ]] && ev="${BASH_REMATCH[1]}"
[[ "$first" =~ \"tool_name\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9_]+)\" ]] && tool="${BASH_REMATCH[1]}"
case "$ev" in
  Stop) kind=idle ;;
  PreToolUse)
    case "$tool" in
      Read|NotebookRead) kind=read ;;
      Edit|Write|MultiEdit|NotebookEdit) kind=edit ;;
      Bash|BashOutput|KillShell|Monitor) kind=run ;;
      Grep|Glob|LS|ToolSearch) kind=search ;;
      WebFetch|WebSearch) kind=web ;;
      Agent|Task|Workflow|SendMessage) kind=agent ;;
      mcp__plugin_telegram_*) kind=telegram ;;
      mcp__voice__*) kind=voice ;;
      *) kind=other ;;
    esac ;;
  *) exit 0 ;;
esac
host="${VOICE_PROGRESS_HOST:-127.0.0.1}"
case "$host" in 127.0.0.1|localhost|::1) ;; *) host=127.0.0.1 ;; esac
# the request is made by a detached child, so the hook is done in a few milliseconds whatever the server does
( python3 -I -c '
import http.client, json, os, re, signal, sys

def main():
    signal.alarm(2)
    kind, host = sys.argv[1], sys.argv[2]
    vdir = os.environ.get("VOICE_DIR") or "/root/.voice"
    def conf(key, default):
        v = os.environ.get(key, "")
        if not v:
            try:
                for line in open(os.path.join(vdir, "env"), encoding="utf-8", errors="replace"):
                    m = re.match(r"\s*" + key + r"\s*=\s*(.*?)\s*$", line)
                    if m:
                        v = m.group(1).strip("\"\x27")
            except OSError:
                pass
        return v or default
    port = conf("VOICE_PORT", "18200")
    if not port.isdigit():
        return
    token = open(conf("VOICE_TOKEN_FILE", os.path.join(vdir, "internal_token")), encoding="utf-8").read().strip()
    if not token:
        return
    c = http.client.HTTPConnection(host, int(port), timeout=0.5)
    c.connect()
    c.sock.settimeout(1.0)
    c.request("POST", "/internal/progress", body=json.dumps({"kind": kind}, separators=(",", ":")),
              headers={"X-Internal-Token": token, "Content-Type": "application/json"})
    c.getresponse().read()
    c.close()

try:
    main()
except BaseException:
    pass
' "$kind" "$host" </dev/null >/dev/null 2>&1 & ) </dev/null >/dev/null 2>&1
exit 0
