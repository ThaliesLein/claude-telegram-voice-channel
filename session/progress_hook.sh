#!/bin/bash
# Claude Code hook (PreToolUse, Stop, SubagentStart, SubagentStop): tells voice-web what the session is doing, so the Voice
# app can show live progress. It sends ONLY small fixed fields: {"kind":"<k>"} with k one of read edit run search web agent
# telegram voice other idle agent_start agent_stop, plus "who":"agent" when a PreToolUse comes from inside a helper (the
# input has an agent_id) and "bg":N (0..20, the number of running subagent/workflow/teammate entries of the Stop input's
# background_tasks) on idle. No tool input, no path, no command, no description, no text, no output ever leaves this script.
# SubagentStart/SubagentStop of Claude Code's internal agents (empty agent_type) are ignored.
#
# It must never affect the session: it prints nothing (the stdout of some hooks reaches the model), always exits 0,
# swallows every error and returns at once: it reads only the first 64 KB of the hook JSON (the event and tool names are
# looked for in the first 4096 bytes, they come before the tool input, which can be megabytes; agent_id, agent_type and
# background_tasks in the 64 KB), drains the rest of its input so that Claude Code never gets a broken pipe, and sends the request from a detached background process (bounded: connect 0.5 s, whole request
# 1 s, alarm at 2 s).
#
# Settings: VOICE_PORT (default 18200) and VOICE_TOKEN_FILE (default $VOICE_DIR/internal_token) come from the
# process environment, else from KEY= lines of $VOICE_DIR/env (parsed, never sourced). VOICE_DIR defaults to /root/.voice.
# The token is sent as the X-Internal-Token header of an HTTP request made in-process: it is in no command line.
# Test hook (environment only): VOICE_PROGRESS_HOST, only 127.0.0.1, localhost or ::1 are accepted (default 127.0.0.1): the
# token must never be sent anywhere else.
exec >/dev/null 2>&1
all=$(head -c 65536)
cat >/dev/null
first="${all:0:4096}"
ev="" tool="" who="" data=""
[[ "$first" =~ \"hook_event_name\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9_]+)\" ]] && ev="${BASH_REMATCH[1]}"
[[ "$first" =~ \"tool_name\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9_]+)\" ]] && tool="${BASH_REMATCH[1]}"
case "$ev" in
  Stop) kind=idle data="$all" ;;
  SubagentStart|SubagentStop)
    # only real helpers: Claude Code's internal agents have an empty agent_type
    [[ "$all" =~ \"agent_type\"[[:space:]]*:[[:space:]]*\"[^\"]+\" ]] || exit 0
    if [ "$ev" = SubagentStart ]; then kind=agent_start; else kind=agent_stop; fi ;;
  PreToolUse)
    [[ "$all" =~ \"agent_id\"[[:space:]]*:[[:space:]]*\"[^\"]+\" ]] && who=agent
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

def bg_running(text):
    # running subagent/workflow/teammate entries of "background_tasks" (only those three fields are looked at); a missing or
    # unreadable list counts as none. The array is decoded on its own, so text cut off at 64 KB elsewhere does not matter.
    m = re.search(r"\"background_tasks\"\s*:\s*(?=\[)", text)
    if not m:
        return 0
    arr, _ = json.JSONDecoder().raw_decode(text, m.end())
    n = sum(1 for t in arr if isinstance(t, dict) and t.get("status") == "running" and t.get("type") in ("subagent", "workflow", "teammate"))
    return min(n, 20)

def main():
    signal.alarm(2)
    kind, host, who = sys.argv[1], sys.argv[2], sys.argv[3]
    body = {"kind": kind}
    if who == "agent":
        body["who"] = "agent"
    if kind == "idle":
        try:
            body["bg"] = bg_running(sys.stdin.read(65536))
        except Exception:
            pass
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
    c.request("POST", "/internal/progress", body=json.dumps(body, separators=(",", ":")),
              headers={"X-Internal-Token": token, "Content-Type": "application/json"})
    c.getresponse().read()
    c.close()

try:
    main()
except BaseException:
    pass
' "$kind" "$host" "$who" <<<"$data" >/dev/null 2>&1 & ) </dev/null >/dev/null 2>&1
exit 0
