#!/usr/bin/env python3
"""Tests of the session helpers: the MCP cache cleanup and the post-start checks of restart_main_session.sh, and
session/auth_watch.sh. Nothing here touches the machine's tmux sessions or the network: a private tmux server
(tmux -L <random socket>), fake files in a temporary directory and stubs for curl. Prints ALL PASSED."""
import http.server, json, os, shutil, stat, subprocess, sys, tempfile, threading, time, uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESTART = os.path.join(ROOT, "restart_main_session.sh")
WATCH = os.path.join(ROOT, "session", "auth_watch.sh")
HOOK = os.path.join(ROOT, "session", "progress_hook.sh")
FAILS = []
TOKEN = "123456789:AAFakeTokenForTestsOnly_abc-DEF"


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + str(detail)[:300]))
    if not ok:
        FAILS.append(name)


def run(cmd, env=None, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env, **kw)


tmp = tempfile.mkdtemp(prefix="voice-session-test.")
SOCK = "vt" + uuid.uuid4().hex[:10]
BASE_ENV = {"PATH": os.environ["PATH"], "HOME": tmp, "LANG": "C"}


def cleanup():
    subprocess.run(["tmux", "-L", SOCK, "kill-server"], capture_output=True)
    shutil.rmtree(tmp, ignore_errors=True)


def tmux(*a):
    return run(["tmux", "-L", SOCK, *a], env={**BASE_ENV})


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write(text)
    if mode is not None:
        os.chmod(path, mode)


try:
    # ------------------------------------------------------------------------------------------------ syntax
    for s in (RESTART, WATCH, HOOK):
        r = run(["bash", "-n", s])
        check(f"bash -n {os.path.relpath(s, ROOT)}", r.returncode == 0, r.stderr)

    # ------------------------------------------------------------------------------------------------ cache cleanup
    cfg = os.path.join(tmp, "cfg")
    os.makedirs(cfg)
    cache = os.path.join(cfg, "mcp-needs-auth-cache.json")

    def clear(env_extra=None):
        env = {**BASE_ENV, "CLAUDE_CONFIG_DIR": cfg, "RESTART_LIB_ONLY": "1", **(env_extra or {})}
        return run(["bash", "-c", f'source "{RESTART}"; clear_mcp_cache'], env=env)

    r = clear()
    check("cache: missing file is skipped silently", r.returncode == 0 and r.stdout == "" and not os.path.exists(cache), r.stdout + r.stderr)

    other = {"plugin:slack:slack": {"timestamp": 1}, "claude.ai Gmail": {"timestamp": 2},
             # names that merely contain the words stay: only the Telegram plugin and the voice server are ours
             "claude.ai Telegram": {"timestamp": 5}, "my-voice-notes": {"timestamp": 6}, "voicemail": {"timestamp": 7},
             "plugin:slack:telegram-bridge": {"timestamp": 8}, "Voice": {"timestamp": 9}, "server:voices": {"timestamp": 10}}
    write(cache, json.dumps({"plugin:telegram:telegram": {"timestamp": 3}, "voice": {"timestamp": 4}, "server:voice": {"timestamp": 11}, **other}), 0o600)
    ino = os.stat(cache).st_ino
    r = clear()
    got = json.load(open(cache))
    check("cache: the plugin:telegram* and the voice / server:voice entries removed, look-alike names kept, count logged", got == other and r.stdout.strip() == "mcp cache: removed 3 entries", r.stdout + r.stderr)
    check("cache: other keys untouched", got == other)
    check("cache: mode kept (600) and file replaced atomically (new inode)", stat.S_IMODE(os.stat(cache).st_mode) == 0o600 and os.stat(cache).st_ino != ino)
    bak = cache + ".bak"
    check("cache: .bak kept for a private file, with mode 600", os.path.exists(bak) and stat.S_IMODE(os.stat(bak).st_mode) == 0o600)
    check("cache: no temporary file left", [f for f in os.listdir(cfg) if f.startswith(".mcp-cache.")] == [])
    r = clear()
    check("cache: second run has nothing to clear", r.stdout.strip() == "mcp cache: nothing to clear", r.stdout)

    os.unlink(bak)
    write(cache, json.dumps({"plugin:telegram:telegram": 1, **other}), 0o644)
    r = clear()
    check("cache: singular wording", r.stdout.strip() == "mcp cache: removed 1 entry", r.stdout)
    check("cache: no .bak for a world-readable file, mode kept", not os.path.exists(bak) and stat.S_IMODE(os.stat(cache).st_mode) == 0o644)

    for label, text in (("garbage", "{not json"), ("a list", '["telegram"]')):
        write(cache, text, 0o600)
        r = clear()
        check(f"cache: {label} is left alone", open(cache).read() == text and r.returncode == 0 and "nothing to clear" in r.stdout, r.stdout + r.stderr)

    # ------------------------------------------------------------------------------------------------ post-start checks
    stubs = os.path.join(tmp, "stubs")
    os.makedirs(stubs)
    fake_bun = os.path.join(stubs, "bun")
    shutil.copy("/bin/bash", fake_bun)          # a process whose name is "bun"
    mcp = os.path.join(tmp, "mcp.json")
    write(mcp, json.dumps({"mcpServers": {"voice": {"command": fake_bun, "args": ["/opt/x/channel/dist/server.js"]}}}))

    def lib(snippet, env_extra=None):
        env = {**BASE_ENV, "RESTART_LIB_ONLY": "1", "RESTART_WAIT_TRIES": "3", "RESTART_WAIT_STEP": "0.3", **(env_extra or {})}
        return run(["bash", "-c", f'source "{RESTART}"; {snippet}'], env=env)

    r = lib(f'voice_target "{mcp}"')
    check("voice_target: reads command and script from mcp.json", r.stdout.strip() == "bun|/opt/x/channel/dist/server.js", r.stdout + r.stderr)
    r = lib(f'voice_target "{tmp}/nope.json"')
    check("voice_target: defaults when mcp.json is unusable", r.stdout.strip() == "bun|channel/dist/server.js", r.stdout)

    def pane_pid(name):
        return tmux("display-message", "-p", "-t", f"={name}:", "#{pane_pid}").stdout.strip()

    # session "good": pane runs a fake bun with the voice marker; session "bad": a fake bun with another script;
    # session "other": the marker process, but under a different pane
    tmux("new-session", "-d", "-s", "good", f"{fake_bun} -c 'sleep 60; sleep 0' /opt/x/channel/dist/server.js")
    tmux("new-session", "-d", "-s", "bad", f"{fake_bun} -c 'sleep 60; sleep 0' /opt/x/other.js")
    time.sleep(0.8)
    good, bad = pane_pid("good"), pane_pid("bad")
    r = lib(f'wait_voice {good} "{mcp}"')
    check("wait_voice: OK for a server below the pane", r.returncode == 0 and r.stdout.startswith("voice channel: OK"), r.stdout + r.stderr)
    r = lib(f'wait_voice {bad} "{mcp}"')
    check("wait_voice: FAIL when the process under the pane runs something else", r.returncode == 1 and r.stdout.startswith("voice channel: FAIL"), r.stdout + r.stderr)
    r = lib(f'wait_voice {"999999"} "{mcp}"')
    check("wait_voice: FAIL for a pane that is not an ancestor", r.returncode == 1 and "FAIL" in r.stdout, r.stdout)

    # whole script, with stubs: tmux (private server), systemctl, claude; fake transcript; --no-voice and voice
    home = os.path.join(tmp, "home")
    vdir = os.path.join(tmp, "vdir")
    os.makedirs(vdir)
    sid = "11111111-2222-3333-4444-555555555555"
    work = os.path.join(tmp, "work")
    os.makedirs(work)
    proj = "".join(c if c.isalnum() else "-" for c in work)
    write(os.path.join(home, ".claude", "projects", proj, sid + ".jsonl"), "{}\n")
    write(os.path.join(home, ".claude", "mcp-needs-auth-cache.json"), json.dumps({"plugin:telegram:telegram": 1, "keep": 2}), 0o600)
    write(os.path.join(vdir, "mcp.json"), json.dumps({"mcpServers": {"voice": {"command": fake_bun, "args": ["/opt/x/channel/dist/server.js"]}}}))
    write(os.path.join(stubs, "tmux"), f'#!/bin/bash\nexec /usr/bin/tmux -L {SOCK} "$@"\n', 0o755)
    write(os.path.join(stubs, "systemctl"), "#!/bin/bash\nexit 0\n", 0o755)
    # the "claude" stub plays a session that has the voice server (and no Telegram plugin: no token in the .env => check skipped)
    argv_log = os.path.join(tmp, "claude.argv")
    write(os.path.join(stubs, "claude-ok"), f"#!/bin/bash\necho \"$@\" > {argv_log}\n{fake_bun} -c 'sleep 60; sleep 0' /opt/x/channel/dist/server.js\n", 0o755)
    write(os.path.join(stubs, "claude-nothing"), f"#!/bin/bash\necho \"$@\" > {argv_log}\nsleep 60\n", 0o755)
    tg_env = os.path.join(tmp, "tg.env")
    write(tg_env, "# no token\n", 0o600)

    def full(claude, *args):
        tmux("kill-server")
        env = {**BASE_ENV, "PATH": stubs + ":" + os.environ["PATH"], "HOME": home, "VOICE_DIR": vdir, "CLAUDE_SESSION_ID": sid,
               "CLAUDE_WORKDIR": work, "CLAUDE_BIN": os.path.join(stubs, claude), "TELEGRAM_ENV_FILE": tg_env,
               "TMUX_SESSION": "main", "RESTART_WAIT_TRIES": "4", "RESTART_WAIT_STEP": "0.3"}
        return run(["bash", RESTART, *args], env=env)

    # the stubbed claude ignores its flags; /usr/bin/tmux -L keeps the run off every real session
    r = full("claude-ok")
    check("restart: no --settings while session-settings.json does not exist", "--settings" not in open(argv_log).read(), open(argv_log).read())
    write(os.path.join(vdir, "session-settings.json"), "{}", 0o600)
    r = full("claude-ok")
    a = open(argv_log).read()
    check("restart: with voice and the file present, --settings <file> is passed", f"--settings {vdir}/session-settings.json" in a, a)
    r = full("claude-nothing", "--no-voice")
    time.sleep(0.3)
    check("restart: --no-voice does not pass --settings", "--settings" not in open(argv_log).read() and "--mcp-config" not in open(argv_log).read(), open(argv_log).read())
    write(os.path.join(home, ".claude", "mcp-needs-auth-cache.json"), json.dumps({"plugin:telegram:telegram": 1, "keep": 2}), 0o600)
    r = full("claude-ok")
    c = json.load(open(os.path.join(home, ".claude", "mcp-needs-auth-cache.json")))
    check("restart: with voice, both checks pass and exit 0", r.returncode == 0 and "voice channel: OK" in r.stdout and "mcp cache: removed 1 entry" in r.stdout, r.stdout + r.stderr)
    check("restart: cache cleared before start, the other key kept", c == {"keep": 2})
    r = full("claude-nothing")
    check("restart: voice server missing -> FAIL line, message, exit 1", r.returncode == 1 and "voice channel: FAIL" in r.stdout and "FAILED: voice channel" in r.stderr, r.stdout + r.stderr)
    r = full("claude-nothing", "--no-voice")
    check("restart: --no-voice does not wait for or require the voice server", r.returncode == 0 and "voice channel" not in r.stdout, r.stdout + r.stderr)
    write(tg_env, "TELEGRAM_BOT_TOKEN=987654321:AAfake\n", 0o600)
    r = full("claude-ok")
    check("restart: Telegram plugin not seen -> exit 1 even though voice is up",
          r.returncode == 1 and "telegram plugin: not seen" in r.stdout and "voice channel: OK" in r.stdout and "FAILED: telegram plugin" in r.stderr, r.stdout + r.stderr)
    tmux("kill-server")

    # ------------------------------------------------------------------------------------------------ progress hook
    got = []                                   # (path, headers, body) of every request the stub received
    delay = [0.0]

    class Stub(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            got.append((self.path, dict(self.headers), body))
            time.sleep(delay[0])
            try:
                self.send_response(204); self.end_headers()
            except OSError:
                pass

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    hport = srv.server_address[1]
    hdir = os.path.join(tmp, "hv")
    HTOKEN = "hook-test-token-0123456789abcdef"
    write(os.path.join(hdir, "internal_token"), HTOKEN + "\n", 0o600)
    henv = {**BASE_ENV, "VOICE_DIR": hdir, "VOICE_PORT": str(hport)}

    def hook(stdin, env=None, timeout=10, wait=1.5):
        """Run the hook. It returns at once and sends from a detached child, so wait (up to `wait` s) for the request to show up."""
        before = len(got)
        t0 = time.time()
        r = subprocess.run(["bash", HOOK], input=stdin, capture_output=True, text=True, timeout=timeout, env=env or henv)
        dt = time.time() - t0
        end = time.time() + wait
        while len(got) == before and time.time() < end:
            time.sleep(0.02)
        return r, dt

    def pre(tool):
        return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": "rm -rf /secret/path", "file_path": "/etc/shadow"}})

    table = [("Read", "read"), ("NotebookRead", "read"), ("Edit", "edit"), ("Write", "edit"), ("MultiEdit", "edit"), ("NotebookEdit", "edit"),
             ("Bash", "run"), ("BashOutput", "run"), ("KillShell", "run"), ("Monitor", "run"), ("Grep", "search"), ("Glob", "search"),
             ("LS", "search"), ("ToolSearch", "search"), ("WebFetch", "web"), ("WebSearch", "web"), ("Agent", "agent"), ("Task", "agent"),
             ("Workflow", "agent"), ("SendMessage", "agent"), ("mcp__plugin_telegram_telegram__reply", "telegram"), ("mcp__plugin_telegram_x", "telegram"),
             ("mcp__voice__voice_reply", "voice"), ("TodoWrite", "other"), ("mcp__scenario__search", "other"), ("mcp__voicex__y", "other"), ("", "other")]
    bad = []
    for tool, kind in table:
        got.clear()
        r, dt = hook(pre(tool))
        if not (r.returncode == 0 and r.stdout == "" and r.stderr == "" and len(got) == 1 and got[0][2] == json.dumps({"kind": kind}, separators=(",", ":")).encode()):
            bad.append((tool, kind, got[:1], r.returncode))
    check(f"hook: mapping table ({len(table)} tool names) sends exactly {{\"kind\": ...}}", not bad, bad)
    got.clear()
    r, dt = hook(json.dumps({"hook_event_name": "Stop", "stop_hook_active": False}))
    check("hook: Stop -> idle", r.returncode == 0 and len(got) == 1 and json.loads(got[0][2]) == {"kind": "idle"}, got)
    p, h, body = got[0]
    check("hook: POST /internal/progress with the token header, JSON content type, loopback Host",
          p == "/internal/progress" and h.get("X-Internal-Token") == HTOKEN and h.get("Content-Type") == "application/json" and h.get("Host", "").startswith("127.0.0.1:"), (p, list(h)))
    check("hook: nothing but the kind is sent (no tool input, path or command)", body == b'{"kind":"idle"}' and b"secret" not in body)
    got.clear()
    for label, text in (("SubagentStop", json.dumps({"hook_event_name": "SubagentStop"})), ("PostToolUse", json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Read"})),
                        ("garbage", "\x00\xff not json {{{"), ("empty", ""), ("a list", "[1,2]"), ("tool name with a space", json.dumps({"hook_event_name": "PreToolUse", "tool_name": "a b"}))):
        r, dt = hook(text)
        extra = [x for x in got if label != "tool name with a space"]
        check(f"hook: {label} stdin -> exit 0, silent" + (" and no request" if label != "tool name with a space" else ""),
              r.returncode == 0 and r.stdout == "" and r.stderr == "" and (not extra), (r.returncode, r.stdout, got))
    got.clear()
    write(os.path.join(hdir, "env"), f"VOICE_PORT={hport}\n", 0o600)
    r, dt = hook(pre("Read"), env={**BASE_ENV, "VOICE_DIR": hdir})
    check("hook: VOICE_PORT is also read from $VOICE_DIR/env", len(got) == 1, got)
    os.unlink(os.path.join(hdir, "env"))

    # server down, and a server that sleeps 5 s: bounded, silent, exit 0
    import socket
    s0 = socket.socket(); s0.bind(("127.0.0.1", 0)); dport = s0.getsockname()[1]; s0.close()
    r, dt = hook(pre("Read"), env={**henv, "VOICE_PORT": str(dport)})
    check(f"hook: server down -> exit 0, silent, fast ({dt:.2f} s)", r.returncode == 0 and r.stdout == "" and r.stderr == "" and dt < 1.5, (r, dt))
    # a Claude Code payload with a 1 MB tool input: the names come first, the hook reads 4 KB, drains the rest (no EPIPE for the writer)
    got.clear()
    big = json.dumps({"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "/x/y", "content": "A" * 1048576}})
    pw = subprocess.Popen(["bash", HOOK], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=henv)
    t0 = time.time()
    epipe = False
    try:
        data = big.encode()
        for i in range(0, len(data), 65536):
            pw.stdin.write(data[i:i + 65536]); pw.stdin.flush()
        pw.stdin.close()
    except BrokenPipeError:
        epipe = True
    pw.stdin = None
    out, err = pw.communicate(timeout=10)
    dt = time.time() - t0
    end = time.time() + 2
    while not got and time.time() < end:
        time.sleep(0.02)
    print(f"info hook with a 1 MB payload: {dt * 1000:.0f} ms")
    check("hook: a 1 MB Write payload -> kind edit, exit 0, silent, the writer gets no broken pipe",
          not epipe and pw.returncode == 0 and out == b"" and err == b"" and len(got) == 1 and json.loads(got[0][2]) == {"kind": "edit"}, (epipe, pw.returncode, got[:1]))
    check("hook: ...and is quick (soft limit 500 ms)", dt < 0.5, dt)
    # the names are found only in the first 4096 bytes: a payload that starts with a long field is not read for them (no request, still exit 0)
    got.clear()
    far = json.dumps({"pad": "B" * 5000, "hook_event_name": "PreToolUse", "tool_name": "Write"})
    r, dt = hook(far, wait=0.5)
    check("hook: names beyond the first 4096 bytes are not looked for (no request, exit 0, silent)", r.returncode == 0 and r.stdout == "" and r.stderr == "" and not got, got)
    # the token is only sent to a loopback host: another VOICE_PROGRESS_HOST is ignored (the request goes to 127.0.0.1)
    for evil in ("203.0.113.9", "evil.example", "127.0.0.1.evil.example", "10.0.0.1"):
        got.clear()
        r, dt = hook(pre("Read"), env={**henv, "VOICE_PROGRESS_HOST": evil})
        check(f"hook: VOICE_PROGRESS_HOST={evil} is ignored, the request goes to 127.0.0.1", r.returncode == 0 and len(got) == 1 and got[0][1].get("Host", "").startswith("127.0.0.1:"), (r.returncode, got[:1]))
    got.clear()
    r, dt = hook(pre("Read"), env={**henv, "VOICE_PROGRESS_HOST": "localhost"})
    check("hook: VOICE_PROGRESS_HOST=localhost is accepted", r.returncode == 0 and len(got) == 1, got)
    delay[0] = 5.0
    p = subprocess.Popen(["bash", HOOK], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=henv)
    t0 = time.time()
    p.stdin.write(pre("Bash")); p.stdin.close(); p.stdin = None
    time.sleep(0.4)
    cmdlines = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                cmdlines.append(open(f"/proc/{d}/cmdline", "rb").read())
            except OSError:
                pass
    out, err = p.communicate(timeout=10)
    dt = time.time() - t0
    check(f"hook: slow server (5 s) -> exit 0, silent, back within 1.5 s ({dt:.2f} s)", p.returncode == 0 and out == "" and err == "" and dt < 1.5, (p.returncode, out, err, dt))
    check("hook: the token is in no command line while the request is in flight (%d processes scanned)" % len(cmdlines),
          len(cmdlines) > 20 and not any(HTOKEN.encode() in c for c in cmdlines))
    delay[0] = 0.0
    ts = []
    for _ in range(5):
        r, dt = hook(pre("Read")); ts.append(dt)
    print(f"info hook timing: {min(ts)*1000:.0f}-{max(ts)*1000:.0f} ms per call with a local server (5 calls)")
    check("hook: a call returns in well under half a second (soft limit; the figure above is the measurement)", sum(ts) / len(ts) < 0.5, ts)
    os.unlink(os.path.join(hdir, "internal_token"))
    got.clear()
    r, dt = hook(pre("Read"))
    check("hook: no token file -> nothing sent, exit 0, silent", r.returncode == 0 and r.stdout == "" and not got)
    srv.shutdown()

    # ------------------------------------------------------------------------------------------------ auth_watch
    wstubs = os.path.join(tmp, "wstubs")
    os.makedirs(wstubs)
    clog = os.path.join(tmp, "curl.log")        # argv of every call
    cin = os.path.join(tmp, "curl.stdin")       # stdin of every call
    write(os.path.join(wstubs, "curl"),
          f'#!/bin/bash\nprintf "%s\\n" "$*" >> "{clog}"\ncat >> "{cin}"\nprintf \'{{"ok":true}}\'\n', 0o755)
    write(os.path.join(wstubs, "tmux"), f'#!/bin/bash\nexec /usr/bin/tmux -L {SOCK} "$@"\n', 0o755)
    wsid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    wwork = os.path.join(tmp, "wwork")
    proj = os.path.join(cfg, "projects", "".join(c if c.isalnum() else "-" for c in wwork))
    os.makedirs(proj)
    tpath = os.path.join(proj, wsid + ".jsonl")
    wenv_file = os.path.join(tmp, "wenv")
    write(wenv_file, f"VOICE_CHAT_ID=424242\nTMUX_SESSION=watched\nCLAUDE_SESSION_ID={wsid}\nCLAUDE_WORKDIR={wwork}\n", 0o600)
    wtg = os.path.join(tmp, "wtg.env")
    write(wtg, f"TELEGRAM_BOT_TOKEN={TOKEN}\n", 0o600)
    state_dir = os.path.join(tmp, "state")
    incident = os.path.join(state_dir, "incident")

    def watch(extra=None):
        env = {**BASE_ENV, "PATH": wstubs + ":" + os.environ["PATH"], "VOICE_ENV_FILE": wenv_file, "VOICE_TG_ENV_FILE": wtg,
               "VOICE_AUTH_STATE_DIR": state_dir, "VOICE_TG_API": "http://127.0.0.1:9", "CLAUDE_CONFIG_DIR": cfg, **(extra or {})}
        return run(["bash", WATCH], env=env)

    def calls():
        return len(open(clog).read().splitlines()) if os.path.exists(clog) else 0

    def last_call():
        return open(clog).read().splitlines()[-1]

    def entry(kind, uuid_, text="hello", error=None, usage=None):
        e = {"type": kind, "uuid": uuid_, "message": {"role": "assistant", "content": [{"type": "text", "text": text}]}}
        if usage is not None:
            e["message"]["usage"] = usage
        if error:
            e.update({"isApiErrorMessage": True, "error": error})
        return json.dumps(e)

    def transcript(*lines, path=None):
        write(path or tpath, "\n".join(lines) + "\n")

    def session(alive):
        tmux("kill-session", "-t", "=watched")
        if alive:
            # the pane shows every marker the old detector looked for: it must not matter
            tmux("new-session", "-d", "-s", "watched", "-x", "200", "-y", "50", "echo 'API Error: 401 authentication_error Please run /login'; sleep 300")
            time.sleep(0.4)

    session(True)
    r = watch()
    check("watch: pane text is ignored (markers on the screen, no transcript errors)", r.returncode == 0 and calls() == 0, r.stdout + r.stderr)
    transcript(entry("user", "u0"), entry("assistant", "a0", "all fine"))
    r = watch()
    check("watch: normal last assistant entry -> no message, no state", r.returncode == 0 and calls() == 0 and not os.path.exists(incident), r.stdout + r.stderr)

    transcript(entry("assistant", "a0"), "{broken json", entry("assistant", "a1", "Invalid API key", "authentication_failed"), "", "also {broken")
    r = watch()
    check("watch: auth error last (broken lines around it) -> exactly one message", r.returncode == 0 and calls() == 1, r.stdout + r.stderr)
    args, stdin = open(clog).read(), open(cin).read()
    check("watch: token only in the stdin config, not in argv",
          TOKEN in stdin and f"/bot{TOKEN}/sendMessage" in stdin and TOKEN not in args and TOKEN.split(":")[0] not in args, args)
    check("watch: auth message names the session and /login, no transcript text",
          "watched" in args and "needs /login" in args and "Invalid API key" not in args, args)
    check("watch: token not in the script output", TOKEN not in r.stdout + r.stderr)
    r = watch()
    check("watch: the same incident is not reported twice", r.returncode == 0 and calls() == 1, r.stdout + r.stderr)

    transcript(entry("assistant", "a1", "x", "authentication_failed"), entry("user", "u2"), entry("assistant", "a2", "logged in again"))
    r = watch()
    check("watch: a later normal assistant entry clears the state, no message", r.returncode == 0 and calls() == 1 and not os.path.exists(incident), r.stdout + r.stderr)

    transcript(entry("assistant", "a1", "x", "authentication_failed"))
    r = watch()
    check("watch: the same entry after recovery is a new incident only if it is the last one again", calls() == 2, r.stdout + r.stderr)

    reset = "You've hit your session limit · resets 3:10pm (UTC)"
    transcript(entry("assistant", "a3", reset, "rate_limit"))
    r = watch()
    check("watch: rate_limit -> one message with Anthropic's text (reset time)", calls() == 3 and "resets 3:10pm (UTC)" in last_call() and "usage limit" in last_call(), last_call())
    r = watch()
    check("watch: the same rate_limit is not reported twice", calls() == 3, r.stdout + r.stderr)
    transcript(entry("assistant", "a4", "y" * 400, "rate_limit"))
    r = watch()
    check("watch: the limit text is cut to 120 characters", calls() == 4 and "y" * 120 in last_call() and "y" * 121 not in last_call(), last_call()[:80])
    transcript(entry("assistant", "a5", "overloaded", "server_error"))
    r = watch()
    check("watch: another error kind (server_error) is not an incident, state cleared", calls() == 4 and not os.path.exists(incident), r.stdout + r.stderr)

    # no CLAUDE_SESSION_ID / its transcript missing: nothing is guessed (no "newest file"), only the tmux check is made, one warning
    os.makedirs(os.path.join(proj, "sub"))
    transcript(entry("assistant", "s1", "x", "authentication_failed"), path=os.path.join(proj, "sub", "zzz.jsonl"))
    transcript(entry("assistant", "o1", "fine"), path=os.path.join(proj, "old.jsonl"))
    os.unlink(tpath)
    transcript(entry("assistant", "n1", "x", "authentication_failed"), path=os.path.join(proj, "new.jsonl"))
    missing_flag = os.path.join(state_dir, "transcript-missing-logged")
    r = watch()
    check("watch: its transcript is missing -> the other *.jsonl files are NOT used, no message", r.returncode == 0 and calls() == 4, r.stdout + r.stderr)
    check("watch: ...one warning on stderr that names the session id and says only tmux is checked",
          wsid in r.stderr and "only the tmux session is checked" in r.stderr and os.path.exists(missing_flag), r.stderr)
    r = watch()
    check("watch: ...and the warning is not repeated every run", r.stderr == "" and calls() == 4, r.stderr)
    write(wenv_file, f"VOICE_CHAT_ID=424242\nTMUX_SESSION=watched\nCLAUDE_WORKDIR={wwork}\n", 0o600)
    os.unlink(missing_flag)
    r = watch()
    check("watch: CLAUDE_SESSION_ID unset -> same: no guessing, a warning, no message", r.returncode == 0 and calls() == 4 and "only the tmux session is checked" in r.stderr, r.stdout + r.stderr)
    session(False)
    r = watch()
    check("watch: ...but the tmux check still works without a transcript", calls() == 5 and "does not exist" in last_call(), r.stdout + r.stderr)
    session(True)
    watch()
    shutil.rmtree(os.path.join(proj, "sub"))
    os.unlink(os.path.join(proj, "old.jsonl"))
    os.unlink(os.path.join(proj, "new.jsonl"))
    write(wenv_file, f"VOICE_CHAT_ID=424242\nTMUX_SESSION=watched\nCLAUDE_SESSION_ID={wsid}\nCLAUDE_WORKDIR={wwork}\n", 0o600)
    os.unlink(incident) if os.path.exists(incident) else None
    # the transcript is there again: the warning flag is dropped, checks resume
    transcript(entry("assistant", "n3", "x", "billing_error"))
    r = watch()
    check("watch: billing_error -> one message 'billing/credit problem', no transcript text", calls() == 6 and "billing/credit problem" in last_call() and "watched" in last_call(), last_call())
    check("watch: ...the missing-transcript flag is gone", not os.path.exists(missing_flag))
    r = watch()
    check("watch: the same billing_error is not reported twice", calls() == 6, r.stdout + r.stderr)
    transcript(entry("assistant", "n4", "x", "billing_error"))
    r = watch()
    check("watch: a new billing_error entry is a new incident", calls() == 7, r.stdout + r.stderr)
    transcript(entry("assistant", "n5", "fine"))
    watch()

    # a huge transcript: only the tail is read (an error 40 MB back is invisible, one in the tail is seen, a cut first line is skipped)
    filler = entry("assistant", "f", "z" * 900) + "\n"
    with open(tpath, "w") as f:
        f.write(entry("assistant", "old", "x", "authentication_failed") + "\n")
        for _ in range(45000):
            f.write(filler)
    check("test setup: the transcript is bigger than 40 MB", os.path.getsize(tpath) > 40 * 1024 * 1024)
    t0 = time.time()
    r = watch()
    check("watch: an old error far outside the tail is ignored (and a huge file is quick)", calls() == 7 and time.time() - t0 < 10, r.stdout + r.stderr)
    with open(tpath, "a") as f:
        f.write(entry("assistant", "tail", "x", "authentication_failed") + "\n")
    r = watch()
    check("watch: an error in the tail of a huge file is found", calls() == 8, r.stdout + r.stderr)
    os.unlink(tpath)

    # the tmux session
    transcript(entry("assistant", "a9", "fine"))
    session(False)
    r = watch()
    check("watch: missing session -> one message", r.returncode == 0 and calls() == 9 and "does not exist" in last_call(), r.stdout + r.stderr)
    r = watch()
    check("watch: missing session is not reported twice", calls() == 9, r.stdout + r.stderr)
    session(True)
    r = watch()
    check("watch: session back -> state cleared", not os.path.exists(incident) and calls() == 9)
    session(False)
    r = watch()
    check("watch: the session vanishing again is a new incident", calls() == 10, r.stdout + r.stderr)
    session(True)
    watch()

    # context fill (window 1000000 here, warn 0.8): input + cache read + cache creation of the last entry that has usage
    ctxenv = {"VOICE_CONTEXT_WINDOW": "1000000"}
    context_file = os.path.join(state_dir, "context")

    def use(total):
        return {"input_tokens": 10, "cache_read_input_tokens": total - 510, "cache_creation_input_tokens": 500, "output_tokens": 7}

    base = calls()
    transcript(entry("assistant", "c1", "ok", usage=use(700000)))
    r = watch(ctxenv)
    check("context: 70% of the window -> no message", r.returncode == 0 and calls() == base and not os.path.exists(context_file), r.stdout + r.stderr)
    transcript(entry("assistant", "c2", "ok", usage=use(820000)))
    r = watch(ctxenv)
    check("context: crossing 80% -> one message with percent and tokens, no incident state",
          calls() == base + 1 and "context is 82% full (820000 of 1000000 tokens)" in last_call() and "/compact" in last_call() and not os.path.exists(incident), last_call())
    r = watch(ctxenv)
    check("context: no repeat while it stays high", calls() == base + 1, r.stdout + r.stderr)
    transcript(entry("assistant", "c3", "ok", usage=use(950000)))
    r = watch(ctxenv)
    check("context: no repeat when it grows further", calls() == base + 1)
    transcript(entry("assistant", "c4", "ok", usage=use(600000)))
    r = watch(ctxenv)
    check("context: between 50% and 80% it stays disarmed (no message, state kept)", calls() == base + 1 and os.path.exists(context_file), r.stdout + r.stderr)
    transcript(entry("assistant", "c5", "ok", usage=use(900000)))
    r = watch(ctxenv)
    check("context: still no message after a dip that did not go below 50%", calls() == base + 1)
    transcript(entry("assistant", "c6", "ok", usage=use(100000)))
    r = watch(ctxenv)
    check("context: below 50% (compaction) re-arms silently", calls() == base + 1 and not os.path.exists(context_file), r.stdout + r.stderr)
    transcript(entry("assistant", "c7", "ok", usage=use(850000)))
    r = watch(ctxenv)
    check("context: the next crossing is reported again", calls() == base + 2 and "85% full" in last_call(), r.stdout + r.stderr)
    transcript(entry("assistant", "c7", "ok", usage=use(850000)), entry("assistant", "c8", "no usage here"), "{broken",
               entry("assistant", "c9", "usage junk", usage={"input_tokens": "x"}))
    r = watch(ctxenv)
    check("context: entries without a usable usage are tolerated (the last usable one counts)", r.returncode == 0 and calls() == base + 2, r.stdout + r.stderr)
    transcript(entry("assistant", "c10", "ok", usage=use(900000)), entry("assistant", "e1", "x", "server_error", usage={"input_tokens": 0}))
    r = watch(ctxenv)
    check("context: an API error entry (zero usage) does not look like a drop", calls() == base + 2 and os.path.exists(context_file), r.stdout + r.stderr)
    os.unlink(context_file)
    nowin = os.path.join(state_dir, "context-skip-logged")
    r = watch()
    check("context: no VOICE_CONTEXT_WINDOW -> no default: no context check, no message, one warning on stderr",
          calls() == base + 2 and "VOICE_CONTEXT_WINDOW is not set" in r.stderr and "skipped" in r.stderr and os.path.exists(nowin) and not os.path.exists(context_file), r.stdout + r.stderr)
    r = watch()
    check("context: ...and the warning is logged once, not on every run", calls() == base + 2 and r.stderr == "", r.stderr)
    for bad in ("abc", "0", "-5", "1e6", "2.5"):
        os.unlink(nowin) if os.path.exists(nowin) else None
        r = watch({"VOICE_CONTEXT_WINDOW": bad})
        check(f"context: an invalid window {bad!r} is the same as none", calls() == base + 2 and "not set" in r.stderr, r.stdout + r.stderr)
    # a window that is far too small (the fill is above 105% of it): treated as a wrong setting, a warning, no message
    toosmall = os.path.join(state_dir, "context-bad-logged")
    r = watch({"VOICE_CONTEXT_WINDOW": "100000"})
    check("context: used/window above 1.05 -> no message, a warning about the setting", calls() == base + 2 and "above VOICE_CONTEXT_WINDOW" in r.stderr and os.path.exists(toosmall) and not os.path.exists(context_file), r.stdout + r.stderr)
    r = watch({"VOICE_CONTEXT_WINDOW": "100000"})
    check("context: ...logged once", r.stderr == "" and calls() == base + 2, r.stderr)
    r = watch({"VOICE_CONTEXT_WINDOW": "880000"})      # 900000 used: 102%, still a real (if tight) window
    check("context: at 102% of the window it is still a normal warning", calls() == base + 3 and "102% full" in last_call() and not os.path.exists(toosmall), last_call())
    os.unlink(context_file)
    r = watch({"VOICE_CONTEXT_WARN": "0.95", "VOICE_CONTEXT_WINDOW": "1000000"})
    check("context: VOICE_CONTEXT_WARN is honoured (state kept, no message)", calls() == base + 3)
    transcript(entry("assistant", "c11", "ok", usage=use(10000)))
    watch(ctxenv)

    # a failing Telegram (no ok) leaves no state, so the next run tries again
    write(os.path.join(wstubs, "curl"), '#!/bin/bash\ncat >/dev/null\nprintf \'{"ok":false}\'\n', 0o755)
    transcript(entry("assistant", "b1", "x", "authentication_failed"))
    r = watch()
    check("watch: a refused message exits 1 and leaves no state (retried next run)", r.returncode == 1 and not os.path.exists(incident), r.stdout + r.stderr)
    r = watch({"VOICE_ENV_FILE": os.path.join(tmp, "none")})
    check("watch: missing chat id is an error", r.returncode == 1 and "numeric" in r.stderr, r.stderr)
    bad_tok = os.path.join(tmp, "badtok.env")
    write(bad_tok, 'TELEGRAM_BOT_TOKEN=x" evil\n', 0o600)
    r = watch({"VOICE_TG_ENV_FILE": bad_tok})
    check("watch: a token that is not shaped like a bot token is refused", r.returncode == 1 and "evil" not in r.stderr, r.stderr)

    for bad_api in ("http://evil.example", "https://api.telegram.org.evil.example", "https://evil.example/", "http://127.0.0.1.evil.example:80", "http://10.0.0.1:80", "ftp://127.0.0.1:1"):
        n_before = calls()
        r = watch({"VOICE_TG_API": bad_api})
        check(f"watch: VOICE_TG_API={bad_api} is refused (the token goes nowhere else)", r.returncode == 1 and "VOICE_TG_API must be" in r.stderr and calls() == n_before and TOKEN not in r.stdout + r.stderr, r.stderr)
    r = watch({"VOICE_TG_API": "https://api.telegram.org"})
    check("watch: the real Telegram API address is accepted (curl is a stub here)", "VOICE_TG_API must be" not in r.stderr, r.stderr)

    leaked = [p for p in (clog,) if os.path.exists(p) and TOKEN in open(p).read()]
    check("token never appears in any recorded command line", not leaked)
finally:
    cleanup()

if FAILS:
    print(f"\n{len(FAILS)} FAILED: " + "; ".join(FAILS))
    sys.exit(1)
print("\nALL PASSED")
