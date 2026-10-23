#!/usr/bin/env python3
"""Tests of the deployment files. Nothing here touches the machine: deploy.sh runs against a temporary tree with a
stand-in `systemctl` (and `journalctl`), and the real systemctl, /opt/voice, /etc/systemd/system, /root/.voice and the
production port are never used. Covers: syntax of the shell scripts; the pinned channel dependencies and lock file; the
hardening of the two unit files; the state migration helper (copy, no overwrite, idempotent, cleanup only after a verified
copy); the bot token staying out of every command line; and the whole of deploy.sh end to end (state migration, rendered
units, the reduced tunnel.env, mcp.json, the channel bundle and the old session command, a missing lock file, a failed
copy, new units that cannot start voice-web or the tunnel and the automatic return to the previous units, a second run, a
fresh install, the menu-button check)."""
import atexit, glob, hashlib, hmac, http.client, http.server, json, os, re, shutil, signal, socket, stat, subprocess, sys
import tempfile, threading, time, urllib.error, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="voice-deploy")
atexit.register(shutil.rmtree, TMP, True)
BUN = os.environ.get("BUN", "/root/.bun/bin/bun")
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f" ({extra})" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------------------------------------
# shell syntax
for script in ("deploy.sh", "migrate_state.sh", "tunnel/run_tunnel.sh", "restart_main_session.sh", "session/auth_watch.sh"):
    r = subprocess.run(["bash", "-n", os.path.join(ROOT, script)], capture_output=True, text=True)
    check(f"bash -n {script}", r.returncode == 0, r.stderr[:200])

# python3 runs isolated (-I: no PYTHON* variables, no user site, no script directory on the path) wherever a script starts it
for script in ("deploy.sh", "migrate_state.sh", "tunnel/run_tunnel.sh"):
    bare = [l.strip()[:70] for l in read(os.path.join(ROOT, script)).splitlines()
            if re.search(r"python3 +(-(?!I\b)|<<)", l) or re.search(r"\bpython3 +[^-\s<]\S*\.py", l)]
    check(f"{script}: every python3 it starts is isolated (-I)", not bare, str(bare))

# ---------------------------------------------------------------------------------------------------------
# the channel server's dependencies: exact versions, a lock file that is committed and agrees with package.json
pkg = json.loads(read(os.path.join(ROOT, "channel/package.json")))
lock_text = read(os.path.join(ROOT, "channel/bun.lock"))
lock = json.loads(re.sub(r",(\s*[}\]])", r"\1", lock_text))      # bun.lock is JSON with trailing commas
deps = pkg["dependencies"]
check("channel/package.json: every dependency is an exact version", deps and all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in deps.values()), str(deps))
check("channel/package.json: start runs the bundle (a session that starts it with 'bun run --silent start' installs nothing)",
      pkg["scripts"]["start"] == "bun dist/server.js", str(pkg["scripts"]))
check("channel/package.json: private", pkg.get("private") is True)
check("channel/bun.lock agrees with package.json (workspace specs)", lock["workspaces"][""]["dependencies"] == deps, str(lock["workspaces"][""]["dependencies"]))
check("channel/bun.lock resolves the direct dependencies to those versions",
      all(lock["packages"][name][0] == f"{name}@{ver}" for name, ver in deps.items()), str({n: lock["packages"][n][0] for n in deps}))
check("channel/bun.lock pins every package with an integrity hash",
      all(re.fullmatch(r"sha512-[A-Za-z0-9+/=]+", entry[3]) for entry in lock["packages"].values()))
git = shutil.which("git")
if git and subprocess.run([git, "-C", ROOT, "rev-parse", "--is-inside-work-tree"], capture_output=True).returncode == 0:
    def ignored(path):          # 0: ignored, 1: not ignored (128 would be an error)
        return subprocess.run([git, "-C", ROOT, "check-ignore", "-q", path]).returncode
    check("channel/bun.lock is not ignored by git (it is committed)", ignored("channel/bun.lock") == 1)
    check("channel/dist and node_modules are ignored by git", ignored("channel/dist/server.js") == 0 and ignored("channel/node_modules/x") == 0)

# ---------------------------------------------------------------------------------------------------------
# the unit files
def unit_lines(name):
    out = []
    for line in read(os.path.join(ROOT, "systemd", name)).splitlines():
        if line.strip() and not line.startswith(("#", ";")):
            out.append(line.strip())
    return out


COMMON = ["DynamicUser=yes", "UMask=0077", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
          "ProtectProc=invisible", "ProcSubset=pid", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
          "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes", "NoNewPrivileges=yes",
          "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictSUIDSGID=yes", "RestrictNamespaces=yes", "RestrictRealtime=yes",
          "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "RemoveIPC=yes", "SystemCallArchitectures=native",
          "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources", "SystemCallErrorNumber=EPERM",
          "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "LimitCORE=0", "Restart=always"]
web, tunnel = unit_lines("voice-web.service"), unit_lines("voice-tunnel.service")
for label, lines, env_source in (("voice-web", web, "env"), ("voice-tunnel", tunnel, "tunnel.env")):
    check(f"{label}.service: the full sandbox (DynamicUser, strict filesystem, no capabilities, syscall filter that fails with EPERM)",
          all(x in lines for x in COMMON), str([x for x in COMMON if x not in lines]))
    check(f"{label}.service: private addresses are denied, loopback and the internet are not",
          any(x.startswith("IPAddressDeny=") and "10.0.0.0/8" in x and "127." not in x for x in lines))
    check(f"{label}.service: secrets arrive as credentials, the Telegram plugin's .env included",
          f"LoadCredential=env:/root/.voice/{env_source}" in lines and "LoadCredential=telegram.env:/root/.claude/channels/telegram/.env" in lines
          and "Environment=VOICE_ENV_FILE=%d/env" in lines and "Environment=VOICE_TG_ENV_FILE=%d/telegram.env" in lines)
    check(f"{label}.service: no reference to the old state directory", not any("/root/.voice/state" in x for x in lines))
check("voice-tunnel.service: its credential 'env' is the reduced tunnel.env, never the full env file (no API keys for cloudflared)",
      not any(x.startswith("LoadCredential=") and x.endswith("/root/.voice/env") for x in tunnel)
      and sum(x.startswith("LoadCredential=") for x in tunnel) == 2)
check("voice-web.service: waits for the network", "After=network-online.target" in web and "Wants=network-online.target" in web)
check("voice-web.service: StateDirectory=voice (mode 0700) is the state directory, the code is read from /opt/voice",
      "StateDirectory=voice" in web and "StateDirectoryMode=0700" in web and "Environment=VOICE_STATE_DIR=%S/voice" in web
      and "ExecStart=/usr/bin/python3 -I -B /opt/voice/web/server.py" in web)
check("voice-web.service: the other credentials", "LoadCredential=internal_token:/root/.voice/internal_token" in web
      and "LoadCredential=glossary.txt:/root/.voice/glossary.txt" in web
      and "Environment=VOICE_TOKEN_FILE=%d/internal_token" in web and "Environment=VOICE_GLOSSARY_FILE=%d/glossary.txt" in web)
check("voice-tunnel.service: the URL file is in its runtime directory (0700), HOME is there too",
      "RuntimeDirectory=voice-tunnel" in tunnel and "RuntimeDirectoryMode=0700" in tunnel
      and "Environment=VOICE_DIR=%t/voice-tunnel" in tunnel and "Environment=HOME=%t/voice-tunnel" in tunnel)
check("voice-tunnel.service: /root/.voice/url stays a working link (made as root, and a failure of the link does not stop the tunnel)",
      "ExecStartPost=-+/bin/ln -sfn %t/voice-tunnel/url /root/.voice/url" in tunnel)
check("voice-tunnel.service: starts after voice-web but is not bound to it",
      "After=network-online.target voice-web.service" in tunnel and "Wants=network-online.target voice-web.service" in tunnel
      and not any(x.startswith(("Requires=", "BindsTo=", "PartOf=")) for x in tunnel))
if shutil.which("systemd-analyze"):
    r = subprocess.run(["systemd-analyze", "verify", os.path.join(ROOT, "systemd/voice-web.service"),
                        os.path.join(ROOT, "systemd/voice-tunnel.service")], capture_output=True, text=True)
    own = [l for l in r.stdout.splitlines() + r.stderr.splitlines() if re.search(r"voice-(web|tunnel)\.service", l)]
    check("systemd-analyze verify has nothing to say about the unit files (no unknown directive)", r.returncode == 0 and not own, str(own))

# ---------------------------------------------------------------------------------------------------------
# the migration helper
MIGRATE = os.path.join(ROOT, "migrate_state.sh")


def migrate(*args):
    r = subprocess.run(["bash", MIGRATE, *args], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout + r.stderr


def tree(base):
    """{relative path: content} of every file under base (the markers and temporary names included)."""
    out = {}
    for dp, dns, fns in os.walk(base):
        for fn in fns:
            p = os.path.join(dp, fn)
            out[os.path.relpath(p, base)] = open(p, "rb").read()
    return out


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def make_old(base, last_id="9\n", disabled=True, extra=None):
    os.makedirs(os.path.join(base, "audio"), exist_ok=True)
    open(os.path.join(base, "inbox.jsonl"), "w").write('{"id": 3, "text": "a", "ts": 1}\n{"id": 7, "text": "b", "ts": 2}\n')
    if last_id is not None:
        open(os.path.join(base, "last_id"), "w").write(last_id)
    if disabled:
        open(os.path.join(base, "DISABLED"), "w").close()
    open(os.path.join(base, "audio", "a1.wav"), "wb").write(b"RIFF1")
    open(os.path.join(base, "audio", "a2.mp3"), "wb").write(b"ID3")
    os.utime(os.path.join(base, "audio", "a1.wav"), (1_700_000_000, 1_700_000_000))
    for name, data in (extra or {}).items():
        open(os.path.join(base, name), "w").write(data)


m = os.path.join(TMP, "mig")
old, new = os.path.join(m, "old"), os.path.join(m, "private", "voice")
make_old(old)
check("migrate: pending when the old directory holds state", migrate("pending", old)[0] == 0)
check("migrate: nothing pending for a missing or empty directory",
      migrate("pending", os.path.join(m, "nope"))[0] == 1 and (os.makedirs(os.path.join(m, "empty")) or migrate("pending", os.path.join(m, "empty"))[0] == 1))
check("migrate: maxid is the larger of last_id and the inbox", migrate("maxid", old) == (0, "9\n"))
before = tree(old)
rc, out = migrate("copy", old, new)
check("migrate copy: succeeds and creates the new directory with mode 700", rc == 0 and mode(new) == 0o700, out)
want = {k: v for k, v in before.items()}
got = tree(new)
check("migrate copy: inbox, DISABLED, last_id and the audio files are in place, content identical",
      all(got.get(k) == v for k, v in want.items()) and set(got) == set(want), str(sorted(got)))
check("migrate copy: files are mode 600, the audio directory 700",
      all(mode(os.path.join(new, k)) == 0o600 for k in got) and mode(os.path.join(new, "audio")) == 0o700)
check("migrate copy: the modification time of the audio files is kept (the retention goes by it)",
      int(os.stat(os.path.join(new, "audio", "a1.wav")).st_mtime) == 1_700_000_000)
after = tree(old)
check("migrate copy: the old directory is unchanged apart from the marker",
      {k: v for k, v in after.items() if k != ".copied-to-state-directory"} == before and ".copied-to-state-directory" in after)
check("migrate copy: maxid agrees on both sides", migrate("maxid", new) == (0, "9\n"))
state_before = tree(new)
rc, out = migrate("copy", old, new)
check("migrate copy: a second run changes nothing", rc == 0 and tree(new) == state_before, out)

# the new directory has moved on (the service ran): its files win, the old ones are kept next to them
open(os.path.join(new, "inbox.jsonl"), "a").write('{"id": 10, "text": "newer", "ts": 3}\n')
open(os.path.join(new, "last_id"), "w").write("12\n")
rc, out = migrate("copy", old, new)
check("migrate copy: never overwrites; the old inbox is saved as .premigration, last_id stays at the larger value",
      rc == 0 and read(os.path.join(new, "last_id")) == "12\n" and b"newer" in open(os.path.join(new, "inbox.jsonl"), "rb").read()
      and open(os.path.join(new, "inbox.jsonl.premigration"), "rb").read() == before["inbox.jsonl"], out)
rc2, out2 = migrate("copy", old, new)
check("migrate copy: ... and repeating that adds nothing", rc2 == 0 and sorted(os.listdir(new)).count("inbox.jsonl.premigration") == 1
      and not [x for x in os.listdir(new) if x.startswith("inbox.jsonl.premigration.")], out2)
open(os.path.join(new, "last_id"), "w").write("2\n")
migrate("copy", old, new)
check("migrate copy: the old last_id wins when it is the larger one", read(os.path.join(new, "last_id")) == "9\n")

rc, out = migrate("cleanup", old)
check("migrate cleanup: removes the old directory after a copy", rc == 0 and not os.path.exists(old), out)
check("migrate cleanup: the copy is still there", os.path.exists(os.path.join(new, "inbox.jsonl")) and os.path.exists(os.path.join(new, "audio", "a1.wav")))
rc, out = migrate("cleanup", old)
check("migrate cleanup: a second run is a no-op", rc == 0, out)
rc, out = migrate("copy", old, new)
check("migrate copy: no old directory, nothing to do", rc == 0 and "nothing to migrate" in out, out)

# a failed copy never removes anything, and cleanup refuses without a verified copy
old2, blocked = os.path.join(m, "old2"), os.path.join(m, "blocked")
make_old(old2)
open(blocked, "w").write("a file where a directory is needed")
b2 = tree(old2)
rc, out = migrate("copy", old2, os.path.join(blocked, "voice"))
check("migrate copy: fails when the new place cannot be made, and the old directory is untouched", rc == 1 and tree(old2) == b2, out)
rc, out = migrate("cleanup", old2)
check("migrate cleanup: refuses without the marker, removes nothing", rc == 1 and tree(old2) == b2, out)
unwritable = os.path.join(m, "ro-new")
os.makedirs(unwritable)
os.chmod(unwritable, 0o500)
if os.geteuid() != 0:      # root ignores directory modes, so this case only means something for other users
    rc, out = migrate("copy", old2, os.path.join(unwritable, "voice"))
    check("migrate copy: fails in a directory that cannot be written", rc == 1 and tree(old2) == b2, out)
os.chmod(unwritable, 0o700)

# other files in the old directory are kept; a damaged last_id is ignored; an empty directory is removed
old3, new3 = os.path.join(m, "old3"), os.path.join(m, "new3")
make_old(old3, last_id="not a number\n", extra={"notes.txt": "keep me"})
rc, out = migrate("copy", old3, new3)
check("migrate copy: a damaged last_id is ignored (the ids come from the inbox)", rc == 0 and not os.path.exists(os.path.join(new3, "last_id")), out)
rc, out = migrate("cleanup", old3)
check("migrate cleanup: files it does not know are kept, and so is their directory",
      rc == 0 and os.listdir(old3) == ["notes.txt"] and "notes.txt" in out, out)
old4 = os.path.join(m, "old4")
os.makedirs(old4)
check("migrate cleanup: an empty directory is simply removed", migrate("cleanup", old4)[0] == 0 and not os.path.exists(old4))
old5, new5 = os.path.join(m, "old5"), os.path.join(m, "new5")
os.makedirs(old5)
open(os.path.join(old5, "last_id"), "w").write("")
check("migrate copy: an empty last_id is no problem", migrate("copy", old5, new5)[0] == 0)
check("migrate: usage errors give exit status 2", migrate()[0] == 2 and migrate("copy", "only-one")[0] == 2 and migrate("frobnicate")[0] == 2)

# ---------------------------------------------------------------------------------------------------------
# the bot token never appears in a command line (the tunnel script hands it to curl on stdin)
PROBE_TOKEN = "123456:ARGVSCAN-token-not-real"


def scan_token(script_text):
    """Run a script that sets the menu button against a slow fake Telegram API and look for the token in
    /proc/*/cmdline meanwhile. Returns the command lines that held it."""
    d = tempfile.mkdtemp(dir=TMP)
    script = os.path.join(d, "script.sh")
    open(script, "w").write(script_text)
    stub = os.path.join(d, "cloudflared")
    open(stub, "w").write("#!/bin/sh\necho 'INF |  https://argv-scan-test.trycloudflare.com  |'\nexec sleep 30\n")
    os.chmod(stub, 0o755)
    got = []

    class Slow(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            got.append(self.path)
            time.sleep(1.5)                      # the curl process lives this long
            body = b'{"ok":true,"result":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = dict(PATH=os.environ["PATH"], VOICE_DIR=d, VOICE_CLOUDFLARED=stub, VOICE_TG_API=f"http://127.0.0.1:{srv.server_address[1]}",
               VOICE_BOT_TOKEN=PROBE_TOKEN, VOICE_ALLOWED_USER="111111111", VOICE_PORT="19999", VOICE_ENV_FILE=os.path.join(d, "none"))
    p = subprocess.Popen(["bash", script], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, text=True)
    mine = set()
    pid = os.getpid()
    while pid > 1:                               # the processes above this one have the test source in their command line
        mine.add(pid)
        try:
            pid = int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    hits, end = [], time.time() + 8
    while time.time() < end and p.poll() is None:
        for f in glob.glob("/proc/[0-9]*/cmdline"):
            try:
                data = open(f, "rb").read()
            except OSError:
                continue
            if int(f.split("/")[2]) not in mine and PROBE_TOKEN.encode() in data:
                hits.append(data.replace(b"\0", b" ").decode("utf-8", "replace")[:80])
        time.sleep(0.002)
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    out = p.communicate(timeout=10)[0]
    srv.shutdown()
    return hits, got, out


leaky = ("#!/bin/bash\n(sleep 30 & echo 'INF |  https://argv-scan-test.trycloudflare.com  |')\n"
         'curl -s -m 20 -d "{}" "$VOICE_TG_API/bot${VOICE_BOT_TOKEN}/setChatMenuButton"\n')
hits, got, out = scan_token(leaky)
check("command-line scan: the detector sees a token that is passed in argv (control)", bool(hits) and got, str((hits, got)))
hits, got, out = scan_token(read(os.path.join(ROOT, "tunnel/run_tunnel.sh")))
check("command-line scan: run_tunnel.sh sets the menu button without the bot token in any command line",
      not hits and got == [f"/bot{PROBE_TOKEN}/setChatMenuButton"] and "menu button set" in out, str((hits, got, out[-200:])))

# ---------------------------------------------------------------------------------------------------------
# deploy.sh end to end, in a temporary tree, with a stand-in systemctl
VENDOR_SRC = next((p for p in ("/opt/voice/web/vendor", os.path.join(ROOT, "web/vendor")) if os.path.isdir(p)), None)
lock_rows = [l.split() for l in read(os.path.join(ROOT, "web/vendor.lock")).splitlines() if l.strip() and not l.startswith("#")]


def vendor_ok(d):
    return d and all(os.path.isfile(os.path.join(d, r[1])) and hashlib.sha256(open(os.path.join(d, r[1]), "rb").read()).hexdigest() == r[0]
                     for r in lock_rows)


SYSTEMCTL = r"""#!/bin/bash
# stand-in for systemctl: records every call with a snapshot of the world and keeps an "active" flag per unit. The
# installed unit files tell old from new ("OLD UNIT" is the old stand-in). Failure flags are files in $STUB_STATE. A flag
# applies only while a NEW unit file is installed (so a way back can work), unless broken-old is there too; a flag file
# that is not empty holds a marker instead, and then it applies only while the installed unit file contains that marker:
#   fail-start.<unit>  start/restart of the unit fails             never-active  voice-web "starts" but never becomes active
#   tunnel-dies        voice-tunnel: restart returns 0 (Type=simple), the unit is not active, the link dangles
#   no-url             voice-tunnel (new unit) runs but never writes the URL
#   stop-fails.<unit>  stop fails (exit 1) and leaves the unit active    (a unit without a file is "not loaded": stop exits 5)
# The new tunnel unit's ExecStartPost is imitated: a link from the instance dir into its runtime directory, which goes
# when the unit stops or fails (so the link dangles then). The old tunnel script writes the URL through that link.
snap() {
  printf 'systemctl %s | unit=%s | new=%s | old=%s\n' "$*" "$(head -n1 "$STUB_UNIT_DIR/voice-web.service" 2>/dev/null | cut -c1-12)" \
    "$([ -e "$STUB_NEWSTATE/inbox.jsonl" ] && echo yes || echo no)" "$([ -e "$STUB_OLDSTATE/inbox.jsonl" ] && echo yes || echo no)" >> "$STUB_LOG"
}
snap "$@"
args=(); for a in "$@"; do case "$a" in --*) ;; *) args+=("$a") ;; esac; done
installed_is_new() { ! head -n1 "$STUB_UNIT_DIR/$1" 2>/dev/null | grep -q '^OLD UNIT'; }
faulty() {
  [ -e "$STUB_STATE/$1" ] || return 1
  [ -e "$STUB_STATE/broken-old" ] && return 0
  if [ -s "$STUB_STATE/$1" ]; then grep -qF -- "$(cat "$STUB_STATE/$1")" "$STUB_UNIT_DIR/$2" 2>/dev/null; else installed_is_new "$2"; fi
}
case "${args[0]:-}" in
  daemon-reload) exit 0 ;;
  enable) for a in "${args[@]:1}"; do case "$a" in *.timer) touch "$STUB_STATE/enabled.$a" ;; esac; done; exit 0 ;;
  disable) for a in "${args[@]:1}"; do rm -f "$STUB_STATE/enabled.$a"; done; exit 0 ;;
  is-enabled) [ -e "$STUB_STATE/enabled.${args[1]}" ] ;;
  is-active) [ -e "$STUB_STATE/active.${args[1]}" ] ;;
  stop)
    if [ ! -e "$STUB_UNIT_DIR/${args[1]}" ]; then echo "Failed to stop ${args[1]}: Unit ${args[1]} not loaded." >&2; exit 5; fi
    if [ -e "$STUB_STATE/stop-fails.${args[1]}" ]; then echo "Failed to stop ${args[1]}: Access denied" >&2; exit 1; fi
    rm -f "$STUB_STATE/active.${args[1]}"
    [ "${args[1]}" = voice-tunnel.service ] && rm -rf "$STUB_RUNTIME"
    exit 0 ;;
  start|restart)
    u=${args[1]}
    if [ "${args[0]}" = restart ]; then     # a restart stops first
      rm -f "$STUB_STATE/active.$u"
      [ "$u" = voice-tunnel.service ] && rm -rf "$STUB_RUNTIME"
    fi
    if [ "$u" = voice-tunnel.service ] && installed_is_new "$u"; then mkdir -p "$STUB_RUNTIME"; ln -sfn "$STUB_RUNTIME/url" "$STUB_URL_FILE"; fi
    if faulty "fail-start.$u" "$u"; then rm -rf "$STUB_RUNTIME"; exit 1; fi
    if [ "$u" = voice-web.service ] && faulty never-active "$u"; then exit 0; fi
    if [ "$u" = voice-tunnel.service ] && faulty tunnel-dies "$u"; then rm -rf "$STUB_RUNTIME"; exit 0; fi
    touch "$STUB_STATE/active.$u"
    if [ "$u" = voice-tunnel.service ]; then
      n=$(( $(cat "$STUB_STATE/urlseq" 2>/dev/null || echo 0) + 1 )); echo $n > "$STUB_STATE/urlseq"
      if installed_is_new "$u"; then faulty no-url "$u" || echo "https://stub-$n.trycloudflare.com" > "$STUB_RUNTIME/url"
      else echo "https://stub-$n.trycloudflare.com" > "$STUB_URL_FILE" || exit 1; fi
    fi ;;
  *) echo "systemctl stand-in: unexpected call: $*" >&2; exit 3 ;;
esac
"""
JOURNALCTL = r"""#!/bin/bash
# stand-in for journalctl: the lines the tunnel script logs; the menu button line is missing when no-menu is there, and
# with big-journal it comes first and is followed by 3 MB (a reader that quits at the match gets SIGPIPE on the writer)
echo "journalctl $*" >> "$STUB_LOG.journal"
if [ -e "$STUB_STATE/no-menu" ]; then printf 'tunnel up: https://stub.trycloudflare.com\n'; exit 0; fi
printf 'menu button set\n'
if [ -e "$STUB_STATE/big-journal" ]; then head -c 3000000 /dev/zero | tr '\0' 'x'; echo; fi
exit 0
"""
RSYNC = r"""#!/bin/bash
# the real rsync; with drop-lock the lock file is gone from the deployed channel directory afterwards
@REAL_RSYNC@ "$@"; rc=$?
if [ -e "$STUB_STATE/drop-lock" ]; then rm -f "$STUB_OPT/channel/bun.lock"; fi
exit $rc
""".replace("@REAL_RSYNC@", shutil.which("rsync") or "/usr/bin/rsync")
BUN_EXTERNAL = r"""#!/bin/bash
# the real bun, except that `bun build` leaves every package external: the bundle then needs node_modules when it runs
if [ "$1" = build ]; then exec @REAL_BUN@ "$@" --external '*'; fi
exec @REAL_BUN@ "$@"
""".replace("@REAL_BUN@", BUN)
CURL = r"""#!/bin/bash
# the real curl, except that nothing may be aimed at the production port 18200
cfg=""; if [[ " $* " == *" -K - "* ]]; then cfg=$(cat); fi
if [[ "$* $cfg" == *":18200"* ]]; then echo "curl stand-in: refusing to talk to port 18200" >&2; exit 99; fi
if [ -n "$cfg" ]; then printf '%s\n' "$cfg" | exec @REAL_CURL@ "$@"; else exec @REAL_CURL@ "$@"; fi
""".replace("@REAL_CURL@", shutil.which("curl") or "/usr/bin/curl")


class Health(http.server.BaseHTTPRequestHandler):
    """The part of voice-web that deploy.sh looks at: GET / and GET /internal/inbox?after=-1."""
    last_id = 0
    token_file = ""

    def do_GET(self):
        if self.path == "/":
            self.reply(200, b"<html></html>")
        elif self.path.startswith("/internal/inbox"):
            if self.headers.get("X-Internal-Token") != read(self.server.token_file).strip():
                self.reply(403, b'{"error": "forbidden"}')
            else:
                self.reply(200, json.dumps({"last_id": self.server.last_id}).encode())
        else:
            self.reply(404, b"{}")

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


BOT = "123456:FAKE-deploy-test"
TEST_USER = 111111111


class Box:
    """A temporary tree standing in for the machine, and one way to run deploy.sh in it."""

    def __init__(self, name, old_state=True, old_units=True, env_extra=None, last_id=9, tg_env="exists", env_lines=None):
        self.root = os.path.join(TMP, name)
        self.V, self.OPT, self.UNITS = (os.path.join(self.root, x) for x in ("voice", "opt", "units"))
        self.NEW = os.path.join(self.root, "private", "voice")
        self.BIN, self.STATE = os.path.join(self.root, "bin"), os.path.join(self.root, "stubstate")
        self.LOG, self.URL = os.path.join(self.root, "calls.log"), os.path.join(self.V, "url")
        self.RUNTIME = os.path.join(self.root, "run-voice-tunnel")
        for d in (self.V, self.UNITS, self.BIN, self.STATE, os.path.join(self.OPT, "web")):
            os.makedirs(d, exist_ok=True)
        os.chmod(self.V, 0o700)
        self.health = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Health)
        self.health.last_id, self.health.token_file = last_id, os.path.join(self.V, "internal_token")
        threading.Thread(target=self.health.serve_forever, daemon=True).start()
        self.port = self.health.server_address[1]
        for fn, text in (("systemctl", SYSTEMCTL), ("curl", CURL), ("journalctl", JOURNALCTL), ("rsync", RSYNC), ("bun-external", BUN_EXTERNAL)):
            open(os.path.join(self.BIN, fn), "w").write(text)
            os.chmod(os.path.join(self.BIN, fn), 0o755)
        for r in lock_rows:                                   # the vendor files are present, so nothing is downloaded
            os.makedirs(os.path.join(self.OPT, "web/vendor"), exist_ok=True)
            shutil.copy(os.path.join(VENDOR_SRC, r[1]), os.path.join(self.OPT, "web/vendor", r[1]))
        self.tg = os.path.join(self.root, "tg.env")
        open(self.tg, "w").write("TELEGRAM_BOT_TOKEN=%s\n" % BOT)
        lines = env_lines if env_lines is not None else [
            "VOICE_ALLOWED_USER=111111111", f"VOICE_PORT={self.port}",
            f"VOICE_TG_ENV_FILE={self.tg if tg_env == 'exists' else os.path.join(self.root, 'no-such.env')}"]
        open(os.path.join(self.V, "env"), "w").write("\n".join(lines + (env_extra or [])) + "\n")
        open(os.path.join(self.V, "internal_token"), "w").write("deploy-test-token-0123456789\n")
        if old_state:
            make_old(os.path.join(self.V, "state"))
            open(os.path.join(self.V, "url"), "w").write("https://old-tunnel.trycloudflare.com\n")
        if old_units:
            for u in ("voice-web.service", "voice-tunnel.service"):
                open(os.path.join(self.UNITS, u), "w").write("OLD UNIT v0\n[Service]\nExecStart=/usr/bin/true\n")
                open(os.path.join(self.STATE, "active." + u), "w").close()
        open(self.LOG, "w").close()

    def env(self, extra=None):
        env = dict(PATH=self.BIN + ":" + os.environ["PATH"], HOME=os.environ.get("HOME", "/root"), TMPDIR=tempfile.gettempdir(), BUN=BUN, VOICE_DIR=self.V,
                   VOICE_OPT_DIR=self.OPT, VOICE_UNIT_DIR=self.UNITS, VOICE_STATE_PRIVATE=self.NEW, VOICE_READY_WAIT="3",
                   VOICE_URL_WAIT="3", VOICE_MENU_WAIT="2", STUB_LOG=self.LOG, STUB_STATE=self.STATE, STUB_UNIT_DIR=self.UNITS,
                   STUB_NEWSTATE=self.NEW, STUB_OLDSTATE=os.path.join(self.V, "state"), STUB_URL_FILE=self.URL, STUB_RUNTIME=self.RUNTIME,
                   STUB_OPT=self.OPT)
        env.update(extra or {})
        return env

    def run(self, extra_env=None, timeout=240, src=ROOT):
        r = subprocess.run(["bash", os.path.join(src, "deploy.sh")], env=self.env(extra_env), capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    def flag(self, *names):
        for n in names:
            open(os.path.join(self.STATE, n), "w").close()

    def flag_marked(self, name, marker):
        """A failure flag that applies only to an installed unit file that contains `marker`."""
        open(os.path.join(self.STATE, name), "w").write(marker)

    def unflag(self, *names):
        for n in names:
            os.remove(os.path.join(self.STATE, n))

    def calls(self):
        """[(command words, unit file head, new state present, old state present)] in order."""
        out = []
        for line in read(self.LOG).splitlines():
            cmd, unit, new_, old_ = line.split(" | ")
            out.append((cmd[len("systemctl "):], unit[len("unit="):], new_ == "new=yes", old_ == "old=yes"))
        return out

    def verbs(self):
        # the auth watchdog's timer is the last step of a deploy and has its own checks
        return [x[0] for x in self.calls() if not x[0].startswith("is-active") and "voice-auth-watch" not in x[0]]

    def head(self, unit):
        return read(os.path.join(self.UNITS, unit)).splitlines()[0]

    def stop(self):
        self.health.shutdown()


def init_data(user, token, age=0):
    d = {"auth_date": str(int(time.time()) - age), "query_id": "AAtest", "user": json.dumps({"id": int(user), "first_name": "T"}, separators=(",", ":"))}
    dcs = "\n".join(f"{k}={v}" for k, v in sorted(d.items()))
    d["hash"] = hmac.new(hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest(), dcs.encode(), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(d)


def old_unit_runs_new_code(b):
    """The previous unit file starts the deployed server.py as a plain `python3 server.py` with no VOICE_* environment, so
    every path is a built-in default (/root/.voice/...; here mapped into the test tree). It must come up on the old state,
    keep the ids going and take an utterance. Returns (ok, what went wrong)."""
    d = tempfile.mkdtemp(dir=TMP)
    web = os.path.join(d, "web")
    shutil.copytree(os.path.join(b.OPT, "web"), web, ignore=shutil.ignore_patterns("vendor", "__pycache__"))
    src = read(os.path.join(web, "server.py"))
    if "/root/.voice/state" not in src:
        return False, "server.py has no default state path"
    open(os.path.join(web, "server.py"), "w").write(src.replace("/root/.voice", b.V))
    port = free_port()
    open(os.path.join(b.V, "env"), "a").write(f"VOICE_PORT={port}\n")      # the old unit gets its port from the env file only
    p = subprocess.Popen([sys.executable, "-B", os.path.join(web, "server.py")], env={"PATH": os.environ["PATH"]},
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if urllib.request.urlopen(base + "/", timeout=2).status == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            return False, "did not come up"
        tok = read(os.path.join(b.V, "internal_token")).strip()
        last = json.load(urllib.request.urlopen(urllib.request.Request(base + "/internal/inbox?after=-1", headers={"X-Internal-Token": tok}), timeout=5))
        if last != {"last_id": 9}:
            return False, f"last id {last} (the old state has 9)"
        def utterance():
            req = urllib.request.Request(base + "/api/utterance", data=b"\x00\x01" * 16000, method="POST",
                                         headers={"X-Init-Data": init_data(TEST_USER, BOT), "Content-Type": "application/octet-stream"})
            try:
                return urllib.request.urlopen(req, timeout=10).status, None
            except urllib.error.HTTPError as e:
                return e.code, None
        disabled = os.path.join(b.V, "state/DISABLED")
        if os.path.exists(disabled):                        # the kill switch of the old state is honoured ...
            if utterance()[0] != 503:
                return False, "the kill switch file of the old state was ignored"
            os.remove(disabled)                             # ... and off again
        req = urllib.request.Request(base + "/api/utterance", data=b"\x00\x01" * 16000, method="POST",
                                     headers={"X-Init-Data": init_data(TEST_USER, BOT), "Content-Type": "application/octet-stream"})
        got = json.load(urllib.request.urlopen(req, timeout=10))
        if got.get("id") != 10:
            return False, f"utterance answered {got}"
        # (the two old entries are from 1970, so the rotation at start dropped them; the ids go on from last_id 9)
        inbox = [json.loads(l)["id"] for l in read(os.path.join(b.V, "state/inbox.jsonl")).splitlines() if l.strip()]
        if inbox != [10] or read(os.path.join(b.V, "state/last_id")).strip() != "10":
            return False, f"old state now: ids {inbox}, last_id {read(os.path.join(b.V, 'state/last_id')).strip()}"
        return True, ""
    finally:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        p.communicate(timeout=10)


def tunnel_script(b, env_file, tg_env):
    """Run the deployed run_tunnel.sh the way the unit does: its settings come from `env_file` (the unit's credential
    'env') and the Telegram env file only. Stub cloudflared, fake Telegram API. Returns (what was posted, cloudflared's
    arguments, output)."""
    d = tempfile.mkdtemp(dir=TMP)
    seen = []

    class TG(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append((self.path, json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))))
            ok = b'{"ok":true,"result":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(ok)))
            self.end_headers()
            self.wfile.write(ok)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TG)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    cf = os.path.join(d, "cloudflared")
    open(cf, "w").write("#!/bin/sh\necho \"$@\" > %s\necho 'INF |  https://tunnel-env-test.trycloudflare.com  |'\nexec sleep 30\n" % os.path.join(d, "cf.args"))
    os.chmod(cf, 0o755)
    env = dict(PATH=os.environ["PATH"], VOICE_DIR=d, VOICE_ENV_FILE=env_file, VOICE_TG_ENV_FILE=tg_env, VOICE_CLOUDFLARED=cf,
               VOICE_TG_API=f"http://127.0.0.1:{srv.server_address[1]}")
    p = subprocess.Popen(["bash", os.path.join(b.OPT, "tunnel/run_tunnel.sh")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True, text=True)
    end = time.time() + 15
    while not seen and time.time() < end and p.poll() is None:
        time.sleep(0.05)
    time.sleep(0.3)
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    out = p.communicate(timeout=10)[0]
    srv.shutdown()
    args = read(os.path.join(d, "cf.args")).strip() if os.path.exists(os.path.join(d, "cf.args")) else ""
    return seen, args, out


def tunnel_sum_of(b):
    """What deploy.sh's tunnel_sum prints: sha256 of the lines `sha256sum < file` makes for run_tunnel.sh, the installed tunnel
    unit and tunnel.env ("missing" for a file that is not there)."""
    text = ""
    for f in (os.path.join(b.OPT, "tunnel/run_tunnel.sh"), os.path.join(b.UNITS, "voice-tunnel.service"), os.path.join(b.V, "tunnel.env")):
        text += (hashlib.sha256(open(f, "rb").read()).hexdigest() + "  -\n") if os.path.isfile(f) else "missing\n"
    return hashlib.sha256(text.encode()).hexdigest()


def src_copy(name, edit):
    """A copy of the repository (without node_modules and the vendor files), changed by edit(dir)."""
    d = os.path.join(TMP, name)
    shutil.copytree(ROOT, d, ignore=shutil.ignore_patterns("node_modules", "__pycache__", ".git", "vendor", "dist"))
    edit(d)
    return d


if not os.path.exists(BUN) or not shutil.which("rsync") or not vendor_ok(VENDOR_SRC):
    print("SKIP deploy.sh end to end: needs bun, rsync and the vendor files (/opt/voice/web/vendor or web/vendor)")
else:
    # -- an upgrade: old state, old units, running services; the env file holds API keys and a menu text
    b = Box("upgrade", env_extra=["OPENROUTER_API_KEY=sk-or-SECRET-deploy-test",
                                  "VOICE_MENU_TEXT=Open voice", "VOICE_CHAT_ID=222222222"])
    rc, out, err = b.run()
    c = b.calls()
    check("deploy.sh upgrade: succeeds", rc == 0 and out.rstrip().endswith("deployed"), out + err)
    check("deploy.sh upgrade: order of the systemctl calls (stop, reload, enable, restart voice-web, restart voice-tunnel)",
          b.verbs() == ["stop voice-web.service", "daemon-reload", "enable voice-web.service voice-tunnel.service",
                        "restart voice-web.service", "restart voice-tunnel.service"], str(b.verbs()))
    check("deploy.sh upgrade: the auth watchdog is copied (executable), its units rendered and installed, the timer enabled last",
          os.access(os.path.join(b.OPT, "session/auth_watch.sh"), os.X_OK)
          and "ExecStart=%s/session/auth_watch.sh" % b.OPT in read(os.path.join(b.UNITS, "voice-auth-watch.service"))
          and "Environment=VOICE_DIR=%s\n" % b.V in read(os.path.join(b.UNITS, "voice-auth-watch.service"))
          and "OnUnitActiveSec=5min" in read(os.path.join(b.UNITS, "voice-auth-watch.timer"))
          and "/root/.voice" not in read(os.path.join(b.UNITS, "voice-auth-watch.service"))
          and os.access(os.path.join(b.OPT, "session/progress_hook.sh"), os.X_OK), out + err)
    check("deploy.sh upgrade: the watchdog timer is opt-in: without VOICE_AUTH_WATCH=1 it is not enabled (the units are installed), the output says how to turn it on",
          [x[0] for x in c if "voice-auth-watch" in x[0]] == ["is-enabled --quiet voice-auth-watch.timer"]
          and not os.path.exists(os.path.join(b.STATE, "enabled.voice-auth-watch.timer")) and "auth watchdog: off (set VOICE_AUTH_WATCH=1" in out, str([x[0] for x in c]) + out + err)
    ss = os.path.join(b.V, "session-settings.json")
    try:
        sj = json.loads(read(ss))
    except Exception:
        sj = {}
    hk = "%s/session/progress_hook.sh" % b.OPT
    check("deploy.sh upgrade: session-settings.json is valid JSON, mode 600, with the progress hook of the code directory on PreToolUse (all tools), Stop, SubagentStart and SubagentStop",
          os.path.isfile(ss) and mode(ss) == 0o600 and not os.path.exists(ss + ".new")
          and sj.get("hooks", {}).get("PreToolUse") == [{"matcher": "*", "hooks": [{"type": "command", "command": hk, "timeout": 2}]}]
          and all(sj.get("hooks", {}).get(e) == [{"hooks": [{"type": "command", "command": hk, "timeout": 2}]}] for e in ("Stop", "SubagentStart", "SubagentStop"))
          and set(sj["hooks"]) == {"PreToolUse", "Stop", "SubagentStart", "SubagentStop"} and set(sj) == {"hooks"}
          and os.access(hk, os.X_OK), (sj, out + err))
    stop_call = next(x for x in c if x[0] == "stop voice-web.service")
    reload_call = next(x for x in c if x[0] == "daemon-reload")
    check("deploy.sh upgrade: voice-web is stopped while the OLD unit is still installed and before anything was copied",
          stop_call[1] == "OLD UNIT v0" and stop_call[2] is False and stop_call[3] is True, str(stop_call))
    check("deploy.sh upgrade: the state is copied before the new units are loaded, and the old state is still there then",
          reload_call[1] == "[Unit]" and reload_call[2] is True and reload_call[3] is True, str(reload_call))
    check("deploy.sh upgrade: the old state directory is gone afterwards, the new one holds everything",
          not os.path.exists(os.path.join(b.V, "state")) and mode(b.NEW) == 0o700
          and set(tree(b.NEW)) == {"inbox.jsonl", "last_id", "DISABLED", "audio/a1.wav", "audio/a2.mp3"} and read(os.path.join(b.NEW, "last_id")) == "9\n",
          str(sorted(tree(b.NEW))))
    check("deploy.sh upgrade: it says what it did", "moving the state of voice-web" in out and "voice-web is up on the migrated state (last id 9)" in out
          and "removed" in out and "new public URL: https://stub-1.trycloudflare.com" in out, out)
    uweb, utun = read(os.path.join(b.UNITS, "voice-web.service")), read(os.path.join(b.UNITS, "voice-tunnel.service"))
    check("deploy.sh upgrade: the units are rendered for this instance (instance dir, code dir, Telegram .env)",
          f"LoadCredential=env:{b.V}/env\n" in uweb and f"LoadCredential=glossary.txt:{b.V}/glossary.txt" in uweb
          and f"LoadCredential=telegram.env:{b.tg}" in uweb and f"LoadCredential=telegram.env:{b.tg}" in utun
          and f"ExecStart=/usr/bin/python3 -I -B {b.OPT}/web/server.py" in uweb and f"ExecStart={b.OPT}/tunnel/run_tunnel.sh" in utun
          and f"ExecStartPost=-+/bin/ln -sfn %t/voice-tunnel/url {b.V}/url" in utun
          and "/root/.voice" not in uweb + utun and "/opt/voice" not in uweb + utun, uweb[:300])
    tenv = os.path.join(b.V, "tunnel.env")
    check("deploy.sh upgrade: the tunnel unit loads the reduced tunnel.env as its 'env', not the full env file",
          f"LoadCredential=env:{tenv}\n" in utun and f"{b.V}/env" not in utun, utun[:400])
    check("deploy.sh upgrade: tunnel.env holds the port, the chat ids and the menu text, mode 600, and no key or secret",
          read(tenv) == f"VOICE_PORT={b.port}\nVOICE_ALLOWED_USER=111111111\nVOICE_CHAT_ID=222222222\nVOICE_MENU_TEXT=Open voice\n"
          and mode(tenv) == 0o600 and "SECRET" not in read(tenv) and "KEY" not in read(tenv) and "tunnel.env.new" not in os.listdir(b.V), read(tenv))
    seen, cfargs, tout = tunnel_script(b, tenv, b.tg)
    check("deploy.sh upgrade: run_tunnel.sh works with nothing but tunnel.env and the Telegram .env (port, chat, text, token)",
          seen == [(f"/bot{BOT}/setChatMenuButton", {"chat_id": 111111111, "menu_button": {"type": "web_app", "text": "Open voice",
                   "web_app": {"url": "https://tunnel-env-test.trycloudflare.com/"}}})] and cfargs.endswith(f"--url http://127.0.0.1:{b.port}")
          and "menu button set" in tout, str((seen, cfargs, tout[-200:])))
    check("deploy.sh upgrade: the tunnel link is the file a person reads", read(b.URL).strip() == "https://stub-1.trycloudflare.com")
    check("deploy.sh upgrade: the journal of the tunnel is asked for the menu-button line, which is there",
          "the menu button was set" in out and "WARNING" not in err and "-u voice-tunnel.service" in read(b.LOG + ".journal"), out + err)
    check("deploy.sh upgrade: mcp.json runs the bundle", json.loads(read(os.path.join(b.V, "mcp.json"))) ==
          {"mcpServers": {"voice": {"command": BUN, "args": [f"{b.OPT}/channel/dist/server.js"]}}} and mode(os.path.join(b.V, "mcp.json")) == 0o600)
    ch = os.path.join(b.OPT, "channel")
    check("deploy.sh upgrade: the channel bundle is built, node_modules is gone, the lock file is deployed, no temporary file is left",
          os.path.isfile(os.path.join(ch, "dist/server.js")) and not os.path.exists(os.path.join(ch, "node_modules"))
          and read(os.path.join(ch, "bun.lock")) == read(os.path.join(ROOT, "channel/bun.lock"))
          and sorted(os.listdir(os.path.join(ch, "dist"))) == ["server.js"], str(os.listdir(ch)))
    INIT = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}\n'
    isolated = dict(os.environ, VOICE_PORT="1", VOICE_ENV_FILE="/dev/null", VOICE_TOKEN_FILE="/dev/null")
    r = subprocess.run([BUN, os.path.join(ch, "dist/server.js")], input=INIT, capture_output=True, text=True, timeout=30, cwd="/", env=isolated)
    check("deploy.sh upgrade: the deployed bundle runs without node_modules and answers MCP initialize", '"name":"voice"' in r.stdout, r.stdout[:200] + r.stderr[:200])
    r = subprocess.run([BUN, "run", "--cwd", ch, "--silent", "start"], input=INIT, capture_output=True, text=True, timeout=30, cwd="/", env=isolated)
    check("deploy.sh upgrade: the command of a running session, 'bun run --cwd <dir> --silent start', still starts the channel server",
          '"name":"voice"' in r.stdout and not os.path.exists(os.path.join(ch, "node_modules")), r.stdout[:200] + r.stderr[:200])
    check("deploy.sh upgrade: the web code is synced, the vendor files kept, the tunnel script is executable",
          os.path.isfile(os.path.join(b.OPT, "web/server.py")) and os.path.isfile(os.path.join(b.OPT, "web/vendor", lock_rows[0][1]))
          and os.access(os.path.join(b.OPT, "tunnel/run_tunnel.sh"), os.X_OK))
    check("deploy.sh upgrade: the real production port was never contacted", "refusing to talk to port 18200" not in err, err[-300:])

    # -- the same again: nothing is moved, nothing stops, the tunnel is left alone
    state_snapshot = tree(b.NEW)
    open(b.LOG, "w").close()
    rc, out, err = b.run()
    check("deploy.sh second run: succeeds without moving or stopping anything",
          rc == 0 and b.verbs() == ["daemon-reload", "enable voice-web.service voice-tunnel.service", "restart voice-web.service"] and "moving the state" not in out,
          str(b.verbs()) + out + err)
    check("deploy.sh second run: the tunnel is left running, its URL is kept; the state is as it was",
          "voice-tunnel unchanged: left running, public URL kept" in out and read(b.URL).strip() == "https://stub-1.trycloudflare.com" and tree(b.NEW) == state_snapshot, out)
    # -- a changed menu text is a changed tunnel.env: the tunnel is restarted to read it (and the URL changes)
    open(os.path.join(b.V, "env"), "a").write("VOICE_MENU_TEXT=Talk\n")
    open(b.LOG, "w").close()
    rc, out, err = b.run()
    check("deploy.sh after a change of the menu text: tunnel.env follows it and the tunnel is restarted to read it",
          rc == 0 and "VOICE_MENU_TEXT=Talk\n" in read(tenv) and "Open voice" not in read(tenv) and "restart voice-tunnel.service" in b.verbs()
          and "new public URL: https://stub-2.trycloudflare.com" in out, str(b.verbs()) + out + err)
    # -- an API key is not a tunnel setting: changing it leaves the tunnel alone
    open(os.path.join(b.V, "env"), "a").write("OPENROUTER_API_KEY=sk-or-SECRET-changed\n")
    open(b.LOG, "w").close()
    rc, out, err = b.run()
    check("deploy.sh after a change of an API key: the tunnel is not restarted (it never sees the key)",
          rc == 0 and "restart voice-tunnel.service" not in b.verbs() and "SECRET" not in read(tenv), str(b.verbs()) + out + err)
    # -- .tunnel-sum: the checksum of what the tunnel was last started with
    tsum = os.path.join(b.V, ".tunnel-sum")
    check(".tunnel-sum holds the checksum of run_tunnel.sh, the installed tunnel unit and tunnel.env; mode 600, no temporary file",
          os.path.isfile(tsum) and read(tsum).strip() == tunnel_sum_of(b) and mode(tsum) == 0o600 and ".tunnel-sum.new" not in os.listdir(b.V), read(tsum))
    # the first run of this logic: no file yet. Nothing changed: no restart for the mere absence of the file, and the file is made
    os.remove(tsum)
    open(b.LOG, "w").close()
    rc, out, err = b.run()
    check("deploy.sh without .tunnel-sum (the first run of this logic) and nothing changed: the tunnel is not restarted, the file is written",
          rc == 0 and "restart voice-tunnel.service" not in b.verbs() and "voice-tunnel unchanged" in out and read(tsum).strip() == tunnel_sum_of(b),
          str(b.verbs()) + out + err)
    # ... and without the file a change is found the way it always was: against the checksum taken at the start of the run
    os.remove(tsum)
    open(os.path.join(b.V, "env"), "a").write("VOICE_MENU_TEXT=Again\n")
    open(b.LOG, "w").close()
    rc, out, err = b.run()
    check("deploy.sh without .tunnel-sum and with a changed tunnel.env: the tunnel is restarted, and the file is written afterwards",
          rc == 0 and "restart voice-tunnel.service" in b.verbs() and read(tsum).strip() == tunnel_sum_of(b), str(b.verbs()) + out + err)
    # a recorded checksum that differs from the current one means a change that was left behind: restart (the tunnel is running)
    open(tsum, "w").write("0" * 64 + "\n")
    open(b.LOG, "w").close()
    rc, out, err = b.run()
    check("deploy.sh with a recorded checksum that is not the current one (a change an earlier run left behind): the tunnel is restarted",
          rc == 0 and "restart voice-tunnel.service" in b.verbs() and read(tsum).strip() == tunnel_sum_of(b), str(b.verbs()) + out + err)
    b.stop()

    # -- a run that fails after it rewrote tunnel.env must not strand the change: the next run restarts the tunnel
    b = Box("stranded")
    rc, out, err = b.run()
    tsum = os.path.join(b.V, ".tunnel-sum")
    first_sum = read(tsum).strip() if os.path.exists(tsum) else ""
    check("deploy.sh stranded-change setup: the first run succeeds and records the checksum", rc == 0 and first_sum == tunnel_sum_of(b), out + err)
    open(os.path.join(b.V, "env"), "a").write("VOICE_MENU_TEXT=Talk\n")
    src_next = src_copy("src-next", lambda d: open(os.path.join(d, "systemd/voice-web.service"), "a").write("\n# BUILD-NEXT\n"))
    b.flag_marked("never-active", "BUILD-NEXT")                  # the new web unit (and only that one) never becomes active
    open(b.LOG, "w").close()
    rc, out, err = b.run(src=src_next)
    check("deploy.sh run that fails before the tunnel step (tunnel.env is already new): goes back to the previous units, the tunnel is not touched",
          rc != 0 and "previous voice-web is running again" in err and "restart voice-tunnel.service" not in b.verbs()
          and "Talk" in read(os.path.join(b.V, "tunnel.env")) and read(tsum).strip() == first_sum, str((rc, b.verbs(), err[-400:])))
    check("deploy.sh going back to a previous unit that sets VOICE_STATE_DIR: no word about a different kill switch file",
          "kill switch" not in err and "VOICE_STATE_DIR" in read(os.path.join(b.UNITS, "voice-web.service")), err[-400:])
    b.unflag("never-active")
    open(b.LOG, "w").close()
    rc, out, err = b.run(src=src_next)
    check("deploy.sh next run: the change that was left behind is applied, the tunnel is restarted (it would have been called unchanged)",
          rc == 0 and "restart voice-tunnel.service" in b.verbs() and "new public URL: https://stub-2.trycloudflare.com" in out
          and read(tsum).strip() == tunnel_sum_of(b) != first_sum, str((rc, b.verbs(), out[-300:], err[-300:])))
    b.stop()

    # -- the watchdog timer is opt-in (VOICE_AUTH_WATCH=1 in the env file) and is switched off again when the line goes
    b = Box("aw-on", old_state=False, env_extra=["VOICE_AUTH_WATCH=1"])
    rc, out, err = b.run()
    c = b.calls()
    check("deploy.sh with VOICE_AUTH_WATCH=1: the timer is enabled and started, as the last call",
          rc == 0 and [x[0] for x in c if "voice-auth-watch" in x[0]] == ["enable --now voice-auth-watch.timer"]
          and c[-1][0] == "enable --now voice-auth-watch.timer" and "auth watchdog: voice-auth-watch.timer enabled" in out
          and os.path.exists(os.path.join(b.STATE, "enabled.voice-auth-watch.timer")), str([x[0] for x in c]) + out + err)
    for val_ in ("0", "yes", ""):
        lines_ = [l for l in read(os.path.join(b.V, "env")).splitlines() if not l.startswith("VOICE_AUTH_WATCH")] + ["VOICE_AUTH_WATCH=" + val_]
        open(os.path.join(b.V, "env"), "w").write("\n".join(lines_) + "\n")
        open(os.path.join(b.STATE, "enabled.voice-auth-watch.timer"), "w").close()      # it was on before
        open(b.LOG, "w").close()
        rc, out, err = b.run()
        c = b.calls()
        check(f"deploy.sh with VOICE_AUTH_WATCH={val_!r} after it was on: the timer is stopped and disabled",
              rc == 0 and [x[0] for x in c if "voice-auth-watch" in x[0]] == ["is-enabled --quiet voice-auth-watch.timer", "disable --now voice-auth-watch.timer"]
              and not os.path.exists(os.path.join(b.STATE, "enabled.voice-auth-watch.timer")) and "timer disabled" in out, str([x[0] for x in c]) + out + err)
    b.stop()
    # session-settings.json: only with an executable hook script; a stale file is removed; both scripts are made executable in /opt
    b = Box("hook-gone", old_state=False)
    stale = os.path.join(b.V, "session-settings.json")
    open(stale, "w").write('{"hooks": {}}\n')
    rc, out, err = b.run(src=src_copy("src-nohook", lambda d: os.remove(os.path.join(d, "session/progress_hook.sh"))))
    check("deploy.sh without session/progress_hook.sh: a stale session-settings.json is removed (so --settings is not passed), a warning, the rest deployed",
          rc == 0 and out.rstrip().endswith("deployed") and not os.path.exists(stale) and "progress_hook.sh is missing or not executable" in err, str((rc, err[-300:])))
    b.stop()
    b = Box("hook-noexec", old_state=False)
    def noexec(d):
        for f in ("auth_watch.sh", "progress_hook.sh"):
            os.chmod(os.path.join(d, "session", f), 0o644)
    rc, out, err = b.run(src=src_copy("src-noexec", noexec))
    check("deploy.sh makes both session scripts executable in the code directory, and writes session-settings.json",
          rc == 0 and all(os.access(os.path.join(b.OPT, "session", f), os.X_OK) for f in ("auth_watch.sh", "progress_hook.sh"))
          and os.path.isfile(os.path.join(b.V, "session-settings.json")), str((rc, err[-300:])))
    b.stop()

    # -- the auth watchdog is optional: a missing session/ directory or a unit systemd does not accept is a warning only
    for label, edit in (("no session/ directory", lambda d: shutil.rmtree(os.path.join(d, "session"))),
                        ("a unit with an unknown directive", lambda d: open(os.path.join(d, "systemd/voice-auth-watch.service"), "a").write("\nNoSuchDirective=1\n"))):
        b = Box("aw-" + label.split()[1], old_state=False)
        rc, out, err = b.run(src=src_copy("src-aw-" + label.split()[1], edit))
        check(f"deploy.sh with {label}: warning, voice-web and voice-tunnel deployed as usual, no watchdog unit installed or enabled",
              rc == 0 and out.rstrip().endswith("deployed") and "WARNING" in err and "auth watchdog" in err
              and b.verbs() == ["daemon-reload", "enable voice-web.service voice-tunnel.service", "restart voice-web.service", "restart voice-tunnel.service"]
              and not os.path.exists(os.path.join(b.UNITS, "voice-auth-watch.timer")) and not any("voice-auth-watch" in x[0] for x in b.calls()),
              str((rc, b.verbs(), err[-300:])))
        b.stop()

    # -- voice-tunnel is Type=simple: a restart that returns 0 while the unit dies at exec time is not a start
    b = Box("tunneldies", old_state=False)
    b.flag("tunnel-dies")
    rc, out, err = b.run()
    check("deploy.sh when the new voice-tunnel dies at start although the restart returned 0: the previous tunnel unit goes back and runs; voice-web keeps the new units",
          rc != 0 and "voice-tunnel is not running after its restart" in err and "previous voice-tunnel unit is running again" in err and "deployed" not in out
          and b.head("voice-tunnel.service") == "OLD UNIT v0" and b.head("voice-web.service") == "[Unit]"
          and b.verbs()[-4:] == ["restart voice-tunnel.service", "daemon-reload", "stop voice-tunnel.service", "start voice-tunnel.service"]
          and os.path.exists(os.path.join(b.STATE, "active.voice-tunnel.service")), str((rc, b.verbs(), err[-400:])))
    check("deploy.sh when the new voice-tunnel dies at start: the dangling link is dropped, the URL is a plain file again, and no checksum is recorded",
          not os.path.islink(b.URL) and read(b.URL).strip().startswith("https://stub-") and not os.path.exists(os.path.join(b.V, ".tunnel-sum")),
          str((os.path.islink(b.URL), os.path.exists(os.path.join(b.V, ".tunnel-sum")))))
    b.stop()
    # ... but a unit that runs and has no URL yet is only a warning
    b = Box("nourl", old_state=False)
    b.flag("no-url")
    rc, out, err = b.run()
    check("deploy.sh when the new voice-tunnel runs but no URL shows up: a warning only, no way back, the checksum is recorded",
          rc == 0 and "WARNING: no new tunnel URL" in err and out.rstrip().endswith("deployed") and b.head("voice-tunnel.service") == "[Unit]"
          and "stop voice-tunnel.service" not in b.verbs() and read(os.path.join(b.V, ".tunnel-sum")).strip() == tunnel_sum_of(b), str((rc, b.verbs(), err[-300:])))
    b.stop()

    # -- the copy fails: the old service runs again, the old unit stays installed, nothing is lost
    b = Box("copyfail")
    blocker = os.path.join(b.root, "blocker")
    open(blocker, "w").write("x")
    old_tree = tree(os.path.join(b.V, "state"))
    rc, out, err = b.run({"VOICE_STATE_PRIVATE": os.path.join(blocker, "voice")})
    check("deploy.sh with a failing copy: stops with an error, starts the old voice-web again, replaces no unit and reloads nothing",
          rc != 0 and "could not be copied" in err and b.verbs() == ["stop voice-web.service", "start voice-web.service"]
          and b.head("voice-web.service") == "OLD UNIT v0" and os.path.exists(os.path.join(b.STATE, "active.voice-web.service")), str((rc, b.verbs(), err[-300:])))
    check("deploy.sh with a failing copy: the message does not claim that nothing changed (the new code is in place; units and state are not)",
          "Nothing else has changed" not in err and "new code is already in" in err and "unit files and the state are unchanged" in err, err[-400:])
    check("deploy.sh with a failing copy: the old state is untouched", tree(os.path.join(b.V, "state")) == old_tree)
    ok, why = old_unit_runs_new_code(b)
    check("deploy.sh with a failing copy: the old unit file really does run the new server.py on the old state (it comes up, keeps the ids, takes an utterance)", ok, why)
    b.stop()
    # ... and when the old voice-web does not come back after the failed copy, the message does not say it runs
    b = Box("copyfail2")
    b.flag("never-active", "broken-old")
    blocker = os.path.join(b.root, "blocker")
    open(blocker, "w").write("x")
    old_tree = tree(os.path.join(b.V, "state"))
    rc, out, err = b.run({"VOICE_STATE_PRIVATE": os.path.join(blocker, "voice")})
    check("deploy.sh with a failing copy and an old voice-web that does not start again: says VOICE IS DOWN, not that it is running; state and units untouched",
          rc != 0 and "VOICE IS DOWN" in err and "running again" not in err and "could not be copied" in err and "systemctl start voice-web" in err
          and b.verbs() == ["stop voice-web.service", "start voice-web.service"] and b.head("voice-web.service") == "OLD UNIT v0"
          and tree(os.path.join(b.V, "state")) == old_tree, str((rc, b.verbs(), err[-500:])))
    b.stop()

    # -- stop of the old voice-web: a unit that is not loaded cannot be stopped (exit 5) and that is no reason to give up
    b = Box("notloaded", old_units=False)
    rc, out, err = b.run()
    check("deploy.sh with old state but no loaded voice-web unit (stop exits 5): goes on, says so, migrates the state, deploys",
          rc == 0 and out.rstrip().endswith("deployed") and "NOTE: voice-web.service could not be stopped" in out
          and b.verbs()[0] == "stop voice-web.service" and os.path.exists(os.path.join(b.NEW, "inbox.jsonl"))
          and not os.path.exists(os.path.join(b.V, "state")), str((rc, b.verbs(), out[-300:], err[-300:])))
    b.stop()
    # ... but one that is still running after a failed stop is not copied from
    b = Box("stopfails")
    b.flag("stop-fails.voice-web.service")
    old_tree = tree(os.path.join(b.V, "state"))
    rc, out, err = b.run()
    check("deploy.sh when voice-web is still active after a failed stop: refuses, nothing is copied, installed or reloaded",
          rc != 0 and "could not be stopped" in err and not os.path.exists(b.NEW) and b.verbs() == ["stop voice-web.service"]
          and b.head("voice-web.service") == "OLD UNIT v0" and tree(os.path.join(b.V, "state")) == old_tree, str((rc, b.verbs(), err[-300:])))
    b.stop()

    # -- the new voice-web does not become active: the previous units come back, the previous voice-web runs again
    b = Box("nostart")
    b.flag("never-active")
    rc, out, err = b.run()
    check("deploy.sh with a voice-web that does not come up: fails, puts the previous unit files back and starts the previous voice-web, and says so",
          rc != 0 and "did not come up" in err and "Going back" in err and "previous voice-web is running again" in err
          and b.head("voice-web.service") == "OLD UNIT v0" and b.head("voice-tunnel.service") == "OLD UNIT v0"
          and os.path.exists(os.path.join(b.STATE, "active.voice-web.service")), str((rc, err[-500:])))
    check("deploy.sh with a voice-web that does not come up: the message names the kill switch file of the restored service (VOICE_STATE_DIR is not set by the previous unit)",
          f"Its kill switch is the file {b.V}/state/DISABLED, not /var/lib/voice/DISABLED" in err and not os.path.exists(os.path.join(b.V, "units.saved")), err[-500:])
    check("deploy.sh with a voice-web that does not come up: the calls are restart (new), reload, restart (old); the tunnel is not touched",
          b.verbs() == ["stop voice-web.service", "daemon-reload", "enable voice-web.service voice-tunnel.service", "restart voice-web.service",
                        "daemon-reload", "restart voice-web.service"] and not os.path.islink(b.URL) and read(b.URL).strip() == "https://old-tunnel.trycloudflare.com",
          str(b.verbs()))
    check("deploy.sh with a voice-web that does not come up: the old state and its marker are there, this run's copy stays, the message says where both are",
          os.path.exists(os.path.join(b.V, "state/inbox.jsonl")) and os.path.exists(os.path.join(b.V, "state/.copied-to-state-directory"))
          and os.path.exists(os.path.join(b.NEW, "inbox.jsonl")) and "The old state is untouched" in err and ".premigration" in err, err[-500:])
    ok, why = old_unit_runs_new_code(b)
    check("deploy.sh with a voice-web that does not come up: the previous unit file really does run the new server.py on the old state (comes up, keeps the ids, takes an utterance)", ok, why)
    b.stop()

    # -- an exec-time failure (systemd cannot even start the new unit: 243/CREDENTIALS, 226/NAMESPACE): same way back
    b = Box("execfail")
    b.flag("fail-start.voice-web.service")
    rc, out, err = b.run()
    check("deploy.sh when systemd cannot start the new voice-web unit: fails, previous units back, previous voice-web running again",
          rc != 0 and "could not install or start the new unit files" in err and "previous voice-web is running again" in err
          and b.head("voice-web.service") == "OLD UNIT v0" and b.head("voice-tunnel.service") == "OLD UNIT v0"
          and os.path.exists(os.path.join(b.STATE, "active.voice-web.service")) and b.verbs()[-2:] == ["daemon-reload", "restart voice-web.service"], str((rc, b.verbs(), err[-400:])))
    b.stop()

    # -- no migration, the service does not come up: the message does not talk about old state
    b = Box("nostart2", old_state=False)
    b.flag("never-active")
    rc, out, err = b.run()
    check("deploy.sh without old state and a service that does not come up: fails, goes back, mentions no old state",
          rc != 0 and "did not come up" in err and "previous voice-web is running again" in err and "old state" not in err.lower()
          and b.head("voice-web.service") == "OLD UNIT v0", str((rc, err[-300:])))
    b.stop()

    # -- the previous voice-web does not come up either: voice is down, and the message says so and how to fix it by hand
    b = Box("brokenold")
    b.flag("never-active", "broken-old")
    rc, out, err = b.run()
    check("deploy.sh when even the previous voice-web does not come up: says voice is down and how to go back by hand",
          rc != 0 and "VOICE IS DOWN" in err and "To go back by hand" in err and "rm -f " + b.V + "/url" in err, str((rc, err[-500:])))
    ud = os.path.join(b.V, "units.saved")
    check("deploy.sh when even the previous voice-web does not come up: the previous unit files are kept in $VOICE_DIR/units.saved (700, files 600) and the message gives the path",
          os.path.isdir(ud) and mode(ud) == 0o700 and sorted(os.listdir(ud)) == ["voice-tunnel.service", "voice-web.service"]
          and all(mode(os.path.join(ud, f)) == 0o600 and read(os.path.join(ud, f)).startswith("OLD UNIT v0") for f in os.listdir(ud))
          and f"kept in {ud}" in err and f"{ud}/*.service" in err, str((os.path.isdir(ud) and os.listdir(ud), err[-500:])))
    b.stop()

    # -- a first install has no previous unit to go back to
    b = Box("freshfail", old_state=False, old_units=False)
    b.flag("never-active")
    rc, out, err = b.run()
    check("deploy.sh on a first install whose voice-web does not come up: fails and says there is no previous unit (no second restart)",
          rc != 0 and "did not come up" in err and "no previous voice-web unit" in err and b.verbs().count("restart voice-web.service") == 1
          and b.head("voice-web.service") == "[Unit]", str((rc, b.verbs(), err[-300:])))
    b.stop()

    # -- the tunnel unit cannot be started: only the tunnel unit goes back, the dangling link of the failed unit is dropped
    b = Box("tunnelfail", old_state=False)
    b.flag("fail-start.voice-tunnel.service")
    rc, out, err = b.run()
    check("deploy.sh when the new voice-tunnel does not start: fails, the previous tunnel unit is put back and started; voice-web keeps the new units",
          rc != 0 and "voice-tunnel did not start" in err and "previous voice-tunnel unit is running again" in err and "deployed" not in out
          and b.head("voice-tunnel.service") == "OLD UNIT v0" and b.head("voice-web.service") == "[Unit]"
          and b.verbs()[-4:] == ["restart voice-tunnel.service", "daemon-reload", "stop voice-tunnel.service", "start voice-tunnel.service"]
          and os.path.exists(os.path.join(b.STATE, "active.voice-tunnel.service")), str((rc, b.verbs(), err[-300:])))
    check("deploy.sh when the new voice-tunnel does not start: the link the failed unit left dangling is removed, so the previous script writes a plain file",
          not os.path.islink(b.URL) and read(b.URL).strip().startswith("https://stub-"), str((os.path.islink(b.URL), os.path.lexists(b.URL))))
    b.stop()
    b = Box("tunnelfail2", old_state=False)
    b.flag("fail-start.voice-tunnel.service", "broken-old")
    rc, out, err = b.run()
    check("deploy.sh when neither tunnel unit starts: says so, and keeps the previous unit files",
          rc != 0 and "did not start either" in err and os.path.isfile(os.path.join(b.V, "units.saved/voice-tunnel.service")), err[-300:])
    b.stop()
    b = Box("tunnelfail3", old_state=False, old_units=False)
    b.flag("fail-start.voice-tunnel.service")
    rc, out, err = b.run()
    check("deploy.sh on a first install whose tunnel does not start: fails and says there is no previous tunnel unit",
          rc != 0 and "voice-tunnel did not start" in err and "no previous voice-tunnel unit" in err, err[-300:])
    b.stop()

    # -- the service came up but its last id is lower than the old one: the previous units come back, the old state stays
    b = Box("lowid", last_id=1)
    rc, out, err = b.run()
    check("deploy.sh when the service reports a lower last id than the old state: fails, goes back to the previous units and keeps the old directory",
          rc != 0 and "last id '1' but the old state had 9" in err and "previous voice-web is running again" in err
          and b.head("voice-web.service") == "OLD UNIT v0" and os.path.exists(os.path.join(b.V, "state/inbox.jsonl")), str((rc, err[-400:])))
    b.stop()

    # -- a menu button that cannot be confirmed in the journal is a warning, not a failure
    b = Box("nomenu", old_state=False)
    b.flag("no-menu")
    rc, out, err = b.run()
    check("deploy.sh when the journal shows no 'menu button set': a warning, the deploy still succeeds",
          rc == 0 and "WARNING: no 'menu button set' line in the journal of voice-tunnel" in err and out.rstrip().endswith("deployed"), str((rc, err[-300:])))
    b.stop()

    # -- the journal check must not give a false alarm when the journal is long (grep -q would quit early; pipefail would call that a failure)
    b = Box("bigjournal", old_state=False)
    b.flag("big-journal")
    rc, out, err = b.run()
    check("deploy.sh with a 3 MB journal that has the menu-button line first: the line is found, no warning",
          rc == 0 and "the menu button was set" in out and "WARNING" not in err, str((rc, out[-200:], err[-300:])))
    b.stop()

    # -- a fresh install on a machine that has none of it
    b = Box("fresh", old_state=False, old_units=False, env_lines=[], tg_env="exists")
    open(os.path.join(b.V, "env"), "w").write(f"VOICE_PORT={b.port}\nVOICE_TG_ENV_FILE={b.tg}\n")
    os.remove(os.path.join(b.V, "internal_token"))
    open(b.health.token_file, "w").close()
    rc, out, err = b.run()
    # the token is generated by deploy.sh; the health stand-in reads it from the same file
    check("deploy.sh fresh install: no state to move (nothing is stopped), both services are started, the units are installed",
          rc == 0 and b.verbs() == ["daemon-reload", "enable voice-web.service voice-tunnel.service", "restart voice-web.service", "restart voice-tunnel.service"]
          and os.path.isfile(os.path.join(b.UNITS, "voice-web.service")) and os.path.isfile(os.path.join(b.UNITS, "voice-tunnel.service")), str(b.verbs()) + out + err)
    check("deploy.sh fresh install: the missing keys are added to env, the token and glossary are made, all mode 600, no state directory is made",
          "VOICE_LANG=en-US" in read(os.path.join(b.V, "env")) and mode(os.path.join(b.V, "env")) == 0o600
          and len(read(os.path.join(b.V, "internal_token")).strip()) == 64 and mode(os.path.join(b.V, "internal_token")) == 0o600
          and mode(os.path.join(b.V, "glossary.txt")) == 0o600 and not os.path.exists(os.path.join(b.V, "state")) and not os.path.exists(b.NEW))
    check("deploy.sh fresh install: tunnel.env exists (mode 600) with the port even though no chat id is set yet",
          mode(os.path.join(b.V, "tunnel.env")) == 0o600 and f"VOICE_PORT={b.port}" in read(os.path.join(b.V, "tunnel.env")))
    check("deploy.sh fresh install: reminds about the missing settings", "VOICE_ALLOWED_USER is empty" in out and "no API key" in out, out)
    b.stop()

    # -- no Telegram .env on this machine: the units get an empty placeholder, and a bot token set in env reaches the tunnel
    b = Box("notg", old_state=False, tg_env="missing", env_extra=["VOICE_BOT_TOKEN=222222:BOT-token-from-env"])
    rc, out, err = b.run()
    ph = os.path.join(b.V, "telegram.env")
    check("deploy.sh without a Telegram .env: an empty private placeholder is made and both units point at it",
          rc == 0 and os.path.getsize(ph) == 0 and mode(ph) == 0o600 and "NOTE:" in out
          and f"LoadCredential=telegram.env:{ph}" in read(os.path.join(b.UNITS, "voice-web.service"))
          and f"LoadCredential=telegram.env:{ph}" in read(os.path.join(b.UNITS, "voice-tunnel.service")), out + err)
    tenv = os.path.join(b.V, "tunnel.env")
    check("deploy.sh with VOICE_BOT_TOKEN in env: it is copied to tunnel.env (the tunnel needs it to set the menu button), nothing else secret is",
          "VOICE_BOT_TOKEN=222222:BOT-token-from-env\n" in read(tenv) and mode(tenv) == 0o600 and "KEY" not in read(tenv), read(tenv))
    seen, cfargs, tout = tunnel_script(b, tenv, ph)
    check("deploy.sh with VOICE_BOT_TOKEN in env: run_tunnel.sh sets the menu button with that token from tunnel.env alone",
          [x[0] for x in seen] == ["/bot222222:BOT-token-from-env/setChatMenuButton"] and "menu button set" in tout, str((seen, tout[-200:])))
    b.stop()

    # -- a path that cannot be written into a unit file is refused before anything is restarted
    b = Box("badpath", old_state=False, tg_env="exists")
    bad = os.path.join(b.root, "tg&weird.env")
    shutil.copy(b.tg, bad)
    open(os.path.join(b.V, "env"), "a").write(f"VOICE_TG_ENV_FILE={bad}\n")
    rc, out, err = b.run()
    check("deploy.sh with an unusual character in a path: refused, no systemctl call at all",
          rc != 0 and "characters outside" in err and read(b.LOG) == "", str((rc, err[-200:], read(b.LOG))))
    b.stop()

    # -- the lock file is what pins the dependencies: without it (or empty) the deploy stops at once, nothing is changed
    for label, edit in (("missing", lambda d: os.remove(os.path.join(d, "channel/bun.lock"))),
                        ("empty", lambda d: open(os.path.join(d, "channel/bun.lock"), "w").close())):
        b = Box("nolock-" + label, old_state=False)
        rc, out, err = b.run(src=src_copy("src-nolock-" + label, edit))
        check(f"deploy.sh with a {label} channel/bun.lock: stops with a clear message before anything is changed (no systemctl call, nothing copied, no tunnel.env)",
              rc != 0 and "channel/bun.lock is missing or empty" in err and "bun install" in err and "nothing has been changed" in err and read(b.LOG) == ""
              and not os.path.exists(os.path.join(b.OPT, "web/server.py")) and not os.path.exists(os.path.join(b.V, "tunnel.env"))
              and not os.path.exists(os.path.join(b.V, "mcp.json")), str((rc, err[-300:])))
        b.stop()

    # -- a lock file that is gone when the channel is built (the code is copied by then): the message does not say that nothing changed
    b = Box("droplock", old_state=False)
    b.flag("drop-lock")
    rc, out, err = b.run()
    check("deploy.sh when channel/bun.lock is missing from the copied code: stops, says the code is already copied and nothing is restarted (not 'nothing has been changed')",
          rc != 0 and "channel/bun.lock is missing or empty" in err and "already copied" in err and "nothing has been restarted" in err
          and "nothing has been changed" not in err and read(b.LOG) == "", str((rc, err[-400:])))
    b.stop()

    # -- the smoke test runs without node_modules: a bundle that still needs it is caught by the deploy, not by the next session start
    b = Box("extbundle", old_state=False)
    rc, out, err = b.run({"BUN": os.path.join(b.BIN, "bun-external")})
    ch = os.path.join(b.OPT, "channel")
    check("deploy.sh with a bundle that needs node_modules: the smoke test (run without it) fails, the deploy stops before any service or mcp.json is touched",
          rc != 0 and "does not answer an MCP initialize without node_modules" in err and "could not be built" in err and read(b.LOG) == ""
          and not os.path.exists(os.path.join(b.V, "mcp.json")) and not os.path.exists(os.path.join(ch, "dist/server.js"))
          and not os.path.exists(os.path.join(ch, "dist/server.new.js")), str((rc, err[-400:], os.path.exists(ch) and os.listdir(ch))))
    b.stop()

    # -- the bundle must work: a package.json that disagrees with bun.lock stops the deploy before the services are touched
    b = Box("badlock", old_state=False)

    def break_pkg(d):
        pk = json.loads(read(os.path.join(d, "channel/package.json")))
        pk["dependencies"]["zod"] = "3.25.75"                # no longer what bun.lock says: --frozen-lockfile must refuse
        open(os.path.join(d, "channel/package.json"), "w").write(json.dumps(pk))
    rc, out, err = b.run(src=src_copy("src-badlock", break_pkg))
    check("deploy.sh with a package.json that disagrees with bun.lock: stops before any service is touched",
          rc != 0 and "could not be built" in err and read(b.LOG) == "" and not os.path.exists(os.path.join(b.V, "mcp.json")), str((rc, err[-300:])))
    b.stop()

print("FAILED: " + ", ".join(fails) if fails else "test_deploy: ALL PASSED")
sys.exit(1 if fails else 0)
