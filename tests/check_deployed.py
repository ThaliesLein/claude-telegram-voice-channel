#!/usr/bin/env python3
"""Read-only look at the DEPLOYED, hardened services: run it as root after deploy.sh. It sends no request to the
services; it reads systemd properties, /proc/<pid>/status of every process of each unit, the state directory, the
tunnel's URL link and mcp.json. Prints one PASS/FAIL line per check and ALL PASSED.

The names default to the production ones. To check test units (the way the units are validated, see CLAUDE.md):
  check_deployed.py --web voicetest-web --tunnel voicetest-tunnel --state-dir voicetest --runtime-dir voicetest-tunnel \
                    --link /scratch/url-link --skip-channel --skip-old-state"""
import argparse, json, os, re, stat, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--web", default="voice-web")
ap.add_argument("--tunnel", default="voice-tunnel")
ap.add_argument("--state-dir", default="voice", help="name of the StateDirectory of the web unit (/var/lib/<name>)")
ap.add_argument("--runtime-dir", default="voice-tunnel", help="name of the RuntimeDirectory of the tunnel unit (/run/<name>)")
ap.add_argument("--voice-dir", default="/root/.voice")
ap.add_argument("--link", help="the link to the tunnel URL (default: <voice-dir>/url)")
ap.add_argument("--opt-dir", default="/opt/voice")
ap.add_argument("--skip-channel", action="store_true", help="do not look at mcp.json and the channel bundle")
ap.add_argument("--skip-old-state", action="store_true", help="do not require that <voice-dir>/state is gone")
ap.add_argument("--max-exposure", type=float, default=2.0, help="highest acceptable systemd-analyze security score")
args = ap.parse_args()
LINK = args.link or os.path.join(args.voice_dir, "url")
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f" ({extra})" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def systemctl_show(unit, *props):
    r = subprocess.run(["systemctl", "show", unit] + [f"-p{p}" for p in props], capture_output=True, text=True)
    return dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)


def proc_status(pid):
    out = {}
    for line in open(f"/proc/{pid}/status"):
        if ":\t" in line:
            k, v = line.rstrip("\n").split(":\t", 1)
            out[k] = v.strip()
    return out


def unit_pids(unit):
    cg = systemctl_show(unit, "ControlGroup").get("ControlGroup", "")
    try:
        return [int(x) for x in open(f"/sys/fs/cgroup{cg}/cgroup.procs").read().split()]
    except OSError:
        return []


def uid_of(pid):
    return int(proc_status(pid)["Uid"].split()[0])


def check_unit(unit, label):
    p = systemctl_show(unit, "ActiveState", "SubState", "DynamicUser", "ProtectSystem", "ProtectHome", "PrivateTmp",
                       "NoNewPrivileges", "SystemCallErrorNumber", "MainPID", "NRestarts")
    check(f"{label}: active (running)", p.get("ActiveState") == "active" and p.get("SubState") == "running", str(p))
    check(f"{label}: DynamicUser, strict filesystem, no /root, private /tmp, no new privileges, EPERM for filtered syscalls",
          p.get("DynamicUser") == "yes" and p.get("ProtectSystem") == "strict" and p.get("ProtectHome") == "yes"
          and p.get("PrivateTmp") == "yes" and p.get("NoNewPrivileges") == "yes"
          and p.get("SystemCallErrorNumber") in ("EPERM", "1"), str(p))     # systemctl shows the errno number
    pids = unit_pids(unit)
    check(f"{label}: has processes", bool(pids), str(pids))
    bad = []
    uids = set()
    for pid in pids:
        try:
            st = proc_status(pid)
        except OSError:
            continue
        uid = int(st["Uid"].split()[0])
        uids.add(uid)
        ok = (len(set(st["Uid"].split())) == 1 and uid != 0 and len(set(st["Gid"].split())) == 1 and int(st["Gid"].split()[0]) != 0
              and all(int(st[k], 16) == 0 for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
              and st["NoNewPrivs"] == "1" and st["Seccomp"] == "2")
        if not ok:
            bad.append((pid, st.get("Name"), st["Uid"], st["CapEff"], st["NoNewPrivs"], st["Seccomp"]))
    check(f"{label}: every process runs as one unprivileged uid, with no capabilities, NoNewPrivs and a seccomp filter",
          pids and not bad and len(uids) == 1, str(bad or uids))
    r = subprocess.run(["systemd-analyze", "security", unit, "--no-pager"], capture_output=True, text=True)
    m = re.search(r"Overall exposure level for \S+: ([0-9.]+)", r.stdout)
    check(f"{label}: systemd-analyze security exposure at most {args.max_exposure}",
          bool(m) and float(m.group(1)) <= args.max_exposure, m.group(0) if m else r.stdout[-200:] + r.stderr[-200:])
    return (next(iter(uids)) if len(uids) == 1 else None), p


web_uid, _ = check_unit(args.web, "web unit")
tun_uid, _ = check_unit(args.tunnel, "tunnel unit")
check("web and tunnel run as different users", web_uid is not None and tun_uid is not None and web_uid != tun_uid, f"{web_uid} {tun_uid}")
def loaded_credentials(unit):            # systemctl show cannot print LoadCredential: read the unit text
    text = subprocess.run(["systemctl", "cat", unit], capture_output=True, text=True).stdout
    return sorted(m.group(1) for m in re.finditer(r"^LoadCredential=([^:\s]+):", text, re.M))


check("web unit: four credentials (env, glossary.txt, internal_token, telegram.env)",
      loaded_credentials(args.web) == ["env", "glossary.txt", "internal_token", "telegram.env"], str(loaded_credentials(args.web)))
check("tunnel unit: two credentials (env, telegram.env)", loaded_credentials(args.tunnel) == ["env", "telegram.env"], str(loaded_credentials(args.tunnel)))


def credential_source(unit, name):
    text = subprocess.run(["systemctl", "cat", unit], capture_output=True, text=True).stdout
    m = re.search(r"^LoadCredential=%s:(\S+)" % re.escape(name), text, re.M)
    return m.group(1) if m else None


# The tunnel's credential called env is the reduced tunnel.env, never the web unit's env file: cloudflared must not be
# able to read the API keys.
web_env, tun_env = credential_source(args.web, "env"), credential_source(args.tunnel, "env")
check("tunnel unit: its credential 'env' is tunnel.env, not the file voice-web gets",
      tun_env is not None and os.path.basename(tun_env) == "tunnel.env" and tun_env != web_env, f"web {web_env}, tunnel {tun_env}")
TUNNEL_KEYS = {"VOICE_PORT", "VOICE_ALLOWED_USER", "VOICE_CHAT_ID", "VOICE_MENU_TEXT", "VOICE_BOT_TOKEN"}
try:
    keys = [ln.split("=", 1)[0].strip() for ln in open(tun_env, encoding="utf-8", errors="replace") if "=" in ln and not ln.lstrip().startswith("#")]
    check("tunnel.env: only tunnel settings (no API key), mode 600", set(keys) <= TUNNEL_KEYS and stat.S_IMODE(os.stat(tun_env).st_mode) == 0o600,
          f"keys {sorted(set(keys) - TUNNEL_KEYS)}, mode {oct(os.stat(tun_env).st_mode)}")
except (OSError, TypeError) as e:
    check("tunnel.env: can be read", False, str(e))

# ---- state directory of voice-web ----
link, private = f"/var/lib/{args.state_dir}", f"/var/lib/private/{args.state_dir}"
check("state: /var/lib/<name> is a link to the private directory", os.path.islink(link) and os.path.realpath(link) == private, f"{link} -> {os.path.realpath(link)}")
st = os.stat(private) if os.path.isdir(private) else None
check("state: the directory belongs to the web unit's user, mode 700", st is not None and st.st_uid == web_uid and stat.S_IMODE(st.st_mode) == 0o700,
      f"{st and (st.st_uid, oct(st.st_mode))} vs uid {web_uid}")
wrong = []
for dp, dns, fns in os.walk(private):
    for n in dns + fns:
        s = os.lstat(os.path.join(dp, n))
        if s.st_uid != web_uid and n != "DISABLED":      # the kill switch is made by root
            wrong.append((os.path.join(dp, n), s.st_uid))
check("state: everything inside belongs to the web unit's user", not wrong, str(wrong[:3]))
# (a fresh install has neither file before the first utterance: whichever exist must be private)
private_files = [f for f in ("inbox.jsonl", "last_id") if os.path.exists(os.path.join(private, f))]
check("state: inbox.jsonl and last_id, where they exist, are private (mode 600)",
      all(stat.S_IMODE(os.stat(os.path.join(private, f)).st_mode) == 0o600 for f in private_files), str(private_files))
if not args.skip_old_state:
    old = os.path.join(args.voice_dir, "state")
    check("state: the old state directory is gone", not os.path.exists(old), os.path.exists(old) and str(os.listdir(old)))

# ---- tunnel URL ----
runtime_url = f"/run/{args.runtime_dir}/url"
check("tunnel: the URL link points into the runtime directory", os.path.islink(LINK) and os.readlink(LINK) == runtime_url, f"{LINK} -> {os.path.islink(LINK) and os.readlink(LINK)}")
try:
    s = os.stat(runtime_url)
    url = open(runtime_url).read().strip()
    check("tunnel: the URL file is mode 600, owned by the tunnel unit's user, and holds a quick-tunnel URL",
          stat.S_IMODE(s.st_mode) == 0o600 and s.st_uid == tun_uid and re.fullmatch(r"https://[a-z0-9-]+\.trycloudflare\.com", url) is not None, f"{oct(s.st_mode)} {s.st_uid} {url[:40]}")
    check("tunnel: the link reads the same URL", open(LINK).read().strip() == url)
except OSError as e:
    check("tunnel: the URL file exists", False, str(e))

# ---- channel server ----
if not args.skip_channel:
    ch = os.path.join(args.opt_dir, "channel")
    try:
        mcp = json.load(open(os.path.join(args.voice_dir, "mcp.json")))["mcpServers"]["voice"]
    except (OSError, ValueError, KeyError) as e:
        mcp = {"error": str(e)}
    check("channel: mcp.json runs the bundle", mcp.get("args") == [os.path.join(ch, "dist/server.js")] and os.access(mcp.get("command", ""), os.X_OK), str(mcp))
    check("channel: the bundle exists and there is no node_modules next to it",
          os.path.isfile(os.path.join(ch, "dist/server.js")) and not os.path.exists(os.path.join(ch, "node_modules")) and os.path.isfile(os.path.join(ch, "bun.lock")))
    check("channel: package.json has exact versions and start runs the bundle ('bun dist/server.js')",
          (lambda pkg: all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in pkg["dependencies"].values()) and pkg["scripts"]["start"] == "bun dist/server.js")(
              json.load(open(os.path.join(ch, "package.json")))))

print("FAILED: " + ", ".join(fails) if fails else "check_deployed: ALL PASSED")
sys.exit(1 if fails else 0)
