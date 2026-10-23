#!/usr/bin/env python3
"""Browser end-to-end tests of the Mini App: Live mode, push-to-talk, language, asset loading.

Headless Chrome is driven over the DevTools Protocol (Python `websockets`) against a throwaway voice-web
instance. The microphone is a WAV file played by Chrome's fake audio device, so no hardware is needed.
Real speech recognition and speech synthesis are used (about 15 recognitions and 4 syntheses in a full run,
a fraction of a cent), so the instance reads its API keys from VOICE_ENV_FILE (default /root/.voice/env).
Without a key the suite stops with a clear message. Nothing is mirrored to Telegram: the instance runs with
a fake bot token and VOICE_MIRROR_TG=0.

Run it after deploy.sh (it uses the vendor files that deploy.sh installed in /opt/voice/web/vendor).
Chrome: the Chrome for Testing launcher of the host, or CHROME=/path/to/chrome. One Chrome runs at a time,
and each one is killed through its own process group. Environment (all optional):
  CHROME               Chrome binary                       (default /root/.cache/archify-chrome/chrome)
  VOICE_TEST_VENDOR    directory with the vendor files    (default web/vendor in the repo, else /opt/voice/web/vendor)
  VOICE_TEST_SAMPLE    WAV with speech (mono 16 bit)      (default: synthesized through the instance's TTS)
  VOICE_TEST_LANG      VOICE_LANG of the instance          (default en-US; use the language of the sample)
  VOICE_TEST_ONLY      comma separated test names to run   (e.g. "language,live")
Every test ends with a check that the page reported no Content-Security-Policy violation (the tests that provoke one on purpose
excepted). Tests that need a server feature (the policy header, GET /api/config) print SKIP when the server lacks it: that is not
a failure. Prints ALL PASSED and exits 0 when everything passed."""
import asyncio, atexit, hashlib, hmac, json, os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request, uuid, wave

try:
    import websockets
except ImportError:
    sys.exit("python3 'websockets' is required: pip install websockets")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME = os.environ.get("CHROME", "/root/.cache/archify-chrome/chrome")
FAKE_BOT = "123456:TESTTOKEN-not-real"     # the instance and the signed initData both use it; the real bot is never involved
ITOK = "browsertestinternaltoken"
USER = 111111111
ENV_FILE = os.environ.get("VOICE_ENV_FILE", "/root/.voice/env")
ONLY = [x for x in os.environ.get("VOICE_TEST_ONLY", "").split(",") if x]
VENDOR = os.environ.get("VOICE_TEST_VENDOR") or next(
    (d for d in (os.path.join(ROOT, "web/vendor"), "/opt/voice/web/vendor") if os.path.isfile(os.path.join(d, "vad.bundle.min.js"))), "")
LANG = os.environ.get("VOICE_TEST_LANG", "en-US")
SAMPLE_TEXT = ("Please look up the weather forecast for tomorrow morning and tell me whether I should take an umbrella "
               "when I leave for work, and also remind me to buy bread on the way home.")
# A long reply: its synthesized speech has to outlast one repetition of the looping microphone file (about 14 s).
LONG_REPLY = ("This is a long spoken reply, used to check that the page stops listening while it talks. "
              "In the morning it is cloudy with a light wind from the west, around twelve degrees. "
              "By noon the clouds break up and the temperature rises to seventeen. "
              "In the afternoon a short shower is possible, so an umbrella is a good idea.")

fails, skipped = [], []
viol_log = []                        # Content-Security-Policy violations the page reported during the current test (see Session.__aexit__)
tmp = tempfile.mkdtemp(prefix="voicebrowser")
atexit.register(shutil.rmtree, tmp, True)
started = {"web": None, "chrome": None}
used = {"ports": [], "pids": []}     # everything this run started, checked again at the very end


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""), flush=True)
    if not cond:
        fails.append(name)


def info(msg):
    print("     " + msg, flush=True)


def skip(name, why):
    """A test that needs something the server does not have yet: reported, not failed."""
    print(f"SKIP {name}: {why}", flush=True)
    skipped.append(name)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def port_is_free(p):
    s = socket.socket()
    s.settimeout(1)
    try:
        return s.connect_ex(("127.0.0.1", p)) != 0
    finally:
        s.close()


# ---------------------------------------------------------------------------------------------- audio fixtures
def read_wav(path):
    with wave.open(path) as w:
        assert w.getsampwidth() == 2, "the speech sample must be 16-bit PCM"
        raw, ch, rate = w.readframes(w.getnframes()), w.getnchannels(), w.getframerate()
    s = list(struct.unpack("<%dh" % (len(raw) // 2), raw))
    if ch > 1:
        s = [sum(s[i:i + ch]) // ch for i in range(0, len(s) - ch + 1, ch)]
    return s, rate


def resample(s, src, dst):
    """Linear interpolation; plenty for a speech stand-in."""
    if src == dst:
        return s
    n = int(len(s) * dst / src)
    out = []
    for i in range(n):
        x = i * src / dst
        j = int(x)
        f = x - j
        a = s[j]
        b = s[j + 1] if j + 1 < len(s) else a
        out.append(int(a + (b - a) * f))
    return out


def write_wav(path, samples, rate=48000):
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(struct.pack("<%dh" % len(samples), *samples))


def silence(sec, rate=48000):
    return [0] * int(sec * rate)


def active_span(samples, rate, thresh=330, frame=0.02):
    """(first, last) second at which a 20 ms frame of the sample is louder than thresh (RMS, 16-bit scale)."""
    n, first, last = int(rate * frame), None, None
    for i in range(0, len(samples) - n, n):
        w = samples[i:i + n]
        if (sum(x * x for x in w) / n) ** 0.5 > thresh:
            first = i / rate if first is None else first
            last = (i + n) / rate
    return first, last


# ---------------------------------------------------------------------------------------------- HTTP helpers
def req(base, path, method="GET", data=None, headers=None, timeout=120):
    r = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def init_data(lang=None, user_id=USER, token=FAKE_BOT, age=0):
    u = {"id": user_id, "first_name": "T"}
    if lang:
        u["language_code"] = lang
    d = {"auth_date": str(int(time.time()) - age), "query_id": "AAbrowser", "user": json.dumps(u, separators=(",", ":"))}
    dcs = "\n".join(f"{k}={v}" for k, v in sorted(d.items()))
    d["hash"] = hmac.new(hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest(), dcs.encode(), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(d)


# ---------------------------------------------------------------------------------------------- test instance
class Instance:
    def __init__(self, extra=None, fake=False):
        """extra: more VOICE_* settings. fake: no speech keys (recognition and synthesis are the FAKE ones), so it costs nothing."""
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        used["ports"].append(self.port)
        self.state = os.path.join(tmp, "state" if started["web"] is None else f"state-{self.port}")
        tok = os.path.join(tmp, "tok")
        open(tok, "w").write(ITOK)
        env = {k: v for k, v in os.environ.items() if not k.startswith("VOICE_")}
        env.update(VOICE_PORT=str(self.port), VOICE_STATE_DIR=self.state, VOICE_TOKEN_FILE=tok, VOICE_ENV_FILE=ENV_FILE,
                   VOICE_MIRROR_TG="0", VOICE_ALLOWED_USER=str(USER), VOICE_BOT_TOKEN=FAKE_BOT, VOICE_VENDOR_DIR=VENDOR,
                   VOICE_LANG=LANG)
        if fake:
            env.update(VOICE_ENV_FILE=os.path.join(tmp, "no-such-env"), OPENROUTER_API_KEY="")
        env.update(extra or {})
        self.log = []
        self.p = subprocess.Popen([sys.executable, os.path.join(ROOT, "web/server.py")], env=env, stderr=subprocess.PIPE, text=True,
                                  start_new_session=True)
        import threading
        threading.Thread(target=lambda: [self.log.append(l.rstrip("\n")) for l in self.p.stderr], daemon=True).start()
        if started["web"] is None:
            started["web"] = self
        else:
            started.setdefault("extra", []).append(self)     # stopped by main() as well, should a test not do it
        used["pids"].append(self.p.pid)
        for _ in range(100):
            try:
                if req(self.base, "/", timeout=2)[0] == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("test instance did not start: " + " | ".join(self.log))

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(5)

    def inbox(self):
        try:
            return [json.loads(l) for l in open(os.path.join(self.state, "inbox.jsonl"), encoding="utf-8") if l.strip()]
        except OSError:
            return []

    def reply(self, text, speech=None):
        """POST /internal/reply (blocks while the speech is synthesized). Returns the HTTP status."""
        body = {"text": text}
        if speech:
            body["speech"] = speech
        return req(self.base, "/internal/reply", "POST", json.dumps(body).encode(),
                   {"X-Internal-Token": ITOK, "Content-Type": "application/json"}, timeout=180)[0]

    def url(self, lang=None, age=0):
        return f"{self.base}/#tgWebAppData={urllib.parse.quote(init_data(lang, age=age), safe='')}&tgWebAppVersion=9.6&tgWebAppPlatform=android"


# ---------------------------------------------------------------------------------------------- Chrome + CDP
class Chrome:
    """One headless Chrome with a fake microphone playing `wav`. Killed through its process group."""

    def __init__(self, wav, loop=True):
        self.port = free_port()
        self.udd = tempfile.mkdtemp(prefix="vc-chrome-", dir=tmp)
        args = [CHROME, "--no-sandbox", "--disable-gpu", "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream",
                "--use-file-for-fake-audio-capture=" + wav + ("" if loop else "%noloop"),
                "--autoplay-policy=no-user-gesture-required", "--mute-audio", f"--remote-debugging-port={self.port}",
                f"--user-data-dir={self.udd}", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
                "--disable-background-timer-throttling", "--disable-renderer-backgrounding", "--window-size=412,820", "about:blank"]
        self.p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.pgid = os.getpgid(self.p.pid)
        used["ports"].append(self.port)
        used["pids"].append(self.p.pid)
        started["chrome"] = self

    def stop(self):
        try:
            os.killpg(self.pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.p.wait(8)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.p.wait(5)
        shutil.rmtree(self.udd, ignore_errors=True)
        started["chrome"] = None

    def ws_url(self, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            try:
                for t in json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=2).read()):
                    if t.get("type") == "page":
                        return t["webSocketDebuggerUrl"]
            except Exception:
                time.sleep(0.2)
            if self.p.poll() is not None:
                raise RuntimeError("Chrome exited at start")
        raise RuntimeError("Chrome has no page target")


# Injected before any page script: records what the tests assert on, without changing the page.
INSTRUMENT = r"""
(function(){
  var T = window.__T = {media: [], fetches: [], states: [], wake: [], console: [], osc: [], gum: [], streams: [], csp: [], reports: [], cfg: [], resume: []};
  var now = function(){ return Date.now(); };
  ['play','playing','pause','ended','error','emptied'].forEach(function(n){
    document.addEventListener(n, function(e){ if (e.target && e.target.tagName === 'AUDIO') T.media.push({t: now(), type: n, dur: e.target.duration || null, src: String(e.target.currentSrc || e.target.src || '').slice(-60)}); }, true);
  });
  var of = window.fetch;
  window.fetch = function(u, o){
    var s = String((u && u.url) || u), up = s.indexOf('api/utterance') >= 0, rep = s.indexOf('api/csp-report') >= 0, cf = s.indexOf('api/config') >= 0;
    if (up) T.fetches.push({t: now(), phase: 'start', bytes: o && o.body ? o.body.byteLength : -1});
    var p = of.apply(this, arguments);
    if (up) p.then(function(r){ T.fetches.push({t: now(), phase: 'response', status: r.status}); }, function(){ T.fetches.push({t: now(), phase: 'error'}); });
    if (rep || cf) {   // the page's CSP reports and its settings request: what was sent, with which header, and the answer
      var rec = {t: now(), method: (o && o.method) || 'GET', body: o && o.body ? String(o.body) : '', init: !!(o && o.headers && o.headers['X-Init-Data']), status: 0};
      (rep ? T.reports : T.cfg).push(rec);
      p.then(function(r){ rec.status = r.status; }, function(){ rec.status = -1; });
    }
    return p;
  };
  // Every Content-Security-Policy violation the page sees (the server's policy, once it sends one). Tests assert there are none.
  document.addEventListener('securitypolicyviolation', function(e){ T.csp.push({t: now(), dir: e.effectiveDirective, blocked: e.blockedURI, disp: e.disposition}); }, true);
  if (window.AudioContext) { var arz = AudioContext.prototype.resume; AudioContext.prototype.resume = function(){ T.resume.push(now()); return arz.apply(this, arguments); }; }
  var ogum = navigator.mediaDevices && navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  if (ogum) navigator.mediaDevices.getUserMedia = function(c){ return ogum(c).then(function(s){ T.gum.push({t: now()}); T.streams.push(s); return s; }); };
  // Screen wake lock: record requests; headless Chrome has no screen, so hand out a stand-in sentinel.
  if (navigator.wakeLock) navigator.wakeLock.request = function(type){
    var listeners = [], s = {released: false, type: type,
      release: function(){ s.released = true; return Promise.resolve(); },
      addEventListener: function(n, f){ if (n === 'release') listeners.push(f); },
      fire: function(){ s.released = true; listeners.forEach(function(f){ f(); }); }};
    T.wake.push({t: now(), type: type, sentinel: s});
    return Promise.resolve(s);
  };
  ['log','warn','error'].forEach(function(k){
    var o = console[k];
    console[k] = function(){ try { T.console.push({t: now(), k: k, s: Array.prototype.map.call(arguments, function(a){ return typeof a === 'string' ? a : JSON.stringify(a); }).join(' ')}); } catch(e){} return o.apply(console, arguments); };
  });
  var po = OscillatorNode.prototype.start;
  OscillatorNode.prototype.start = function(){ T.osc.push({t: now(), f: this.frequency.value}); return po.apply(this, arguments); };
  document.addEventListener('DOMContentLoaded', function(){
    var last = null;
    function snap(){
      var st = document.getElementById('state'), orb = document.getElementById('orb');
      var cur = (st ? st.textContent : '') + '|' + (orb ? orb.getAttribute('data-state') : '');
      if (cur !== last) { last = cur; T.states.push({t: now(), text: st ? st.textContent : '', state: orb ? orb.getAttribute('data-state') : ''}); }
    }
    new MutationObserver(snap).observe(document.documentElement, {subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['data-state']});
    snap();
  });
})();
"""


class Page:
    def __init__(self, ws):
        self.ws, self.n, self.pending, self.requests, self.responses, self.failed, self.console_native = ws, 0, {}, {}, {}, [], []
        self.task = asyncio.ensure_future(self._reader())

    async def _reader(self):
        try:
            async for msg in self.ws:
                m = json.loads(msg)
                if "id" in m:
                    f = self.pending.pop(m["id"], None)
                    if f and not f.done():
                        f.set_result(m)
                    continue
                meth, p = m.get("method"), m.get("params", {})
                if meth == "Network.requestWillBeSent":
                    self.requests[p["requestId"]] = {"url": p["request"]["url"], "method": p["request"]["method"], "type": p.get("type"),
                                                     "wall": p.get("wallTime")}
                elif meth == "Network.responseReceived":
                    self.responses[p["requestId"]] = {"url": p["response"]["url"], "status": p["response"]["status"],
                                                      "mime": p["response"].get("mimeType"), "headers": p["response"].get("headers", {})}
                elif meth == "Network.loadingFailed":
                    self.failed.append({"id": p["requestId"], "error": p.get("errorText"), "blocked": p.get("blockedReason")})
                elif meth == "Runtime.exceptionThrown":
                    self.console_native.append("EXC " + json.dumps(p["exceptionDetails"])[:300])
        except Exception:
            pass

    async def send(self, method, params=None, timeout=30):
        self.n += 1
        i = self.n
        f = asyncio.get_event_loop().create_future()
        self.pending[i] = f
        await self.ws.send(json.dumps({"id": i, "method": method, "params": params or {}}))
        m = await asyncio.wait_for(f, timeout)
        if "error" in m:
            raise RuntimeError(f"{method}: {m['error']}")
        return m.get("result", {})

    async def ev(self, expr, await_promise=False, timeout=30, strict_csp=False):
        """strict_csp: DevTools evaluation may otherwise use eval() although the page's policy forbids it."""
        params = {"expression": expr, "returnByValue": True, "awaitPromise": await_promise}
        if strict_csp:
            params["allowUnsafeEvalBlockedByCSP"] = False
        r = await self.send("Runtime.evaluate", params, timeout)
        if "exceptionDetails" in r:
            raise RuntimeError("eval: " + json.dumps(r["exceptionDetails"])[:400])
        return r["result"].get("value")

    async def wait(self, expr, timeout=30, every=0.2, label=""):
        """Poll a JS expression until it is truthy; returns its value or None on timeout."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                v = await self.ev(expr)
            except RuntimeError:
                v = None
            if v:
                return v
            await asyncio.sleep(every)
        return None

    async def click(self, selector):
        """A real mouse click (Input.dispatchMouseEvent) at the centre of the element."""
        c = await self.ev("(function(){var e=document.querySelector(%s);e.scrollIntoView({block:'center'});var r=e.getBoundingClientRect();"
                          "return [r.x+r.width/2,r.y+r.height/2]})()" % json.dumps(selector))
        x, y = c
        await self.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        await self.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1})
        await self.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1})

    async def T(self):
        return await self.ev("JSON.stringify({media:__T.media,fetches:__T.fetches,states:__T.states,console:__T.console,osc:__T.osc,"
                             "gum:__T.gum,csp:__T.csp,reports:__T.reports,cfg:__T.cfg,resume:__T.resume,"
                             "tracks:__T.streams.map(function(s){return s.getTracks().map(function(t){return t.readyState})}),"
                             "wake:__T.wake.map(function(w){return {t:w.t,type:w.type,released:w.sentinel.released}})})")


class Session:
    """async with Session(inst, wav, lang=..., loop=...) as page"""

    def __init__(self, inst, wav, lang=None, loop=True, block=None, script=None, csp_probe=False, age=0):
        """csp_probe: the test provokes policy violations on purpose, so they are not counted against it.
        age: how many seconds old the page's initData is."""
        self.inst, self.wav, self.lang, self.loop, self.block, self.script, self.csp_probe = inst, wav, lang, loop, block, script, csp_probe
        self.age = age
        self.page = None

    async def __aenter__(self):
        self.chrome = Chrome(self.wav, self.loop)
        try:
            self.ws = await websockets.connect(self.chrome.ws_url(), max_size=None, ping_interval=None)
            pg = self.page = Page(self.ws)
            await pg.send("Runtime.enable")
            await pg.send("Page.enable")
            await pg.send("Network.enable")
            await pg.send("Emulation.setDeviceMetricsOverride", {"width": 412, "height": 820, "deviceScaleFactor": 1, "mobile": False})
            if self.block:
                await pg.send("Network.setBlockedURLs", {"urls": self.block})
            await pg.send("Page.addScriptToEvaluateOnNewDocument", {"source": INSTRUMENT})
            if self.script:
                await pg.send("Page.addScriptToEvaluateOnNewDocument", {"source": self.script})
            await self.navigate()
        except BaseException:
            await self.__aexit__(None, None, None)
            raise
        return self.page

    async def navigate(self):
        pg = self.page
        await pg.send("Page.navigate", {"url": self.inst.url(self.lang, self.age)})
        ok = await pg.wait("document.readyState==='complete' && !!(window.Telegram&&Telegram.WebApp&&Telegram.WebApp.initData)", 30)
        if not ok:
            raise RuntimeError("the page did not get its Telegram context (is https://telegram.org reachable?)")

    async def __aexit__(self, *exc):
        # Let every upload that is still in flight finish, so a late phrase of this session cannot show up in the
        # next test's inbox.
        try:
            if self.page:
                await self.page.ev("(function(){var b=document.getElementById('livebtn');if(b&&b.className==='on')b.click()})()")   # end Live: no new phrases
                await self.page.wait("(function(){var s=0,r=0;__T.fetches.forEach(function(f){if(f.phase==='start')s++;else r++});return s<=r})()", 25, 0.3)
        except Exception:
            pass
        try:
            if self.page and not self.csp_probe:
                viol_log.extend(json.loads(await self.page.ev("JSON.stringify(__T.csp)")))
        except Exception:
            pass
        try:
            if getattr(self, "ws", None):
                await self.ws.close()
        except Exception:
            pass
        self.chrome.stop()


def parse(js):
    return json.loads(js)


async def wait_utterance(inst, pg, n0, timeout=45):
    """Wait until the page got a 200 for one of its uploads and the instance has stored a new utterance (more than n0
    in its inbox). Returns the new inbox entries, or None."""
    ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='response' && f.status===200})", timeout)
    end = time.time() + 5
    while ok and time.time() < end and len(inst.inbox()) <= n0:
        await asyncio.sleep(0.2)
    return inst.inbox()[n0:] if ok and len(inst.inbox()) > n0 else None


def state_labels(T):
    return [s["text"] for s in T["states"]]


# ---------------------------------------------------------------------------------------------- tests
VIS = "function vis(id){var e=document.getElementById(id);return !!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)}"


async def t_language(inst, fx):
    """(d) The page speaks Russian for language_code ru, English otherwise; preferences persist."""
    ru = {"title": "\u0413\u043e\u043b\u043e\u0441", "start": "\u041d\u0430\u0447\u0430\u0442\u044c \u0440\u0430\u0437\u0433\u043e\u0432\u043e\u0440",
          "ptt": "\u041f\u043e \u043a\u043d\u043e\u043f\u043a\u0435", "short": "\u041a\u043e\u0440\u043e\u0442\u043a\u0430\u044f 0,8 \u0441",
          "rec": "\u0413\u043e\u0432\u043e\u0440\u0438\u0442\u044c"}
    async with Session(inst, fx["live"], lang="ru") as pg:
        v = await pg.ev("JSON.stringify({lang:document.documentElement.lang,title:document.title,start:document.getElementById('livebtn').textContent,"
                        "ptt:document.getElementById('mode-ptt').textContent,short:document.querySelector('[data-sil=short]').textContent,"
                        "rec:document.getElementById('rec').textContent,body:document.body.innerText})")
        v = parse(v)
        check("(d) language_code ru: <html lang> is ru", v["lang"] == "ru", str(v))
        check("(d) language_code ru: title and Live button are Russian", v["title"] == ru["title"] and v["start"] == ru["start"], str(v))
        check("(d) language_code ru: mode switch, pause preset and push-to-talk button are Russian",
              v["ptt"] == ru["ptt"] and v["short"] == ru["short"] and v["rec"] == ru["rec"], str(v))
        check("(d) language_code ru: no English UI strings left", "Start conversation" not in v["body"] and "Push-to-talk" not in v["body"], v["body"][:200])
    for lang in ("en", None):
        async with Session(inst, fx["live"], lang=lang) as pg:
            v = parse(await pg.ev("JSON.stringify({lang:document.documentElement.lang,start:document.getElementById('livebtn').textContent})"))
            check(f"(d) language_code {lang!r}: English", v["lang"] == "en" and v["start"] == "Start conversation", str(v))
    # persistence of the mode and of the pause preset (localStorage), and defaults
    async with Session(inst, fx["live"], lang="en") as pg:
        v = parse(await pg.ev(VIS + ";JSON.stringify({mode:document.getElementById('app').dataset.mode,sil:document.querySelector('#silopts [aria-pressed=true]').dataset.sil,"
                              "orb:vis('orb'),rec:vis('rec')})"))
        check("defaults: Live mode, Normal pause, indicator shown, push-to-talk button hidden",
              v["mode"] == "live" and v["sil"] == "normal" and v["orb"] and not v["rec"], str(v))
        await pg.click("[data-sil=long]")
        await pg.click("#mode-ptt")
        await pg.ev("location.reload()")
        await asyncio.sleep(0.5)
        await pg.wait("document.readyState==='complete' && !!(window.Telegram&&Telegram.WebApp&&Telegram.WebApp.initData)", 20)
        v = parse(await pg.ev(VIS + ";JSON.stringify({mode:document.getElementById('app').dataset.mode,sil:document.querySelector('#silopts [aria-pressed=true]').dataset.sil,"
                              "ls:[localStorage.getItem('mode'),localStorage.getItem('silence')],orb:vis('orb'),rec:vis('rec')})"))
        check("mode and pause preset persist across reloads (localStorage)", v["mode"] == "ptt" and v["sil"] == "long" and v["ls"] == ["ptt", "long"], str(v))
        check("push-to-talk mode shows the Speak button and hides the Live indicator", v["rec"] and not v["orb"], str(v))


async def t_live(inst, fx):
    """(a) Live captures speech and uploads it; (e) the VAD assets come from /vendor/ only."""
    n0 = len(inst.inbox())
    async with Session(inst, fx["live"], lang="en", loop=False) as pg:
        t_click = time.time() * 1000
        await pg.click("#livebtn")
        ok = await pg.wait("document.getElementById('orb').dataset.state==='listening'||document.getElementById('orb').dataset.state==='hearing'", 40)
        check("(a) Live starts: the indicator reaches the listening state", bool(ok))
        got = await wait_utterance(inst, pg, n0, 45)
        check("(a) Live: an utterance reaches the test instance without any button press", bool(got), "no utterance within 45 s")
        if got:
            info("recognized: " + got[0]["text"])
        await asyncio.sleep(1.5)
        T = parse(await pg.T())
        labels = state_labels(T)
        ups = [f for f in T["fetches"] if f["phase"] == "start"]
        check("(a) Live: the page went through Hearing you, Sending and Thinking",
              all(any(x in l for l in labels) for x in ("Hearing you", "Sending", "Thinking")), str(labels))
        check("(a) Live: a soft beep (oscillator) was played when the phrase was sent", len(T["osc"]) >= 1, str(T["osc"]))
        if ups:
            by = ups[0]["bytes"]
            check("(a) Live: the upload is 16 kHz PCM of about the phrase length", 0.6 * fx["speech_len"] * 32000 <= by <= (fx["speech_len"] + 1.5) * 32000 and by % 2 == 0,
                  f"{by / 32000:.1f} s for {fx['speech_len']:.1f} s of speech")
            gum = T["gum"][0]["t"] if T["gum"] else t_click
            lat = (ups[0]["t"] - (gum + 1000 + fx["speech_last"] * 1000)) / 1000
            info(f"upload started {lat:.2f} s after the last loud frame of the speech (Normal pause = 1.5 s)")
            check("(a) Live: the default pause is Normal: the upload starts 1.1-2.1 s after the speech ends", 1.1 <= lat <= 2.1, f"{lat:.2f}")
        else:
            check("(a) Live: an upload was started by the page", False)
        info("states: " + " > ".join(f"{(s['t'] - t_click) / 1000:.1f}s {s['text'] or '-'}" for s in T["states"]))
        mine = await pg.ev("document.querySelectorAll('.msg.me').length")
        check("(a) Live: the transcript is shown in the log", mine >= 1, str(mine))
        # (e) network
        urls = [r["url"] for r in pg.requests.values()]
        origin = inst.base
        foreign = [u for u in urls if u.startswith(("http://", "https://")) and not u.startswith(origin + "/")
                   and u != "https://telegram.org/js/telegram-web-app.js"]
        check("(e) no request leaves the test origin except telegram.org/js/telegram-web-app.js", not foreign, str(foreign))
        check("(e) telegram-web-app.js itself was requested", "https://telegram.org/js/telegram-web-app.js" in urls)
        need = ["vad.bundle.min.js", "vad.worklet.bundle.min.js", "silero_vad_v5.onnx", "ort-wasm-simd-threaded.mjs", "ort-wasm-simd-threaded.wasm"]
        resp = {os.path.basename(r["url"].split("?")[0]): r for r in pg.responses.values() if "/vendor/" in r["url"]}
        # The worklet module is fetched by the audio rendering thread and does not show up among the page's requests:
        # the server's access log is the evidence for it.
        served = {m.group(1): m.group(2) for l in inst.log for m in [re.search(r'"GET /vendor/([^ ]+) HTTP/1\.1" (\d+)', l)] if m}
        check("(e) all five VAD assets were loaded from /vendor/ with status 200",
              all((n in resp and resp[n]["status"] == 200) or (n == "vad.worklet.bundle.min.js" and served.get(n) == "200") for n in need),
              str({n: (resp.get(n, {}).get("status"), served.get(n)) for n in need}))
        check("(e) the server served nothing under /vendor/ except those five files", set(served) <= set(need), str(sorted(served)))
        check("(e) the wasm file came as application/wasm", resp.get("ort-wasm-simd-threaded.wasm", {}).get("mime") == "application/wasm",
              str(resp.get("ort-wasm-simd-threaded.wasm", {}).get("mime")))
        check("(e) no request failed", not pg.failed, str(pg.failed))
        basic = any("basic mode" in l for l in labels)
        check("(e) Silero VAD is in use (the basic mode tag never appeared)", not basic, str(labels))
        total = sum(os.path.getsize(os.path.join(VENDOR, n)) for n in need)
        info(f"vendor total {total} bytes, wasm {os.path.getsize(os.path.join(VENDOR, 'ort-wasm-simd-threaded.wasm'))} bytes")


def ups_of(T):
    return [f for f in T["fetches"] if f["phase"] == "start"]


def audio_of(T):
    """Media events of reply audio (/a/<uuid>.wav); the page also plays a silent data: clip once to unlock autoplay."""
    return [m for m in T["media"] if "/a/" in m["src"]]


REPLY_AUDIO = "__T.media.filter(function(m){return m.src.indexOf('/a/')>=0})"


async def t_presets(inst, fx):
    """The pause presets: Short 0.8 s and Long 2.5 s change when the phrase is sent (Normal is checked in `live`)."""
    for k, lo, hi, nominal in (("short", 0.6, 1.4, 0.8), ("long", 2.2, 3.1, 2.5)):
        async with Session(inst, fx["live"], lang="en", loop=False) as pg:
            await pg.click(f"[data-sil={k}]")
            pressed = await pg.ev(f"document.querySelector('[data-sil={k}]').getAttribute('aria-pressed')")
            await pg.click("#livebtn")
            ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='start'})", 45)
            T = parse(await pg.T())
            ups = ups_of(T)
            if not ok or not ups:
                check(f"presets: {k} sends the phrase", False, "no upload")
                continue
            lat = (ups[0]["t"] - (T["gum"][0]["t"] + 1000 + fx["speech_last"] * 1000)) / 1000
            info(f"{k}: upload {lat:.2f} s after the last loud frame (nominal pause {nominal} s)")
            check(f"presets: {k} is selectable and sends the phrase {lo}-{hi} s after the speech ends", pressed == "true" and lo <= lat <= hi, f"{pressed} {lat:.2f}")


async def t_half_duplex(inst, fx):
    """(b) Half-duplex: nothing is sent while a reply is spoken; listening resumes afterwards. Also: a reply waits
    for the end of the user's phrase, a tap on the indicator interrupts the audio, and with "Speak replies" off
    the page never pauses."""
    loop = asyncio.get_event_loop()
    P = fx["live_period"] * 1000

    def starts(T):
        return [f["t"] for f in ups_of(T)]

    async with Session(inst, fx["live"], lang="en", loop=True) as pg:
        await pg.click("#livebtn")
        ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='start'})", 45)
        check("(b) setup: the first phrase of the looping microphone is sent", bool(ok))
        if not ok:
            return
        # --- a short reply that arrives while the user is speaking waits for the end of the phrase
        ok = await pg.wait("document.getElementById('orb').dataset.state==='hearing'", 30)
        check("(b) setup: the next repetition of the phrase is heard", bool(ok))
        st = await loop.run_in_executor(None, inst.reply, "Okay, one moment.")
        t_arrived = time.time() * 1000      # the reply event is on the page's long poll from here on
        check("(b) setup: short reply synthesized", st == 200, str(st))
        ok = await pg.wait(REPLY_AUDIO + ".some(function(m){return m.type==='ended'})", 40)
        T = parse(await pg.T())
        pl = [m["t"] for m in audio_of(T) if m["type"] == "playing"]
        ups = starts(T)
        spk = [x["t"] for x in T["states"] if "Speaking" in x["text"]]
        if len(ups) >= 2 and pl and spk:
            check("(b) setup: the reply arrived while the phrase was still being spoken", t_arrived < ups[1] - 200, f"{ups[1] - t_arrived:.0f} ms before the phrase was sent")
            check("(b) a reply that arrives while the user speaks is not played over the user: it starts after the phrase was sent",
                  spk[0] >= ups[1] - 50 and pl[0] >= ups[1] - 50, f"speaking +{spk[0] - ups[1]} ms, playing +{pl[0] - ups[1]} ms vs the upload")
        else:
            check("(b) the short reply was played", False, f"ended={ok} ups={len(ups)} playing={pl} speaking={spk}")
        # --- a long reply: nothing is sent while it plays
        await asyncio.sleep(0.5)
        t_reply = time.time()
        st = await loop.run_in_executor(None, inst.reply, LONG_REPLY)
        check("(b) long reply synthesized (real TTS)", st == 200, str(st))
        info(f"TTS took {time.time() - t_reply:.1f} s")
        k = len([m for m in audio_of(parse(await pg.T())) if m["type"] == "ended"])
        ok = await pg.wait(REPLY_AUDIO + ".filter(function(m){return m.type==='ended'}).length>%d" % k, 90)
        T = parse(await pg.T())
        media = audio_of(T)
        play_t = [m["t"] for m in media if m["type"] == "playing"][-1]
        end_t = [m["t"] for m in media if m["type"] == "ended"][-1]
        info(f"long reply played for {(end_t - play_t) / 1000:.1f} s")
        ups = starts(T)
        inside = [u for u in ups if play_t <= u <= end_t + 250]
        check("(b) no utterance upload starts while the reply audio is playing", bool(ok) and not inside, f"{[(u - play_t) / 1000 for u in inside]}")
        wall = [r["wall"] * 1000 for r in pg.requests.values() if r["method"] == "POST" and r["url"].endswith("/api/utterance") and r["wall"]]
        check("(b) the same holds in the browser's own request log (CDP Network)", not [w for w in wall if play_t <= w <= end_t + 250])
        before = [u for u in ups if u < play_t]
        due = [before[-1] + j * P for j in range(1, 8)] if before else []
        due_in = [x for x in due if play_t + 500 < x < end_t - 500]
        check("(b) the test is meaningful: a phrase of the looping microphone would have been sent during playback", bool(due_in),
              f"play {(end_t - play_t) / 1000:.1f} s, period {P / 1000:.1f} s")
        # The status is set a moment before the audio element reports "playing", so look at the state in force when
        # playback started and at every change until it ended: there must be none.
        in_force = [x for x in T["states"] if x["t"] <= play_t + 50][-1]
        changes = [x for x in T["states"] if play_t + 50 < x["t"] < end_t - 50]
        check("(b) while the reply plays the status says Speaking (tap to interrupt) and never changes (no Hearing you)",
              "tap to interrupt" in in_force["text"] and not changes, f"{in_force} {changes}")
        ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='start' && f.t>%d})" % (end_t + 300), 45)
        check("(b) uploads resume after the reply has been played", bool(ok))
        T = parse(await pg.T())
        hear = [x["t"] for x in T["states"] if "Hearing" in x["text"] and x["t"] > end_t]
        if hear and hear[0] - end_t < 3000:
            check("(b) listening resumes no earlier than about 300 ms after the audio ends", hear[0] - end_t >= 550, f"{hear[0] - end_t} ms")
        else:
            info("(resume delay not observable in this run: the microphone was silent right after the reply)")

        # --- barge-in by tap
        await pg.wait("document.getElementById('orb').dataset.state!=='speaking'", 20)
        medium = "Here is a medium length answer that takes several seconds to say aloud, so that there is time to interrupt it with a tap."
        n_play = len([m for m in audio_of(parse(await pg.T())) if m["type"] == "playing"])
        st = await loop.run_in_executor(None, inst.reply, medium)
        ok = await pg.wait(REPLY_AUDIO + ".filter(function(m){return m.type==='playing'}).length>%d" % n_play, 60)
        check("(b) barge-in setup: the reply starts playing", bool(ok))
        if ok:
            await asyncio.sleep(1.5)
            t_tap = time.time() * 1000
            await pg.click("#orb")
            await asyncio.sleep(0.15)
            paused = await pg.ev("document.getElementById('player').paused")
            lab = await pg.ev("document.getElementById('state').textContent")
            check("(b) a tap on the indicator during playback stops the audio at once", paused is True, str(paused))
            check("(b) ...and the status leaves Speaking", "Speaking" not in lab, lab)
            T = parse(await pg.T())
            check("(b) ...without a normal end of the audio (it was interrupted)", not [m for m in audio_of(T) if m["type"] == "ended" and m["t"] > t_tap])
            ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='start' && f.t>%d})" % (t_tap + 400), 40)
            check("(b) after the tap listening is back: the next phrase is sent", bool(ok))

        # --- "Speak replies" off: no audio, no pause
        await pg.wait("document.getElementById('orb').dataset.state!=='speaking'", 10)
        await pg.click("#speak")
        off = await pg.ev("JSON.stringify([document.getElementById('speak').checked, localStorage.getItem('speak')])")
        check("(b) Speak replies can be switched off and the choice is saved", off == '[false,"0"]', str(off))
        n_media = len(audio_of(parse(await pg.T())))
        n_msgs = await pg.ev("document.querySelectorAll('.msg.cl').length")
        t_off = time.time() * 1000
        st = await loop.run_in_executor(None, inst.reply, "This reply must stay silent.")
        await asyncio.sleep(1.0)
        T = parse(await pg.T())
        check("(b) with Speak replies off the reply is shown but never played",
              await pg.ev("document.querySelectorAll('.msg.cl').length") == n_msgs + 1 and len(audio_of(T)) == n_media)
        check("(b) ...and the page never shows Speaking",
              not [x for x in T["states"] if x["t"] >= t_off and "Speaking" in x["text"]])
        ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='start' && f.t>%d})" % (t_off + 1000), 20)
        check("(b) ...and listening continues: the next phrase is sent", bool(ok))


async def t_ptt(inst, fx):
    """(c) Push-to-talk still works: real mouse clicks start and stop a 3 s recording."""
    n0 = len(inst.inbox())
    async with Session(inst, fx["ptt"], lang="en", loop=True) as pg:
        await pg.click("#mode-ptt")
        mode = await pg.ev("document.getElementById('app').dataset.mode")
        check("(c) the mode switch selects Push-to-talk", mode == "ptt", str(mode))
        await pg.click("#rec")
        on = await pg.wait("document.getElementById('rec').classList.contains('on')", 10)
        check("(c) a click on Speak starts recording", bool(on))
        await asyncio.sleep(3)
        await pg.click("#rec")
        got = await wait_utterance(inst, pg, n0, 45)
        check("(c) the second click stops it and an utterance reaches the test instance", bool(got), "nothing arrived")
        if got:
            info("recognized: " + got[0]["text"])
        T = parse(await pg.T())
        ups = ups_of(T)
        check("(c) the upload is about 3 s of 16 kHz audio", len(ups) == 1 and 2.5 * 32000 <= ups[0]["bytes"] <= 3.8 * 32000, str(ups))
        await asyncio.sleep(0.5)
        check("(c) the transcript is shown", await pg.ev("document.querySelectorAll('.msg.me').length") >= 1)
        check("(c) push-to-talk does not load the voice detection assets", not [r for r in pg.requests.values() if "/vendor/" in r["url"]])
        check("(c) the Live indicator stayed idle", await pg.ev("document.getElementById('orb').dataset.state") == "idle")


async def t_fallback(inst, fx):
    """If the Silero detector cannot be loaded (script, model, or a silent failure) Live falls back to the energy detector."""
    n0 = len(inst.inbox())
    async with Session(inst, fx["live"], lang="en", loop=False, block=["*/vendor/vad.bundle.min.js"]) as pg:
        await pg.click("#livebtn")
        ok = await pg.wait("document.getElementById('state').textContent.indexOf('basic mode')>=0", 30)
        check("(f) the detection script cannot be loaded: Live starts in basic mode and the status says so", bool(ok))
        note = await pg.ev("Array.prototype.map.call(document.querySelectorAll('.st'),function(e){return e.textContent}).join('|')")
        check("(f) ...with a note in the log", "basic voice detection" in note, note)
        got = await wait_utterance(inst, pg, n0, 45)
        check("(f) the energy detector captures the speech and it is uploaded", bool(got), "no utterance")
        T = parse(await pg.T())
        ups = ups_of(T)
        check("(f) ...as one phrase of about the length of the speech and with a beep",
              len(ups) >= 1 and 0.6 * fx["speech_len"] * 32000 <= ups[0]["bytes"] <= (fx["speech_len"] + 1.5) * 32000 and len(T["osc"]) >= 1, str(ups[:1]))
        check("(f) ...and the status went through Hearing you", any("Hearing" in l for l in state_labels(T)), str(state_labels(T)))
    async with Session(inst, fx["live"], lang="en", loop=False, block=["*/vendor/silero_vad_v5.onnx"]) as pg:
        await pg.click("#livebtn")
        ok = await pg.wait("document.getElementById('state').textContent.indexOf('basic mode')>=0", 30)
        check("(f) the model file cannot be loaded: basic mode as well", bool(ok))
        await pg.click("#livebtn")
    # The detector loads but cannot start (its worklet module is rejected): the fallback is immediate, no watchdog needed.
    nostart = ("(function(){var o=AudioWorklet.prototype.addModule;AudioWorklet.prototype.addModule=function(u){"
               "if(String(u).indexOf('vad.worklet')>=0)return Promise.reject(new Error('blocked'));return o.apply(this,arguments)}})();")
    async with Session(inst, fx["live"], lang="en", loop=False, script=nostart) as pg:
        t0 = time.time()
        await pg.click("#livebtn")
        ok = await pg.wait("document.getElementById('state').textContent.indexOf('basic mode')>=0", 30)
        took = time.time() - t0
        check("(f) the detector loads but cannot start (worklet rejected): basic mode at once, without waiting for the watchdog", bool(ok) and took < 4.5, f"{took:.1f} s")
        await pg.click("#livebtn")
    # The detector loads but never delivers a frame (its worklet node is muted): the watchdog must notice.
    mute = ("(function(){var W=window.AudioWorkletNode;window.AudioWorkletNode=function(c,n,o){var x=new W(c,n,o);"
            "if(n==='vad-helper-worklet')Object.defineProperty(x.port,'onmessage',{set:function(){},get:function(){return null}});return x};"
            "window.AudioWorkletNode.prototype=W.prototype})();")
    async with Session(inst, fx["live"], lang="en", loop=False, script=mute) as pg:
        await pg.click("#livebtn")
        ok = await pg.wait("document.getElementById('state').textContent.indexOf('basic mode')>=0", 30)
        check("(f) the detector loads but delivers no audio: the watchdog switches to basic mode", bool(ok))
        await pg.click("#livebtn")


async def t_lifecycle(inst, fx):
    """While Live runs: wake lock, Telegram swipe/close guards, pause when hidden; everything is undone on Stop."""
    async with Session(inst, fx["live"], lang="en", loop=True) as pg:
        await pg.click("#livebtn")
        await pg.wait("document.getElementById('orb').dataset.state==='listening'||document.getElementById('orb').dataset.state==='hearing'", 40)
        T = parse(await pg.T())
        cons = [c["s"] for c in T["console"]]
        check("Live requests a screen wake lock", [w["type"] for w in T["wake"]] == ["screen"], str(T["wake"]))
        check("Live disables vertical swipes in Telegram", any("web_app_setup_swipe_behavior" in c and '"allow_vertical_swipe":false' in c for c in cons), str(cons[-6:]))
        check("Live turns on the closing confirmation", any("web_app_setup_closing_behavior" in c and '"need_confirmation":true' in c for c in cons), str(cons[-6:]))
        # hide the page in the silent part of the loop, keep it hidden through one whole repetition of the phrase
        ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='start'})", 45)
        T = parse(await pg.T())
        n_up = len(ups_of(T))
        t_hide = int(time.time() * 1000)
        await pg.ev("(function(){Object.defineProperty(document,'hidden',{configurable:true,get:function(){return true}});"
                    "Object.defineProperty(document,'visibilityState',{configurable:true,get:function(){return 'hidden'}});"
                    "__T.wake.forEach(function(w){w.sentinel.fire()});document.dispatchEvent(new Event('visibilitychange'))})()")
        await asyncio.sleep(0.4)
        lab = await pg.ev("document.getElementById('state').textContent")
        check("a hidden page shows Paused", lab == "Paused", lab)
        await asyncio.sleep(fx["live_period"] + 3)   # a whole phrase passes the microphone while hidden
        T = parse(await pg.T())
        check("nothing is sent while the page is hidden (listening is paused)", len(ups_of(T)) == n_up, f"{len(ups_of(T))} vs {n_up}")
        await pg.ev("(function(){Object.defineProperty(document,'hidden',{configurable:true,get:function(){return false}});"
                    "Object.defineProperty(document,'visibilityState',{configurable:true,get:function(){return 'visible'}});"
                    "document.dispatchEvent(new Event('visibilitychange'))})()")
        await asyncio.sleep(0.4)
        T = parse(await pg.T())
        check("the wake lock is requested again when the page is visible again", len(T["wake"]) == 2, str(T["wake"]))
        lab = await pg.ev("document.getElementById('state').textContent")
        check("a visible page is no longer paused (it listens; Thinking… while a reply is awaited)", lab in ("Listening…", "Hearing you…", "Sending…", "Thinking…"), lab)
        t_show = int(time.time() * 1000)
        ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='start' && f.t>%d})" % t_show, 30)
        check("after the page is visible again the next phrase is sent", bool(ok))
        # Stop undoes everything
        await pg.click("#livebtn")
        await asyncio.sleep(1.0)
        T = parse(await pg.T())
        cons = [c["s"] for c in T["console"]]
        sw = [c for c in cons if "web_app_setup_swipe_behavior" in c]
        cl = [c for c in cons if "web_app_setup_closing_behavior" in c]
        check("Stop re-enables vertical swipes (last message: allow_vertical_swipe true)", sw and '"allow_vertical_swipe":true' in sw[-1], str(sw))
        check("Stop turns the closing confirmation off (last message: need_confirmation false)", cl and '"need_confirmation":false' in cl[-1], str(cl))
        check("Stop releases the wake lock", T["wake"][-1]["released"] is True, str(T["wake"]))
        check("Stop releases the microphone", T["tracks"] and all(r == "ended" for r in T["tracks"][0]), str(T["tracks"]))
        check("Stop returns the page to its idle state", await pg.ev("document.getElementById('orb').dataset.state") == "idle"
              and await pg.ev("document.getElementById('livebtn').textContent") == "Start conversation")
        n_up = len(ups_of(T))
        await asyncio.sleep(fx["live_period"])
        check("nothing is sent after Stop", len(ups_of(parse(await pg.T()))) == n_up)


async def t_cap(inst, fx):
    """A phrase longer than 60 s is cut and sent at 60 s; the rest follows as the next phrase."""
    async with Session(inst, fx["long"], lang="en", loop=False) as pg:
        await pg.click("#livebtn")
        ok = await pg.wait("__T.fetches.filter(function(f){return f.phase==='start'}).length>=2", 100)
        T = parse(await pg.T())
        ups = [f for f in T["fetches"] if f["phase"] == "start"]
        check("(h) continuous speech of 66 s is sent in two parts", bool(ok) and len(ups) >= 2, str(len(ups)))
        if len(ups) >= 2:
            s1, s2 = ups[0]["bytes"] / 32000, ups[1]["bytes"] / 32000
            info(f"first part {s1:.1f} s, second part {s2:.1f} s, first upload {(ups[0]['t'] - T['gum'][0]['t']) / 1000:.1f} s after the microphone opened")
            check("(h) the first part is cut at 60 s", 59.0 <= s1 <= 60.6, f"{s1:.2f}")
            check("(h) nothing is lost at the cut: the parts add up to the speech", s1 + s2 >= 62.0, f"{s1 + s2:.1f}")
            check("(h) the first part is sent when the limit is reached, not at the end of the speech",
                  (ups[1]["t"] - ups[0]["t"]) / 1000 >= 4.0, f"{(ups[1]['t'] - ups[0]['t']) / 1000:.1f} s between the uploads")


# ---------------------------------------------------------------------------------------------- hardening: presence, away, CSP, URLs
# The lifecycle test shows how a hidden page is emulated: the visibility getters are overridden and the event is fired by hand
# (headless Chrome has no real visibility). The OS also releases the wake lock then, so the stand-in sentinels fire "release".
HIDE = ("Object.defineProperty(document,'hidden',{configurable:true,get:function(){return true}});"
        "Object.defineProperty(document,'visibilityState',{configurable:true,get:function(){return 'hidden'}});"
        "__T.wake.forEach(function(w){w.sentinel.fire()});document.dispatchEvent(new Event('visibilitychange'));")
SHOW = ("Object.defineProperty(document,'hidden',{configurable:true,get:function(){return false}});"
        "Object.defineProperty(document,'visibilityState',{configurable:true,get:function(){return 'visible'}});"
        "document.dispatchEvent(new Event('visibilitychange'));")
# What the Telegram client sends when the Mini App goes to the background or comes back (Bot API 8.0 "deactivated" / "activated")
TG_AWAY = "Telegram.WebView.receiveEvent('visibility_changed',{is_visible:false});"
TG_BACK = "Telegram.WebView.receiveEvent('visibility_changed',{is_visible:true});"
TOUCH = "document.getElementById('log').dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,pointerType:'touch'}));"
LIVE_ON = "document.getElementById('livebtn').className==='on'"
LIVE_OFF = "document.getElementById('livebtn').className===''"
LISTENING = "(function(){var s=document.getElementById('orb').dataset.state;return s==='listening'||s==='hearing'})()"
STATE_TEXT = "document.getElementById('state').textContent"
ST_LINES = "JSON.stringify(Array.prototype.map.call(document.querySelectorAll('.st'),function(e){return e.textContent}))"
EN_IDLE_STOP = "Conversation stopped: no taps for a while"
EN_HIDDEN_STOP = "Conversation stopped: the page was in the background too long"


def api(inst, path, method="GET", body=None):
    """A request of the Mini App (with its signed initData) to a test instance: (status, body)."""
    return req(inst.base, path, method, body, {"X-Init-Data": init_data(), "Content-Type": "application/json"}, timeout=10)


def page_policy(inst):
    """The Content-Security-Policy header of the page, "" when the server sends none."""
    try:
        with urllib.request.urlopen(inst.base + "/", timeout=5) as r:
            return r.headers.get("Content-Security-Policy") or ""
    except Exception:
        return ""


def fake_instance(**settings):
    """A throwaway instance without speech keys (recognition and synthesis are the FAKE ones: free), with settings such as
    VOICE_LIVE_IDLE_SEC=20. For tests of the page's own behaviour, where what is recognized does not matter."""
    return Instance(extra={k: str(v) for k, v in settings.items()}, fake=True)


async def tracks_ended(pg, n=0, timeout=4):
    """Every track of the n-th microphone stream is ended (Live lets go of the microphone a moment after it stops)."""
    return await pg.wait("(function(){var s=__T.streams[%d];return !!s&&s.getTracks().every(function(t){return t.readyState==='ended'})})()" % n, timeout)


def silent_wav(path, seconds, rate=48000):
    """A WAV of silence: a quiet microphone (nothing is ever heard) or a reply clip of a known length."""
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"\0\0" * int(seconds * rate))
    return path


def reply_clip(srv, seconds):
    """A silent reply clip in the instance's audio store, named the way the server names its own. Returns its /a/ URL."""
    name = str(uuid.uuid4()) + ".wav"
    silent_wav(os.path.join(srv.state, "audio", name), seconds, 24000)
    return "/a/" + name


def reply_event(n, url):
    return {"id": n, "type": "reply", "text": f"Made-up reply {n}", "audio_url": url}


async def t_ptt_double(inst, fx):
    """A second tap on Speak while the first still waits for the microphone must not open a second microphone stream."""
    srv = fake_instance()
    delay = ("(function(){var g=navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);"        # the permission prompt takes 700 ms
             "navigator.mediaDevices.getUserMedia=function(c){return new Promise(function(r){setTimeout(r,700)}).then(function(){return g(c)})}})();")
    try:
        async with Session(srv, fx["ptt"], lang="en", loop=True, script=delay) as pg:
            await pg.click("#mode-ptt")
            await pg.click("#rec")
            await pg.click("#rec")       # the first request is still pending: a double tap
            on = await pg.wait("document.getElementById('rec').classList.contains('on')", 10)
            check("ptt double tap: recording starts", bool(on))
            await asyncio.sleep(1.0)     # time enough for a second microphone request to have been served too
            T = parse(await pg.T())
            check("ptt double tap: one microphone request, one stream", len(T["gum"]) == 1 and len(T["tracks"]) == 1, f"{len(T['gum'])} requests, {len(T['tracks'])} streams")
            check("ptt double tap: the second tap did not stop the recording", await pg.ev("document.getElementById('rec').classList.contains('on')") is True)
            await pg.click("#rec")
            await pg.wait("!document.getElementById('rec').classList.contains('on')", 5)
            check("ptt double tap: Stop releases the microphone (no stream left open)", bool(await tracks_ended(pg)), str(parse(await pg.T())["tracks"]))
            # and the next recording works as before
            await pg.click("#rec")
            on = await pg.wait("document.getElementById('rec').classList.contains('on')", 10)
            check("ptt double tap: a later recording starts normally", bool(on))
            await pg.click("#rec")
            await pg.wait("!document.getElementById('rec').classList.contains('on')", 5)
            T = parse(await pg.T())
            check("ptt double tap: ...and releases its stream too", len(T["tracks"]) == 2 and all(r == "ended" for tr in T["tracks"] for r in tr), str(T["tracks"]))
    finally:
        srv.stop()


CRAFT = r"""(function(){
  var of = window.fetch, held = [], srcs = [];
  window.__held = held; window.__srcs = srcs;
  window.__inject = function(evs){ var h = held.shift(); if (!h) return false; h(evs); return true; };
  // The page's event long-poll waits for the test: the first answer is a list of replies made up here
  window.fetch = function(u, o){
    var s = String((u && u.url) || u);
    if (s.indexOf('api/events?after=') >= 0 && s.indexOf('after=-1') < 0)
      return new Promise(function(res){ held.push(function(evs){ res(new Response(JSON.stringify({events: evs, last: 0}), {status: 200, headers: {'Content-Type': 'application/json'}})); }); });
    return of.apply(this, arguments);
  };
  // Every URL the page gives its audio element
  var d = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src');
  Object.defineProperty(HTMLMediaElement.prototype, 'src', {configurable: true, enumerable: d.enumerable,
    get: function(){ return d.get.call(this); }, set: function(v){ srcs.push(String(v)); d.set.call(this, v); }});
})();"""


async def t_audio_url(inst, fx):
    """Reply audio is played only from /a/<uuid>.wav|mp3 on the page's own origin; any other audio_url is ignored (console.warn)
    and the text of the reply is still shown. The events are made up in the browser: the instance only ever hands out valid URLs."""
    good = ["/a/3f2b8c1e-5d4a-4e7b-9c10-0a1b2c3d4e5f.wav", "/a/3f2b8c1e-5d4a-4e7b-9c10-0a1b2c3d4e60.mp3"]
    uid = "3f2b8c1e-5d4a-4e7b-9c10-0a1b2c3d4e5f"
    bad = ["https://csp-probe.invalid/a/%s.wav" % uid,        # right path, another origin
           "//csp-probe.invalid/a/%s.wav" % uid,              # protocol-relative
           "/a/%s.ogg" % uid, "/a/%s.wav?x=1" % uid, "/a/%s.wav\n" % uid, "/a/../%s.wav" % uid, "/b/%s.wav" % uid,
           "/a/%s.wav" % uid.upper(), "/a/%s.wav" % uid[:-1], "javascript:alert(1)", "data:audio/wav;base64,UklGRg==",
           {"url": "/a/%s.wav" % uid}, ["/a/%s.wav" % uid]]   # not strings
    events = [{"id": i + 1, "type": "reply", "text": f"made-up reply {i}", "audio_url": u} for i, u in enumerate(bad + good)]
    async with Session(inst, fx["live"], lang="en", loop=False, script=CRAFT) as pg:
        check("audio_url: setup: the page is waiting for events", bool(await pg.wait("__held.length>=1", 15)))
        await pg.ev("__inject(%s)" % json.dumps(events))
        ok = await pg.wait("document.querySelectorAll('.msg.cl').length>=%d" % len(events), 10)
        check("audio_url: every reply is shown as text, whatever its audio_url", bool(ok), str(await pg.ev("document.querySelectorAll('.msg.cl').length")))
        own = "JSON.stringify(__srcs.filter(function(s){return s.indexOf('data:')!==0}))"       # the page's silent unlock clip is a data: URL
        await pg.wait("JSON.parse(%s).length>=%d" % (own, len(good)), 10)
        await asyncio.sleep(0.5)
        srcs = parse(await pg.ev(own))
        check("audio_url: only the well-formed /a/<uuid> URLs reached the audio element", srcs == good, str(srcs))
        T = parse(await pg.T())
        warns = [c for c in T["console"] if c["k"] == "warn" and "reply audio ignored" in c["s"]]
        check("audio_url: each rejected URL is logged with console.warn", len(warns) == len(bad), f"{len(warns)} of {len(bad)}")


async def t_csp_report(inst, fx):
    """The page reports what the policy blocks: the directive and the origin of the blocked resource only, each pair once, at most
    10 per page load, errors ignored. The violations are staged with SecurityPolicyViolationEvent, so this runs with or without a
    server policy."""
    served = api(inst, "/api/csp-report", "POST", b'{"directive":"img-src","blocked":"data:"}')[0] != 404
    async with Session(inst, fx["live"], lang="en", loop=False, csp_probe=True) as pg:
        async def violate(directive, blocked):
            await pg.ev("document.dispatchEvent(new SecurityPolicyViolationEvent('securitypolicyviolation',{bubbles:true,composed:true,"
                        "effectiveDirective:%s,violatedDirective:%s,blockedURI:%s,disposition:'enforce'}))" % (json.dumps(directive), json.dumps(directive), json.dumps(blocked)))

        async def reports():
            await asyncio.sleep(0.4)
            return [json.loads(r["body"]) for r in parse(await pg.T())["reports"]]
        await violate("connect-src", "https://secret.example:8443/private/path?token=SECRET#frag")
        got = await reports()
        check("csp report: the directive and the origin of the blocked resource, no path, no query, no fragment",
              got == [{"directive": "connect-src", "blocked": "https://secret.example:8443"}], str(got))
        await violate("connect-src", "https://secret.example:8443/another/path")
        check("csp report: the same directive and origin is reported once", len(await reports()) == 1)
        for d, b in (("script-src", "eval"), ("img-src", "data:image/png;base64,AAAA"), ("script-src-elem", "blob:https://other.example/0f3c"),
                     ("style-src-attr", "inline")):
            await violate(d, b)
        got = await reports()
        check("csp report: eval and inline as they are, data: as its scheme, a blob: URL as the origin inside it",
              [(g["directive"], g["blocked"]) for g in got[1:]] == [("script-src", "eval"), ("img-src", "data:"), ("script-src-elem", "https://other.example"),
                                                                       ("style-src-attr", "inline")], str(got))
        for i in range(14):
            await violate("img-src", f"https://h{i}.example/x.png")
        got = await reports()
        check("csp report: at most 10 reports per page load", len(got) == 10, str(len(got)))
        rs = parse(await pg.T())["reports"]
        check("csp report: each is a POST with the page's initData and a body far below the 4 KB the server takes",
              all(r["method"] == "POST" and r["init"] and len(r["body"]) < 300 for r in rs), str(rs[:2]))
        if served:
            check("csp report: the server answers each with 204", all(r["status"] == 204 for r in rs), str([r["status"] for r in rs]))
        else:
            info("(the server has no POST /api/csp-report yet: its answer was not checked; the page ignores it)")
        check("csp report: the page still works afterwards", await pg.ev(STATE_TEXT) == "" and await pg.ev(LIVE_OFF) is True)


async def t_csp(inst, fx):
    """The server's Content-Security-Policy is enforced: each kind of foreign resource is blocked and recorded as a violation, the
    page's own way of styling (element.style) is not. Needs the server's header; without it the test says SKIP."""
    policy = page_policy(inst)
    if not policy:
        skip("csp", "the page is served without a Content-Security-Policy header (server work pending)")
        return
    info("policy: " + policy[:100] + "...")
    probes = [   # (what, directive family, expression, eval needs the strict flag: DevTools evaluation may use eval() otherwise)
        ("a fetch to a foreign origin", "connect-src", "fetch('https://csp-probe.invalid/x').catch(function(){})", False),
        ("a foreign image", "img-src", "(function(){var i=new Image();i.src='https://csp-probe.invalid/x.png'})()", False),
        ("a foreign script element", "script-src", "(function(){var s=document.createElement('script');s.src='https://csp-probe.invalid/x.js';document.head.appendChild(s)})()", False),
        ("eval()", "script-src", "(function(){try{eval('1')}catch(e){}})()", True),
        ("foreign media", "media-src", "(function(){var a=new Audio();a.src='https://csp-probe.invalid/x.wav';a.load()})()", False),
        ("an inline style attribute", "style-src", "document.body.appendChild(document.createElement('i')).setAttribute('style','color:red')", False),
        ("a Worker", "worker-src", "(function(){try{new Worker('/vendor/vad.worklet.bundle.min.js')}catch(e){}})()", False),
    ]
    async with Session(inst, fx["live"], lang="en", loop=False, csp_probe=True) as pg:
        v0 = parse(await pg.ev("JSON.stringify(__T.csp)"))
        check("csp: the page itself (inline script and style, telegram-web-app.js) loaded without a violation", not v0, str(v0))
        for what, family, js, strict in probes:
            await pg.ev("__T.csp.length=0")
            await pg.ev(js, strict_csp=strict)
            ok = await pg.wait("__T.csp.length>0", 5)
            v = parse(await pg.ev("JSON.stringify(__T.csp)"))
            check(f"csp: {what} is blocked and recorded ({family})", bool(ok) and v[0]["dir"].startswith(family) and v[0]["disp"] == "enforce", str(v))
        await pg.ev("__T.csp.length=0")
        await pg.ev("(function(){var d=document.createElement('div');d.style.color='red';d.style.setProperty('--x','1');d.style.animation='none';document.body.appendChild(d);d.remove()})()")
        await asyncio.sleep(0.3)
        check("csp: styling through element.style (what the page does) is not a violation", not parse(await pg.ev("JSON.stringify(__T.csp)")))
        await asyncio.sleep(0.5)
        rs = parse(await pg.T())["reports"]
        got = {(json.loads(r["body"])["directive"], json.loads(r["body"])["blocked"]) for r in rs}
        check("csp: the page reported each probe to the server (directive and origin only)",
              ("connect-src", "https://csp-probe.invalid") in got and ("img-src", "https://csp-probe.invalid") in got
              and ("script-src", "eval") in got and ("media-src", "https://csp-probe.invalid") in got and ("style-src-attr", "inline") in got
              and not [r for r in rs if re.search(r"/x(\.|\")", r["body"])], str(sorted(got)))
        n = len(rs)
        await pg.ev("fetch('https://csp-probe.invalid/x').catch(function(){})")
        await asyncio.sleep(0.6)
        check("csp: a repeated violation is not reported again", len(parse(await pg.T())["reports"]) == n)
        if api(inst, "/api/csp-report", "POST", b'{"directive":"x","blocked":"y"}')[0] != 404:
            check("csp: the server answers the reports with 204", all(r["status"] == 204 for r in rs), str([r["status"] for r in rs]))


async def t_hidden_flush(inst, fx):
    """A phrase cut off because the page went to the background is unfinished: it is dropped, not sent. Afterwards listening
    works as before (the next phrase is sent)."""
    srv = fake_instance()
    try:
        async with Session(srv, fx["live"], lang="en", loop=True) as pg:
            await pg.click("#livebtn")
            # wait (in the page, so that nothing slips in between) until the user has been heard for over a second, then go away
            r = await pg.ev("""new Promise(function(done){
              var since = 0, t0 = Date.now();
              (function poll(){
                var heard = document.getElementById('orb').dataset.state === 'hearing';
                if (!heard) since = 0; else if (!since) since = Date.now();
                if (since && Date.now() - since >= 1200) {
                  var r = {ok: true, ups: __T.fetches.filter(function(f){return f.phase==='start'}).length, osc: __T.osc.length};
                  %s
                  return done(r);
                }
                if (Date.now() - t0 > 60000) return done({ok: false});
                setTimeout(poll, 30);
              })();
            })""" % HIDE, await_promise=True, timeout=70)
            check("hidden flush: setup: speech had been in progress for over a second when the page went to the background", r.get("ok"), str(r))
            if not r.get("ok"):
                return
            await asyncio.sleep(3.5)
            T = parse(await pg.T())
            check("hidden flush: the page shows Paused", await pg.ev(STATE_TEXT) == "Paused")
            check("hidden flush: the phrase cut off by going away is not uploaded", len(ups_of(T)) == r["ups"], f"{len(ups_of(T))} uploads, {r['ups']} before")
            check("hidden flush: ...and no beep marks it as captured", len(T["osc"]) == r["osc"], f"{len(T['osc'])} vs {r['osc']}")
            check("hidden flush: ...the page says it dropped it", any("phrase dropped" in c["s"] for c in T["console"]), str([c["s"] for c in T["console"]][-3:]))
            await pg.ev(SHOW)
            ok = await pg.wait("__T.fetches.filter(function(f){return f.phase==='start'}).length>%d" % r["ups"], fx["live_period"] + 12)
            check("hidden flush: back in the foreground the next phrase is sent (the drop does not stick)", bool(ok))
    finally:
        srv.stop()


async def t_presence(inst, fx):
    """Live stops by itself when nobody touches the page (VOICE_LIVE_IDLE_SEC), however much is said: speech is no presence. A touch
    or a click starts the time again, a countdown shows during the last minute. Needs GET /api/config; SKIP without it."""
    srv = fake_instance(VOICE_LIVE_IDLE_SEC=20)
    srv2 = None
    try:
        st, body = api(srv, "/api/config")
        if st == 404:
            skip("presence", "the server has no GET /api/config yet (VOICE_LIVE_IDLE_SEC is not served)")
            return
        c = json.loads(body) if st == 200 else {}
        check("presence: api/config reports the idle time of the instance (and a hidden-stop time)",
              c.get("live_idle_ms") == 20000 and isinstance(c.get("hidden_stop_ms"), int), f"{st} {body[:200]!r}")
        async with Session(srv, fx["live"], lang="en", loop=True) as pg:
            T = parse(await pg.T())
            check("presence: the page asked api/config once, with its initData", len(T["cfg"]) == 1 and T["cfg"][0]["init"] and T["cfg"][0]["status"] == 200, str(T["cfg"]))
            t0 = time.time()
            await pg.click("#livebtn")
            check("presence: Live starts", bool(await pg.wait(LISTENING, 40)))
            ok = await pg.wait(VIS + ";vis('idle')", 6)
            txt = await pg.ev("document.getElementById('idle').textContent")
            m = re.fullmatch(r"Live stops in (\d+) s: tap anywhere to keep talking", txt or "")
            check("presence: with under a minute left a countdown shows how long Live has", bool(ok) and bool(m) and 1 <= int(m.group(1)) <= 20, str(txt))
            # Without touches Live would stop at 20 s. A real click at 6 s moves that to 26 s; a dispatched pointer event at 23 s to 43 s.
            await asyncio.sleep(max(0, t0 + 6 - time.time()))
            await pg.click("#log")
            t_click = time.time()
            n = re.search(r"\d+", await pg.ev("document.getElementById('idle').textContent") or "")
            check("presence: a click on the page starts the time again (the countdown is back at 20)", bool(n) and int(n.group()) >= 19, str(n))
            await asyncio.sleep(max(0, t0 + 21.5 - time.time()))
            check("presence: 21.5 s in, past the original 20 s, Live runs on (the click counted)", await pg.ev(LIVE_ON) is True)
            await asyncio.sleep(max(0, t0 + 23 - time.time()))
            await pg.ev(TOUCH)
            t_touch = time.time()
            await asyncio.sleep(max(0, t_click + 22 - time.time()))
            check("presence: 22 s after the click, past its 20 s, Live runs on (the dispatched pointer event counted)", await pg.ev(LIVE_ON) is True)
            ok = await pg.wait(LIVE_OFF, 25)
            after = time.time() - t_touch
            check("presence: Live stops about 20 s after the last touch", bool(ok) and 19.5 <= after <= 23.5, f"{after:.1f} s")
            T = parse(await pg.T())
            check("presence: speech did not keep it alive: the looping microphone was heard and sent meanwhile",
                  any("Hearing" in l for l in state_labels(T)) and len(ups_of(T)) >= 1, f"{len(ups_of(T))} uploads")
            lines = parse(await pg.ev(ST_LINES))
            check("presence: the log says why Live stopped", EN_IDLE_STOP in lines, str(lines))
            check("presence: the countdown is gone", await pg.ev(VIS + ";vis('idle')") is False)
            check("presence: the microphone is released and the page is idle", bool(await tracks_ended(pg))
                  and await pg.ev("document.getElementById('orb').dataset.state") == "idle" and await pg.ev("document.getElementById('livebtn').textContent") == "Start conversation")
            cons = [c["s"] for c in T["console"]]
            off = max((i for i, s in enumerate(cons) if "web_app_setup_closing_behavior" in s and '"need_confirmation":false' in s), default=-1)
            check("presence: the stop gave a light haptic",
                  off >= 0 and any("web_app_trigger_haptic_feedback" in s and '"impact_style":"light"' in s for s in cons[off + 1:]), str(cons[-4:]))
        # the countdown shows only in the last minute: with 70 s configured it is not there at first, and a touch hides it again
        srv2 = fake_instance(VOICE_LIVE_IDLE_SEC=70)
        async with Session(srv2, fx["live"], lang="en", loop=True) as pg:
            t0 = time.time()
            await pg.click("#livebtn")
            await pg.wait(LISTENING, 40)
            await asyncio.sleep(3)
            check("presence: with more than a minute left there is no countdown", await pg.ev(VIS + ";vis('idle')") is False)
            ok = await pg.wait(VIS + ";vis('idle')", 15)
            seen = time.time() - t0
            n = re.search(r"\d+", await pg.ev("document.getElementById('idle').textContent") or "")
            check("presence: the countdown appears when a minute is left", bool(ok) and 8.5 <= seen <= 13.5 and bool(n) and 55 <= int(n.group()) <= 60, f"{seen:.1f} s, {n}")
            await pg.ev(TOUCH)
            await asyncio.sleep(0.5)
            check("presence: a touch sends it away again (70 s are left)", await pg.ev(VIS + ";vis('idle')") is False)
            await pg.click("#livebtn")
    finally:
        for s in (srv, srv2):
            if s:
                s.stop()


async def t_hidden_stop(inst, fx):
    """Live stops when the page stays away (hidden, or deactivated by Telegram) for VOICE_LIVE_HIDDEN_SEC and lets go of the microphone;
    a shorter absence is forgiven. The two sources of "away" do not fight. Needs GET /api/config; SKIP without it."""
    srv = fake_instance(VOICE_LIVE_IDLE_SEC=0, VOICE_LIVE_HIDDEN_SEC=3)      # no idle limit: only the absence can stop Live here
    try:
        st, body = api(srv, "/api/config")
        if st == 404:
            skip("hidden_stop", "the server has no GET /api/config yet (VOICE_LIVE_HIDDEN_SEC is not served)")
            return
        c = json.loads(body) if st == 200 else {}
        check("hidden stop: api/config reports both limits (0 = no idle limit)", c.get("live_idle_ms") == 0 and c.get("hidden_stop_ms") == 3000, f"{st} {body[:200]!r}")
        # --- the document is hidden (the user left the app, the screen went off)
        async with Session(srv, fx["live"], lang="en", loop=True) as pg:
            await pg.click("#livebtn")
            await pg.wait(LISTENING, 40)
            await pg.ev(HIDE)
            await asyncio.sleep(1.2)
            check("hidden stop: a hidden page shows Paused", await pg.ev(STATE_TEXT) == "Paused")
            await pg.ev(SHOW)
            await asyncio.sleep(0.4)
            check("hidden stop: back after 1.2 s, Live listens again", await pg.ev(STATE_TEXT) != "Paused" and await pg.ev(LIVE_ON) is True)
            await asyncio.sleep(4.0)
            check("hidden stop: the short absence is forgiven (Live still runs 4 s later, more than the limit after it began)", await pg.ev(LIVE_ON) is True)
            n_up = len(ups_of(parse(await pg.T())))
            t_hide = time.time()
            await pg.ev(HIDE)
            ok = await pg.wait(LIVE_OFF, 12)
            took = time.time() - t_hide
            check("hidden stop: hidden for 3 s Live stops (3-6 s after it went away)", bool(ok) and 2.5 <= took <= 6.0, f"{took:.1f} s")
            T = parse(await pg.T())
            check("hidden stop: the microphone is released", bool(await tracks_ended(pg)), str(T["tracks"]))
            check("hidden stop: the log says why", EN_HIDDEN_STOP in parse(await pg.ev(ST_LINES)), str(parse(await pg.ev(ST_LINES))))
            check("hidden stop: nothing was sent while away", len(ups_of(T)) == n_up, f"{len(ups_of(T))} vs {n_up}")
            check("hidden stop: the page is idle again and the wake lock is released",
                  await pg.ev("document.getElementById('orb').dataset.state") == "idle" and T["wake"][-1]["released"] is True, str(T["wake"]))
            check("hidden stop: no countdown with the idle limit off", await pg.ev(VIS + ";vis('idle')") is False)
        # --- Telegram deactivates the Mini App (Bot API 8.0)
        async with Session(srv, fx["live"], lang="en", loop=True) as pg:
            check("hidden stop: setup: the page's Telegram client is 8.0 or newer", await pg.ev("Telegram.WebApp.isVersionAtLeast('8.0')") is True)
            await pg.click("#livebtn")
            await pg.wait(LISTENING, 40)
            T = parse(await pg.T())
            n_wake, n_res = len(T["wake"]), len(T["resume"])
            await pg.ev(TG_AWAY + "__T.wake.forEach(function(w){w.sentinel.fire()});")
            await asyncio.sleep(0.4)
            check("hidden stop: a deactivated Mini App shows Paused", await pg.ev(STATE_TEXT) == "Paused")
            await pg.ev(TG_BACK)
            await asyncio.sleep(0.5)
            T = parse(await pg.T())
            check("hidden stop: activated again, Live listens", await pg.ev(STATE_TEXT) != "Paused" and await pg.ev(LIVE_ON) is True)
            check("hidden stop: ...the audio context is resumed and the wake lock is requested again", len(T["resume"]) > n_res and len(T["wake"]) == n_wake + 1,
                  f"resume {n_res}->{len(T['resume'])}, wake {n_wake}->{len(T['wake'])}")
            # the two sources: hidden if either says so
            await pg.ev(HIDE + TG_AWAY + TG_BACK)
            await asyncio.sleep(0.5)
            n_res = len(parse(await pg.T())["resume"])
            check("hidden stop: activated while the document is still hidden: still Paused", await pg.ev(STATE_TEXT) == "Paused")
            await pg.ev(SHOW)
            await asyncio.sleep(0.5)
            check("hidden stop: the document visible and Telegram active: listening again", await pg.ev(STATE_TEXT) != "Paused" and len(parse(await pg.T())["resume"]) > n_res)
            await pg.ev(TG_AWAY + HIDE + SHOW)
            await asyncio.sleep(0.5)
            check("hidden stop: the document visible while Telegram says deactivated: still Paused", await pg.ev(STATE_TEXT) == "Paused")
            await pg.ev(TG_BACK)
            await asyncio.sleep(0.5)
            check("hidden stop: ...and Live runs on once both agree", await pg.ev(STATE_TEXT) != "Paused" and await pg.ev(LIVE_ON) is True)
            # Telegram says "deactivated" and never "activated": a tap proves the app is active, the flag must not go stale
            await pg.ev(TG_AWAY)
            await asyncio.sleep(1.0)
            check("hidden stop: deactivated, and no activated follows: Paused", await pg.ev(STATE_TEXT) == "Paused")
            await pg.click("#log")
            await asyncio.sleep(0.5)
            check("hidden stop: a tap proves the app is active: Live listens again", await pg.ev(STATE_TEXT) != "Paused" and await pg.ev(LIVE_ON) is True)
            await asyncio.sleep(4.0)                                 # more than the 3 s limit, counted from the deactivated event
            check("hidden stop: ...and it still runs 4 s later (the stale deactivated does not stop it)", await pg.ev(LIVE_ON) is True and await pg.ev(STATE_TEXT) != "Paused")
            n_up = len(ups_of(parse(await pg.T())))
            t_away = time.time()
            await pg.ev(TG_AWAY)
            ok = await pg.wait(LIVE_OFF, 12)
            took = time.time() - t_away
            check("hidden stop: deactivated for 3 s Live stops (3-6 s after it went away)", bool(ok) and 2.5 <= took <= 6.0, f"{took:.1f} s")
            T = parse(await pg.T())
            check("hidden stop: ...the microphone is released, the log says why, nothing was sent",
                  bool(await tracks_ended(pg)) and EN_HIDDEN_STOP in parse(await pg.ev(ST_LINES)) and len(ups_of(T)) == n_up, str(T["tracks"]))
        # --- a reply is being spoken when the absence runs out: Live stops at once and the clip is cut (nobody is looking), unlike the idle stop
        quiet = silent_wav(os.path.join(tmp, "quiet.wav"), 5)
        clip = reply_clip(srv, 12)
        async with Session(srv, quiet, lang="en", loop=True, script=CRAFT) as pg:
            await pg.click("#livebtn")
            check("hidden stop mid-reply: Live starts", bool(await pg.wait(LISTENING, 40)) and bool(await pg.wait("__held.length>=1", 15)))
            await pg.ev("__inject(%s)" % json.dumps([reply_event(1, clip)]))
            check("hidden stop mid-reply: the reply is playing", bool(await pg.wait(REPLY_AUDIO + ".some(function(m){return m.type==='playing'})", 10)))
            t_hide = time.time()
            await pg.ev(HIDE)
            ok = await pg.wait(LIVE_OFF, 12)
            took = time.time() - t_hide
            check("hidden stop mid-reply: Live stops 3-6 s after the page went away, with 8 s of the 12 s clip still to play", bool(ok) and 2.5 <= took <= 6.0, f"{took:.1f} s")
            T = parse(await pg.T())
            check("hidden stop mid-reply: the clip was cut: it never reached its end, the audio is stopped",
                  not [m for m in audio_of(T) if m["type"] == "ended"] and await pg.ev("document.getElementById('player').paused") is True)
    finally:
        srv.stop()


async def t_presence_reply(inst, fx):
    """The idle limit does not cut a reply short: while reply audio plays Live goes on, and it stops right after the last clip, before
    listening resumes. A touch before the clip ends cancels the stop. Needs GET /api/config; SKIP without it. (The hidden limit still
    stops at once, in the middle of a reply: see hidden_stop.) The replies are made-up events with silent clips of the instance's audio
    store, and the microphone is silent, so that nothing the user "says" can delay a reply."""
    srv = fake_instance(VOICE_LIVE_IDLE_SEC=12)
    try:
        if api(srv, "/api/config")[0] == 404:
            skip("presence_reply", "the server has no GET /api/config yet (VOICE_LIVE_IDLE_SEC is not served)")
            return
        quiet = silent_wav(os.path.join(tmp, "quiet.wav"), 5)
        clips = [reply_clip(srv, 12), reply_clip(srv, 12)]
        playing = REPLY_AUDIO + ".filter(function(m){return m.type==='playing'}).length"
        ended = REPLY_AUDIO + ".filter(function(m){return m.type==='ended'}).length"
        async with Session(srv, quiet, lang="en", loop=True, script=CRAFT) as pg:
            await pg.click("#livebtn")
            t0 = time.time()
            check("presence reply: Live starts", bool(await pg.wait(LISTENING, 40)) and bool(await pg.wait("__held.length>=1", 15)))
            # reply 1 plays from about 4 s to 16 s; the 12 s limit passes in the middle of it
            await asyncio.sleep(max(0, t0 + 4 - time.time()))
            await pg.ev("__inject(%s)" % json.dumps([reply_event(1, clips[0])]))
            check("presence reply: the first reply is playing", bool(await pg.wait(playing + ">=1", 10)))
            await asyncio.sleep(max(0, t0 + 14 - time.time()))
            lab = await pg.ev(STATE_TEXT)
            check("presence reply: past the 12 s limit the reply is still being spoken and Live runs on", await pg.ev(LIVE_ON) is True and lab.startswith("Speaking"), lab)
            check("presence reply: ...with no countdown over it", await pg.ev(VIS + ";vis('idle')") is False)
            await pg.ev(TOUCH)                                       # the user is there after all: that cancels the stop
            t_touch = time.time()
            check("presence reply: the first clip plays to its end", bool(await pg.wait(ended + ">=1", 15)))
            await asyncio.sleep(1.5)
            check("presence reply: the touch cancelled the stop: Live listens on after the clip", await pg.ev(LIVE_ON) is True and await pg.ev(LISTENING) is True)
            # reply 2: the touch moved the limit to 26 s, which passes in the middle of this one (it plays from about 17.7 s to 29.7 s)
            await pg.ev("__inject(%s)" % json.dumps([reply_event(2, clips[1])]))
            check("presence reply: the second reply is playing", bool(await pg.wait(playing + ">=2", 10)))
            await asyncio.sleep(max(0, t_touch + 13.5 - time.time()))
            lab = await pg.ev(STATE_TEXT)
            check("presence reply: past the limit again the reply is still being spoken and Live runs on", await pg.ev(LIVE_ON) is True and lab.startswith("Speaking"), lab)
            ok = await pg.wait(ended + ">=2", 15)
            check("presence reply: the second clip plays to its end too", bool(ok))
            check("presence reply: and then Live stops", bool(await pg.wait(LIVE_OFF, 3)))
            T = parse(await pg.T())
            ends = [m["t"] for m in audio_of(T) if m["type"] == "ended"]
            after = [x for x in T["states"] if ends and x["t"] >= ends[-1] - 50]
            idle_at = next((x["t"] for x in after if x["state"] == "idle"), None)
            check("presence reply: it stops right after the last clip, before listening resumes (no Listening or Hearing in between)",
                  idle_at is not None and idle_at - ends[-1] < 300 and not [x for x in after if "Listening" in x["text"] or "Hearing" in x["text"]],
                  str([(x["t"] - ends[-1], x["text"]) for x in after]) if ends else "no clip ended")
            check("presence reply: the log says why, and both replies are shown",
                  EN_IDLE_STOP in parse(await pg.ev(ST_LINES)) and await pg.ev("document.querySelectorAll('.msg.cl').length") == 2)
            check("presence reply: the microphone is released", bool(await tracks_ended(pg)))
    finally:
        srv.stop()


# A clock that can be moved forward (the page reads time only through Date.now), so that "15 minutes" and "a minute" need no waiting
CLOCK = r"""(function(){ var o = Date.now; window.__jump = 0; Date.now = function(){ return o.call(Date) + window.__jump; }; })();"""


def no_config(kind):
    """A script: the page's api/config request is answered with 404, fails, or gets nonsense."""
    answer = {"404": "Promise.resolve(new Response('{\"error\":\"not found\"}', {status: 404, headers: {'Content-Type': 'application/json'}}))",
              "network": "Promise.reject(new TypeError('Failed to fetch'))",
              "nonsense": "Promise.resolve(new Response('{\"live_idle_ms\":\"soon\",\"hidden_stop_ms\":-5}', {status: 200, headers: {'Content-Type': 'application/json'}}))"}[kind]
    return "(function(){var of=window.fetch;window.fetch=function(u,o){if(String((u&&u.url)||u).indexOf('api/config')>=0)return %s;return of.apply(this,arguments)}})();" % answer


async def t_config_defaults(inst, fx):
    """Without usable settings (api/config answers 404, fails, or is nonsense) the page keeps its defaults: Live stops after 60 s away
    and after 15 minutes without a touch, with the countdown in the last minute. The waiting is done by moving the page's clock."""
    srv = fake_instance()
    try:
        for kind in ("404", "network", "nonsense"):
            async with Session(srv, fx["live"], lang="en", loop=True, script=CLOCK + no_config(kind)) as pg:
                await pg.click("#livebtn")
                await pg.wait(LISTENING, 40)
                await pg.ev(HIDE + "window.__jump=54000;")           # away for 54 s (and the few seconds of this check): forgiven
                await asyncio.sleep(2.5)
                on = await pg.ev(LIVE_ON)
                await pg.ev("window.__jump=62000;")                  # away for 62 s
                off = await pg.wait(LIVE_OFF, 5)
                check(f"config defaults ({kind}): away for 54 s Live runs on, after 62 s it has stopped (60 s)", on is True and bool(off), f"{on} {off}")
                check(f"config defaults ({kind}): the log says it was the background", EN_HIDDEN_STOP in parse(await pg.ev(ST_LINES)))
                if kind != "404":
                    continue
                await pg.ev(SHOW)
                await pg.click("#livebtn")                           # Live again: the idle time starts now
                await pg.wait(LISTENING, 40)
                await asyncio.sleep(1.5)
                check("config defaults (404): at the start, 15 minutes ahead, there is no countdown", await pg.ev(VIS + ";vis('idle')") is False)
                await pg.ev("window.__jump+=840000;")                # 14 minutes without a touch: a minute is left
                ok = await pg.wait(VIS + ";vis('idle')", 3)
                n = re.search(r"\d+", await pg.ev("document.getElementById('idle').textContent") or "")
                check("config defaults (404): with a minute left of the 15 the countdown shows", bool(ok) and bool(n) and 55 <= int(n.group()) <= 60, str(n))
                await pg.ev(TOUCH)
                await asyncio.sleep(0.4)
                check("config defaults (404): a touch hides it again", await pg.ev(VIS + ";vis('idle')") is False and await pg.ev(LIVE_ON) is True)
                await pg.ev("window.__jump+=895000;")                # 14 min 55 s since the touch
                await asyncio.sleep(1.5)
                check("config defaults (404): still running 5 s before the 15 minutes are over", await pg.ev(LIVE_ON) is True)
                off = await pg.wait(LIVE_OFF, 12)
                check("config defaults (404): after 15 minutes without a touch Live has stopped", bool(off) and EN_IDLE_STOP in parse(await pg.ev(ST_LINES)))
    finally:
        srv.stop()


EN_VOICE_OFF = "Voice input is turned off on the server"


async def t_killswitch(inst, fx):
    """The server's kill switch (a file DISABLED in its state directory) answers every /api request with 503 {"error":"voice input is
    disabled"}. Live ends and one status line says so: when a phrase is refused, when a push-to-talk recording is refused, and when the
    events long-poll is (which then waits 15 s between attempts). With the file gone Live works again."""
    srv = fake_instance()
    flag = os.path.join(srv.state, "DISABLED")
    # Live part: the events long-poll is parked, so that only the phrase can be what ends Live here
    park = ("(function(){var of=window.fetch;window.fetch=function(u,o){var s=String((u&&u.url)||u);"
            "if(s.indexOf('api/events?after=')>=0&&s.indexOf('after=-1')<0)return new Promise(function(){});return of.apply(this,arguments)}})();")
    refused = "__T.fetches.some(function(f){return f.phase==='response' && f.status===503})"
    accepted = "__T.fetches.some(function(f){return f.phase==='response' && f.status===200})"
    try:
        async with Session(srv, fx["live"], lang="en", loop=True, script=park) as pg:
            await pg.click("#livebtn")
            await pg.wait(LISTENING, 40)
            open(flag, "w").close()                                  # the switch is thrown while Live runs
            check("kill switch: the next phrase is refused with 503", bool(await pg.wait(refused, 45)))
            check("kill switch: Live ends", bool(await pg.wait(LIVE_OFF, 5)))
            lines = parse(await pg.ev(ST_LINES))
            check("kill switch: one status line says so (and no generic 'Error: ...' line)", lines == [EN_VOICE_OFF], str(lines))
            check("kill switch: ...in the error style", await pg.ev("document.querySelector('.st').className") == "st err")
            check("kill switch: the microphone is released", bool(await tracks_ended(pg)))
            n_up = len(ups_of(parse(await pg.T())))
            await asyncio.sleep(fx["live_period"])
            check("kill switch: nothing is sent after Live ended", len(ups_of(parse(await pg.T()))) == n_up)
            os.remove(flag)
            await pg.click("#livebtn")
            check("kill switch: the file removed, Live starts again", bool(await pg.wait(LISTENING, 40)))
            check("kill switch: ...and a phrase is accepted", bool(await pg.wait(accepted, 45)) and bool(await pg.wait("document.querySelectorAll('.msg.me').length>=1", 5)))
            check("kill switch: ...and the status line is gone", EN_VOICE_OFF not in parse(await pg.ev(ST_LINES)))
        # A page opened while the switch is on: the events long-poll says so at once, and a push-to-talk recording gets the same single line
        open(flag, "w").close()
        async with Session(srv, fx["ptt"], lang="en", loop=True) as pg:
            t0 = time.time()
            await pg.wait("document.querySelectorAll('.st').length>0", 5)
            lines = parse(await pg.ev(ST_LINES))
            check("kill switch: a page opened while it is on says so at once (the events long-poll)", lines == [EN_VOICE_OFF], str(lines))
            await pg.click("#mode-ptt")
            await pg.click("#rec")
            await pg.wait("document.getElementById('rec').classList.contains('on')", 10)
            await asyncio.sleep(1.2)
            await pg.click("#rec")
            ok = await pg.wait(refused, 10)
            await asyncio.sleep(0.3)
            lines = parse(await pg.ev(ST_LINES))
            check("kill switch: push-to-talk: the refused recording leaves the same single line", bool(ok) and lines == [EN_VOICE_OFF], str(lines))
            await asyncio.sleep(max(0, t0 + 17 - time.time()))
            n = len([r for r in pg.requests.values() if "/api/events" in r["url"]])
            check("kill switch: the events long-poll waits 15 s between attempts (2 requests in 17 s, not one every 3 s)", 2 <= n <= 3, str(n))
    finally:
        srv.stop()


async def t_rate_limit(inst, fx):
    """The server allows 12 phrases a minute. Past that a phrase gets 429 {"error":"rate limited"}: an error line with the server's words,
    and Live goes on listening (only a 403 or the kill switch ends it)."""
    srv = fake_instance()
    try:
        silence_pcm = b"\0" * 6400                                       # 0.2 s: counted as a recognition (free in FAKE mode)
        codes = [api(srv, "/api/utterance", "POST", silence_pcm)[0] for _ in range(13)]
        check("rate limit: setup: 12 phrases a minute are accepted, the 13th gets 429", codes == [200] * 12 + [429], str(codes))
        async with Session(srv, fx["live"], lang="en", loop=True) as pg:
            await pg.click("#livebtn")
            ok = await pg.wait("__T.fetches.some(function(f){return f.phase==='response'})", 45)
            resp = [f for f in parse(await pg.T())["fetches"] if f["phase"] == "response"]
            check("rate limit: the page's phrase is answered with 429", bool(ok) and resp[0]["status"] == 429, str(resp[:1]))
            await asyncio.sleep(0.5)
            lines = parse(await pg.ev(ST_LINES))
            check("rate limit: an error line with the server's words", lines == ["Error: rate limited"] and await pg.ev("document.querySelector('.st').className") == "st err", str(lines))
            check("rate limit: Live goes on listening", await pg.ev(LIVE_ON) is True and await pg.ev(LISTENING) is True)
    finally:
        srv.stop()



CF_UP = "document.getElementById('confirm').classList.contains('on')"
CF_BTNS = "JSON.stringify([document.getElementById('cf-yes').disabled,document.getElementById('cf-no').disabled])"
CF_EN = {"title": "Confirm this action?", "yes": "Confirm", "no": "Decline", "stale": "Reopen the app from the menu to confirm"}


def internal_confirm(srv, action):
    """The channel server's call: (status, answer)."""
    st, b = req(srv.base, "/internal/confirm", "POST", json.dumps({"action": action}).encode(),
                {"X-Internal-Token": ITOK, "Content-Type": "application/json"}, timeout=10)
    return st, json.loads(b)


def confirm_status(srv, cid):
    return json.loads(req(srv.base, "/internal/confirm/" + cid, headers={"X-Internal-Token": ITOK}, timeout=10)[1])["status"]


def confirm_posts(pg):
    return [r for r in pg.requests.values() if r["method"] == "POST" and "/api/confirm" in r["url"]]


async def open_card(srv, pg, action):
    """Create a confirmation the way the channel server does (once the page has polled), and wait for its card."""
    ans = None
    for _ in range(40):
        st, ans = internal_confirm(srv, action)
        if st == 200 and ans.get("delivered"):
            break
        await asyncio.sleep(0.25)
    else:
        return None
    t0 = time.time()
    return ans["id"] if await pg.wait(CF_UP, 10, 0.05) and time.time() - t0 < 10 else None


async def t_confirm(inst, fx):
    """Confirmation by a tap (voice_confirm): the card (role alertdialog, text only), its buttons disabled for the first second,
    a tap on the big indicator confirms nothing, Confirm and Decline reach the server, in both modes, the countdown removes the
    card, a stale login shows the reopen line, and the Russian strings. voice-web is the real one; the channel server is
    played by the test (POST /internal/confirm)."""
    srv = fake_instance(VOICE_CONFIRM_TTL=10)
    action = "Restart the demo service <b>now</b>"
    try:
        async with Session(srv, fx["live"], lang="en", loop=False) as pg:
            check("confirm: no card before a confirmation", await pg.ev(CF_UP) is False)
            cid = await open_card(srv, pg, action)
            check("confirm: a card appears when the confirmation is created", cid is not None)
            if cid is None:
                return
            btns = parse(await pg.ev(CF_BTNS))
            check("confirm: both buttons are disabled when the card appears", btns == [True, True], str(btns))
            t0 = time.time()
            v = parse(await pg.ev("JSON.stringify({role:document.getElementById('confirm').getAttribute('role'),"
                                  "title:document.getElementById('cf-title').textContent,action:document.getElementById('cf-action').textContent,"
                                  "html:document.getElementById('cf-action').innerHTML,time:document.getElementById('cf-time').textContent,"
                                  "yes:document.getElementById('cf-yes').textContent,no:document.getElementById('cf-no').textContent,"
                                  "labelled:document.getElementById('confirm').getAttribute('aria-labelledby'),"
                                  "inline:document.querySelectorAll('#confirm [style],#confirm [onclick]').length})"))
            check("confirm: role alertdialog, labelled", v["role"] == "alertdialog" and v["labelled"] == "cf-title", str(v))
            check("confirm: English strings", v["title"] == CF_EN["title"] and v["yes"] == CF_EN["yes"] and v["no"] == CF_EN["no"], str(v))
            check("confirm: the action is shown as text (no HTML is parsed)", v["action"] == action and "<b>" not in v["html"].replace("&lt;b&gt;", ""), str(v))
            check("confirm: a countdown", re.fullmatch(r"Expires in \d+ s", v["time"]) is not None, v["time"])
            check("confirm: no inline style or handler on the card", v["inline"] == 0)
            await pg.click("#cf-yes")                                   # a real click on a disabled button: nothing happens
            check("confirm: a click during the first second sends nothing", not confirm_posts(pg) and confirm_status(srv, cid) == "pending")
            # a tap on the big indicator while the card is shown: no confirmation, and Live does not start
            await pg.click("#orb")
            await asyncio.sleep(0.3)
            check("confirm: a tap on the big indicator confirms nothing and starts nothing",
                  not confirm_posts(pg) and confirm_status(srv, cid) == "pending" and await pg.ev(LIVE_OFF) is True)
            on = await pg.wait("document.getElementById('cf-yes').disabled===false && document.getElementById('cf-no').disabled===false", 5, 0.05)
            dt = time.time() - t0
            check("confirm: the buttons wake up after about a second", bool(on) and 0.4 < dt < 2.5, f"{dt:.2f} s")
            await pg.click("#cf-yes")
            gone = await pg.wait("!" + CF_UP, 5)
            check("confirm: Confirm sends the decision, the card goes away", bool(gone) and len(confirm_posts(pg)) == 1 and confirm_status(srv, cid) == "confirmed",
                  f"{len(confirm_posts(pg))} posts, {confirm_status(srv, cid)}")
            check("confirm: the logged answer has the id prefix only", any(l == "CONFIRM: %s confirmed" % cid[:8] for l in srv.log)
                  and not any(action in l or cid in l for l in srv.log), str(srv.log[-5:]))
            # push-to-talk mode, Decline
            await pg.click("#mode-ptt")
            cid2 = await open_card(srv, pg, "Delete the scratch file")
            check("confirm: the card also appears in push-to-talk mode", cid2 is not None and await pg.ev(
                "(function(){var r=document.getElementById('confirm').getBoundingClientRect();return r.width>100&&r.height>50})()") is True)
            await pg.wait("document.getElementById('cf-no').disabled===false", 5, 0.05)
            await pg.click("#cf-no")
            gone = await pg.wait("!" + CF_UP, 5)
            check("confirm: Decline sends the decision", bool(gone) and confirm_status(srv, cid2) == "declined", confirm_status(srv, cid2))
            # nobody taps: the countdown removes the card when the time is up
            cid3 = await open_card(srv, pg, "Nobody taps this")
            t1 = time.time()
            gone = await pg.wait("!" + CF_UP, 14, 0.2)
            check("confirm: an unanswered card goes away when its time is up (10 s)", cid3 is not None and bool(gone) and 7 < time.time() - t1 < 13, f"{time.time() - t1:.1f} s")
            check("confirm: ...and the server says expired", confirm_status(srv, cid3) == "expired")
            check("confirm: no CSP violation was reported for any of it", not parse(await pg.ev("JSON.stringify(__T.csp)")))
            # the tap that is too late: a card whose id the server no longer takes shows a line and goes away
            cid4 = await open_card(srv, pg, "Gone on the server")
            await pg.wait("document.getElementById('cf-yes').disabled===false", 5, 0.05)
            with open(os.path.join(srv.state, "DISABLED"), "w"):
                pass
            await pg.click("#cf-yes")
            await asyncio.sleep(0.6)
            os.remove(os.path.join(srv.state, "DISABLED"))
            lines = parse(await pg.ev(ST_LINES))
            check("confirm: the kill switch answers the tap with the usual single line, the card goes away",
                  EN_VOICE_OFF in lines and await pg.ev(CF_UP) is False and confirm_status(srv, cid4) == "pending", str(lines))
        # a page whose login is older than the confirm window (3600 s) but inside the general one
        fresh = {"X-Init-Data": init_data()}
        async with Session(srv, fx["live"], lang="en", loop=False, age=4000) as pg:
            req(srv.base, "/api/events?after=-1", headers=fresh)       # a second, fresh page keeps the confirmation deliverable
            cid5 = await open_card(srv, pg, "Stale login check")
            check("confirm: the card also shows on a page with an old login", cid5 is not None)
            await pg.wait("document.getElementById('cf-yes').disabled===false", 5, 0.05)
            await pg.click("#cf-yes")
            gone = await pg.wait("!" + CF_UP, 5)
            lines = parse(await pg.ev(ST_LINES))
            check("confirm: an old login gets the line 'Reopen the app from the menu to confirm' and the card goes away",
                  bool(gone) and lines == [CF_EN["stale"]] and await pg.ev("document.querySelector('.st').className") == "st err", str(lines))
            check("confirm: ...the request was refused (403 stale login) and nothing was confirmed",
                  confirm_status(srv, cid5) == "pending" and any(r["status"] == 403 for r in pg.responses.values() if "/api/confirm" in r["url"]),
                  str([r for r in pg.responses.values() if "/api/confirm" in r["url"]]))
        # Russian
        async with Session(srv, fx["live"], lang="ru", loop=False) as pg:
            cid6 = await open_card(srv, pg, "Restart")
            v = parse(await pg.ev("JSON.stringify([document.getElementById('cf-title').textContent,document.getElementById('cf-yes').textContent,"
                                  "document.getElementById('cf-no').textContent,document.getElementById('cf-time').textContent])"))
            check("confirm: Russian strings", cid6 is not None and v[:3] == ["Подтвердить действие?",
                                                                             "Подтвердить", "Отклонить"]
                  and re.fullmatch("Осталось \\d+ с", v[3]) is not None, str(v))
    finally:
        srv.stop()



PROG_LINE = "JSON.stringify([document.getElementById('prog').textContent,document.getElementById('prog').classList.contains('on')])"


def internal_progress(srv, kind):
    return req(srv.base, "/internal/progress", "POST", json.dumps({"kind": kind}).encode(),
               {"X-Internal-Token": ITOK, "Content-Type": "application/json"}, timeout=10)[0]


def make_ack(srv):
    """An utterance that the channel server then fetches: the page gets an `ack` event (it is waiting for the reply)."""
    st, b = api(srv, "/api/utterance", "POST", b"\x01\x00" * 16000)
    uid = json.loads(b)["id"]
    req(srv.base, "/internal/inbox?after=%d" % (uid - 1), headers={"X-Internal-Token": ITOK}, timeout=10)


async def t_progress(inst, fx):
    """Live progress: a small line under the controls while a reply is awaited (Thinking, in push-to-talk and in Live), cleared by
    "idle" or by the reply, faded after 20 s, never shown outside Thinking, Russian strings."""
    srv = fake_instance()
    try:
        async with Session(srv, fx["live"], lang="en", loop=False) as pg:
            await pg.click("#mode-ptt")
            await asyncio.sleep(0.8)
            internal_progress(srv, "read")
            await asyncio.sleep(1.0)
            check("progress: nothing is shown before a reply is awaited", parse(await pg.ev(PROG_LINE)) == ["", False])
            make_ack(srv)
            check("progress: push-to-talk: the page is waiting", bool(await pg.wait("!!document.querySelector('.typing')", 8)))
            for kind, text in (("read", "Reading files"), ("run", "Running a command"), ("agent", "A sub-agent is working")):
                internal_progress(srv, kind)
                ok = await pg.wait("document.getElementById('prog').textContent===%s" % json.dumps(text), 8)
                check(f"progress: {kind} -> {text!r}", bool(ok) and parse(await pg.ev(PROG_LINE)) == [text, True])
            internal_progress(srv, "idle")
            check("progress: idle clears the line", bool(await pg.wait("document.getElementById('prog').textContent===''", 8)) and parse(await pg.ev(PROG_LINE))[1] is False)
            internal_progress(srv, "edit")
            await pg.wait("document.getElementById('prog').textContent==='Editing files'", 8)
            t0 = time.time()
            check("progress: the line fades after 20 s without a new event",
                  bool(await pg.wait("document.getElementById('prog').textContent===''", 26, 0.5)) and 17 < time.time() - t0 < 24, f"{time.time() - t0:.1f}")
            internal_progress(srv, "web")
            await pg.wait("document.getElementById('prog').textContent==='Browsing the web'", 8)
            assert srv.reply("Made-up answer") == 200
            check("progress: the reply clears it", bool(await pg.wait("document.getElementById('prog').textContent===''", 8)) and parse(await pg.ev(PROG_LINE))[1] is False)
            internal_progress(srv, "search")
            await asyncio.sleep(1.2)
            check("progress: after the reply nothing is shown (not Thinking)", parse(await pg.ev(PROG_LINE)) == ["", False])
            check("progress: no CSP violation", not parse(await pg.ev("JSON.stringify(__T.csp)")))
        quiet = silent_wav(os.path.join(tmp, "progress-quiet.wav"), 5)       # nothing is heard: only the ack puts the page into Thinking
        async with Session(srv, quiet, lang="en", loop=True) as pg:
            await pg.click("#livebtn")
            check("progress: Live: listening", bool(await pg.wait(LISTENING, 40)))
            internal_progress(srv, "run")
            await asyncio.sleep(1.0)
            check("progress: Live: not shown while only listening", parse(await pg.ev(PROG_LINE)) == ["", False])
            make_ack(srv)
            check("progress: Live: Thinking", bool(await pg.wait("document.getElementById('orb').dataset.state==='thinking'", 8)))
            internal_progress(srv, "voice")
            ok = await pg.wait("document.getElementById('prog').textContent==='Preparing the answer'", 8)
            check("progress: Live: the line shows during Thinking", bool(ok))
            assert srv.reply("Made-up answer") == 200
            check("progress: Live: the reply clears it", bool(await pg.wait("document.getElementById('prog').textContent===''", 8)))
        async with Session(srv, fx["live"], lang="ru", loop=False) as pg:
            await pg.click("#mode-ptt")
            await asyncio.sleep(0.6)
            make_ack(srv)
            await pg.wait("!!document.querySelector('.typing')", 8)
            ru = {"read": "Читаю файлы", "other": "Работаю"}
            for kind, text in ru.items():
                internal_progress(srv, kind)
                ok = await pg.wait("document.getElementById('prog').textContent===%s" % json.dumps(text), 8)
                check(f"progress: Russian {kind}", bool(ok))
    finally:
        srv.stop()



TESTS = [("language", t_language), ("live", t_live), ("presets", t_presets), ("halfduplex", t_half_duplex), ("ptt", t_ptt),
         ("fallback", t_fallback), ("lifecycle", t_lifecycle), ("cap", t_cap),
         ("ptt_double", t_ptt_double), ("audio_url", t_audio_url), ("csp_report", t_csp_report), ("csp", t_csp),
         ("hidden_flush", t_hidden_flush), ("presence", t_presence), ("hidden_stop", t_hidden_stop), ("config_defaults", t_config_defaults),
         ("killswitch", t_killswitch), ("rate_limit", t_rate_limit), ("presence_reply", t_presence_reply), ("confirm", t_confirm), ("progress", t_progress)]


async def run_all():
    inst = Instance()
    try:
        startup = " ".join(inst.log)
        info("test instance: " + next((l for l in inst.log if "voice-web starting" in l), "?"))
        if "stt=openrouter (FAKE)" in startup or "tts=openrouter (FAKE)" in startup:
            print("SKIP: no OpenRouter key in " + ENV_FILE + ": recognition and speech would be fakes; the browser suite needs real ones")
            return
        check("test instance does not mirror to Telegram", "mirror_tg=False" in startup, startup)
        if not VENDOR:
            check("vendor files found (run deploy.sh first)", False)
            return
        sample = os.environ.get("VOICE_TEST_SAMPLE")
        if sample:
            speech, rate = read_wav(sample)
        else:
            s0 = len(os.listdir(os.path.join(inst.state, "audio")))
            assert inst.reply(SAMPLE_TEXT) == 200
            name = sorted(os.listdir(os.path.join(inst.state, "audio")), key=lambda f: os.path.getmtime(os.path.join(inst.state, "audio", f)))[-1]
            speech, rate = read_wav(os.path.join(inst.state, "audio", name))
        speech48 = resample(speech, rate, 48000)
        info(f"speech sample: {len(speech48) / 48000:.1f} s")
        fx = {"speech": speech48}
        fx["speech_len"] = len(speech48) / 48000
        fx["speech_first"], fx["speech_last"] = active_span(speech48, 48000)
        info(f"speech is loud from {fx['speech_first']:.2f} s to {fx['speech_last']:.2f} s of the sample")
        fx["live"] = os.path.join(tmp, "live.wav")      # 1 s silence + speech + 3 s silence (loop period = file length)
        write_wav(fx["live"], silence(1) + speech48 + silence(3))
        fx["live_period"] = (len(speech48) / 48000) + 4
        fx["ptt"] = os.path.join(tmp, "ptt.wav")        # speech first, so that a 3 s recording is full of it
        write_wav(fx["ptt"], speech48 + silence(1))
        fx["long"] = os.path.join(tmp, "long.wav")      # 66+ s of continuous speech, then silence
        reps = int(66 * 48000 // len(speech48)) + 1
        write_wav(fx["long"], speech48 * reps + silence(4))
        for name, fn in TESTS:
            if ONLY and name not in ONLY:
                continue
            print(f"--- {name}", flush=True)
            t0 = time.time()
            del viol_log[:]
            try:
                await fn(inst, fx)
            except Exception as e:
                import traceback
                traceback.print_exc()
                check(f"{name}: ran without an exception", False, repr(e))
            # Whatever the server's Content-Security-Policy blocked in any page of this test (none, unless it provoked it on purpose)
            check(f"{name}: the page reported no Content-Security-Policy violation", not viol_log, str(viol_log[:3]))
            info(f"{name}: {time.time() - t0:.0f} s")
        n_stt = sum(1 for l in inst.log if '"POST /api/utterance' in l)
        n_tts = sum(1 for l in inst.log if '"POST /internal/reply' in l)
        info(f"paid API calls in this run: {n_stt} recognitions, {n_tts} syntheses")
    finally:
        pass


def pid_alive(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")   # a zombie counts as gone
    except OSError:
        return False


def main():
    try:
        asyncio.run(run_all())
    finally:
        if started["chrome"]:
            started["chrome"].stop()
        for x in started.get("extra", []):
            x.stop()
        if started["web"]:
            started["web"].stop()
        shutil.rmtree(tmp, ignore_errors=True)
    time.sleep(0.3)
    if used["pids"]:
        check("cleanup: no Chrome and no test server left running", not [p for p in used["pids"] if pid_alive(p)],
              str([p for p in used["pids"] if pid_alive(p)]))
        check("cleanup: every port the run used is free again", all(port_is_free(p) for p in used["ports"]),
              str([p for p in used["ports"] if not port_is_free(p)]))
    if skipped:
        print("SKIPPED (needs server work that is not there yet): " + ", ".join(skipped))
    print("FAILED: " + ", ".join(fails) if fails else "ALL PASSED")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
