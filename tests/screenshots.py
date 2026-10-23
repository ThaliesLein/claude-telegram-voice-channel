#!/usr/bin/env python3
"""Screenshots of the Mini App's key states, for design review: python3 tests/screenshots.py OUT_DIR

Reuses the harness of e2e_browser.py (throwaway voice-web instance, headless Chrome over the DevTools Protocol, a WAV file as
the microphone) and drives real flows: a click starts Live, the fake microphone speaks, the speech is recognized, the instance
posts a reply. Like the browser tests it uses real speech recognition and synthesis (about 5 recognitions and 3 syntheses),
so the instance reads its keys from VOICE_ENV_FILE (default /root/.voice/env). Nothing is mirrored to Telegram and no private
data is involved: the spoken sentences below are made up.

The UI is shown in Russian (the Mini App's second language), plus one English shot; the instance runs with VOICE_LANG ru-RU
unless VOICE_TEST_LANG says otherwise. Shots at 390x844 (DPR 2): Live idle with the empty state, listening, hearing,
thinking (with messages and the typing bubble), speaking, push-to-talk idle and recording; Thinking with a progress line, a confirmation card (voice_confirm) at 390x844 and 320x568, then idle and thinking at 320x568
and 430x932. At 320x568 it also checks that nothing scrolls sideways in either mode.

Headless Chrome on a server often has only DejaVu Sans, which is about 12% wider than the system fonts of a phone; if
Liberation Sans is installed, the generic names of the page's font stack are pointed at it for the screenshots.
Prints the path of every PNG, then ALL PASSED (exit 0) or the list of what failed (exit 1). Without keys it prints SKIP and exits 0."""
import asyncio, base64, os, shutil, sys, time

SHOT_LANG = os.environ.get("SHOT_LANG", "en")           # "en" (default) or "ru": the language of the UI, of the spoken samples and of the instance
os.environ.setdefault("VOICE_TEST_LANG", "ru-RU" if SHOT_LANG == "ru" else "en-US")   # recognition and synthesis language; read by e2e_browser at import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_browser as E

# Made-up sentences, written as escapes so that the source stays English (the same way e2e_browser.py writes its Russian strings).
# SPOKEN: "Tell me, please, what the weather is like tomorrow morning and whether I need an umbrella when I leave for work."
# ANSWER: "Tomorrow morning it is cloudy, around twelve degrees; by noon it clears up and warms to seventeen. The umbrella can stay at home."
SPOKEN = "\u041f\u043e\u0434\u0441\u043a\u0430\u0436\u0438, \u043f\u043e\u0436\u0430\u043b\u0443\u0439\u0441\u0442\u0430, \u043a\u0430\u043a\u0430\u044f \u0437\u0430\u0432\u0442\u0440\u0430 \u043f\u043e\u0433\u043e\u0434\u0430 \u0443\u0442\u0440\u043e\u043c \u0438 \u043d\u0443\u0436\u043d\u043e \u043b\u0438 \u0431\u0440\u0430\u0442\u044c \u0437\u043e\u043d\u0442, \u043a\u043e\u0433\u0434\u0430 \u044f \u043f\u043e\u0435\u0434\u0443 \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0443."
ANSWER = "\u0417\u0430\u0432\u0442\u0440\u0430 \u0443\u0442\u0440\u043e\u043c \u043e\u0431\u043b\u0430\u0447\u043d\u043e \u0438 \u043e\u043a\u043e\u043b\u043e \u0434\u0432\u0435\u043d\u0430\u0434\u0446\u0430\u0442\u0438 \u0433\u0440\u0430\u0434\u0443\u0441\u043e\u0432, \u043a \u043e\u0431\u0435\u0434\u0443 \u043f\u0440\u043e\u044f\u0441\u043d\u0438\u0442\u0441\u044f \u0438 \u043f\u043e\u0442\u0435\u043f\u043b\u0435\u0435\u0442 \u0434\u043e \u0441\u0435\u043c\u043d\u0430\u0434\u0446\u0430\u0442\u0438. \u0417\u043e\u043d\u0442 \u043c\u043e\u0436\u043d\u043e \u043e\u0441\u0442\u0430\u0432\u0438\u0442\u044c \u0434\u043e\u043c\u0430."
# CONFIRM_ACTION: "Restart the service "demo" and check that it answers."
CONFIRM_ACTION = "\u041f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c \u0441\u0435\u0440\u0432\u0438\u0441 \u00ab\u0434\u0435\u043c\u043e\u00bb \u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c, \u0447\u0442\u043e \u043e\u043d \u043e\u0442\u0432\u0435\u0447\u0430\u0435\u0442."
if SHOT_LANG != "ru":
    SPOKEN = "Tell me, please, what the weather is like tomorrow morning and whether I need an umbrella when I leave for work."
    ANSWER = "Tomorrow morning it is cloudy, around twelve degrees; by noon it clears up and warms to seventeen. The umbrella can stay at home."
    CONFIRM_ACTION = "Restart the service \u201cdemo\u201d and check that it answers."
FONTS = """<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig>
<include ignore_missing="yes">/etc/fonts/fonts.conf</include>
%s</fontconfig>"""
ALIAS = ('<match target="pattern"><test qual="any" name="family"><string>%s</string></test>'
         '<edit name="family" mode="assign" binding="same"><string>Liberation Sans</string></edit></match>')

out_dir = ""
saved, problems = [], []


def note(ok, name, extra=""):
    E.check(name, ok, extra)
    if not ok:
        problems.append(name)
    return ok


async def shot(pg, name):
    r = await pg.send("Page.captureScreenshot", {"format": "png"})
    path = os.path.join(out_dir, name + ".png")
    with open(path, "wb") as f:
        f.write(base64.b64decode(r["data"]))
    saved.append(path)
    print("     saved " + path, flush=True)


async def phone(pg, w, h, dpr=2):
    """Resize the emulated phone and give the layout (and the orb's canvas) a moment to follow."""
    await pg.send("Emulation.setDeviceMetricsOverride", {"width": w, "height": h, "deviceScaleFactor": dpr, "mobile": False})
    await asyncio.sleep(0.6)


STATE = "document.getElementById('orb').dataset.state"


async def reached(pg, expr, what, timeout=45):
    ok = await pg.wait(expr, timeout)
    note(bool(ok), "reached: " + what, "timed out")
    return bool(ok)


async def sideways(pg, label):
    v = await pg.ev("document.documentElement.scrollWidth<=document.documentElement.clientWidth")
    note(v is True, "no horizontal scroll: " + label)


async def run_flow(inst, fx):
    loop = asyncio.get_event_loop()

    # Live idle with the empty state, then listening: a silent microphone, so nothing is heard
    async with E.Session(inst, fx["quiet"], lang=SHOT_LANG, loop=True) as pg:
        await phone(pg, 390, 844)
        await shot(pg, "01_live_idle_empty_" + SHOT_LANG)
        await pg.click("#livebtn")
        if await reached(pg, STATE + "==='listening'", "listening"):
            await asyncio.sleep(2.0)
            await shot(pg, "02_live_listening_" + SHOT_LANG)

    # hearing, speaking and thinking in one conversation: the microphone loops 1 s of silence + a spoken sentence + a long silence,
    # so that the reply is synthesized and played before the sentence comes round again
    async with E.Session(inst, fx["loop"], lang=SHOT_LANG, loop=True) as pg:
        await phone(pg, 390, 844)
        await pg.click("#livebtn")
        if await reached(pg, STATE + "==='hearing'", "hearing"):
            await asyncio.sleep(1.4)
            await shot(pg, "03_live_hearing_" + SHOT_LANG)
        if await reached(pg, "document.querySelectorAll('.msg.me').length>=1", "the first transcript in the log", 60):
            await loop.run_in_executor(None, inst.reply, ANSWER)
            if await reached(pg, STATE + "==='speaking'", "speaking", 60):
                await asyncio.sleep(1.6)
                await shot(pg, "05_live_speaking_" + SHOT_LANG)
            # the reply is played, the microphone loops, the next sentence is heard and sent: three messages and the typing bubble
            if await reached(pg, "document.querySelectorAll('.msg.me').length>=2 && !!document.querySelector('.typing') && " + STATE + "==='thinking'",
                             "the second transcript and the typing bubble", 120):
                await asyncio.sleep(1.2)
                note(await pg.ev("document.querySelectorAll('.msg.cl').length") == 1 and await pg.ev("document.querySelector('.typing')===document.getElementById('log').lastElementChild"),
                     "the typing bubble is the last child of the log and the log has the reply")
                await shot(pg, "04_live_thinking_" + SHOT_LANG)
                # the progress line (the hook's call is made by the test)
                E.internal_progress(inst, "read")
                if await reached(pg, "document.getElementById('prog').classList.contains('on')", "the progress line", 10):
                    await asyncio.sleep(0.6)
                    await shot(pg, "15_live_thinking_progress_" + SHOT_LANG)

    # push-to-talk: idle, then recording (real clicks)
    async with E.Session(inst, fx["quiet"], lang=SHOT_LANG, loop=True) as pg:
        await phone(pg, 390, 844)
        await pg.click("#mode-ptt")
        await asyncio.sleep(0.8)
        await shot(pg, "06_ptt_idle_" + SHOT_LANG)
        await pg.click("#rec")
        if await reached(pg, "document.getElementById('rec').classList.contains('on')", "recording", 15):
            await asyncio.sleep(2.3)
            await shot(pg, "07_ptt_recording_" + SHOT_LANG)

    # English
    async with E.Session(inst, fx["quiet"], lang="en", loop=True) as pg:
        await phone(pg, 390, 844)
        await shot(pg, "08_live_idle_en")

    # a confirmation card (voice_confirm; the test plays the channel server): Live idle behind it, then the smallest phone
    for n, (w, h) in enumerate(((390, 844), (320, 568))):
        async with E.Session(inst, fx["quiet"], lang=SHOT_LANG, loop=False) as pg:
            await phone(pg, w, h)
            cid = await E.open_card(inst, pg, CONFIRM_ACTION)
            if note(cid is not None, "a confirmation card at %dx%d" % (w, h)) is False:
                continue
            await pg.wait("document.getElementById('cf-yes').disabled===false", 5, 0.1)
            await asyncio.sleep(0.5)
            await shot(pg, ("%02d_confirm_card_%dx%d_" + SHOT_LANG) % (13 + n, w, h))
            v = await pg.ev("(function(){var r=document.getElementById('confirm').getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight})()")
            note(v is True, "%dx%d: the confirmation card is inside the screen" % (w, h))
            await sideways(pg, "%dx%d, confirmation card" % (w, h))

    # the smallest and the largest phone: idle, then thinking after one spoken sentence
    for n, (w, h) in enumerate(((320, 568), (430, 932))):
        async with E.Session(inst, fx["live"], lang=SHOT_LANG, loop=False) as pg:
            await phone(pg, w, h)
            await shot(pg, ("%02d_live_idle_%dx%d_" + SHOT_LANG) % (9 + 2 * n, w, h))
            if w == 320:
                await sideways(pg, "320x568, Live")
            await pg.click("#livebtn")
            if await reached(pg, STATE + "==='thinking' && document.querySelectorAll('.msg.me').length>=1", "thinking at %dx%d" % (w, h), 60):
                await asyncio.sleep(1.2)
                await shot(pg, ("%02d_live_thinking_%dx%d_" + SHOT_LANG) % (10 + 2 * n, w, h))
            if w == 320:
                await pg.click("#livebtn")                      # stop Live, then look at push-to-talk
                await pg.click("#mode-ptt")
                await asyncio.sleep(0.5)
                await sideways(pg, "320x568, push-to-talk")
                v = await pg.ev("(function(){var r=document.getElementById('rec').getBoundingClientRect();return r.bottom<=innerHeight && r.top>=0})()")
                note(v is True, "320x568: the Speak button is inside the screen")


async def main():
    """Returns False when the run was skipped (no keys)."""
    inst = E.Instance()
    startup = " ".join(inst.log)
    if "stt=openrouter (FAKE)" in startup or "tts=openrouter (FAKE)" in startup:
        print("SKIP: no OpenRouter key in " + E.ENV_FILE + ": the flows need real recognition and synthesis")
        return False
    if not E.VENDOR:
        note(False, "vendor files found (run deploy.sh first)")
        return True
    audio = os.path.join(inst.state, "audio")
    before = set(os.listdir(audio))
    assert inst.reply(SPOKEN) == 200, "the instance could not synthesize the sample"
    name = max(set(os.listdir(audio)) - before, key=lambda f: os.path.getmtime(os.path.join(audio, f)))
    speech, rate = E.read_wav(os.path.join(audio, name))
    speech48 = E.resample(speech, rate, 48000)
    fx = {k: os.path.join(E.tmp, k + ".wav") for k in ("quiet", "live", "loop")}
    E.write_wav(fx["quiet"], E.silence(60))
    E.write_wav(fx["live"], E.silence(1) + speech48 + E.silence(3))
    E.write_wav(fx["loop"], E.silence(1) + speech48 + E.silence(24))
    E.info("speech sample: %.1f s" % (len(speech48) / 48000))
    await run_flow(inst, fx)
    return True


def run():
    conf = os.path.join(E.tmp, "fonts.conf")
    with open(conf, "w") as f:
        f.write(FONTS % "".join(ALIAS % n for n in ("system-ui", "Roboto", "sans-serif")))
    os.environ["FONTCONFIG_FILE"] = conf
    ran = True
    try:
        ran = asyncio.run(main())
    except Exception:
        import traceback
        traceback.print_exc()
        problems.append("the run raised an exception")
    finally:
        if E.started["chrome"]:
            E.started["chrome"].stop()
        if E.started["web"]:
            E.started["web"].stop()
    time.sleep(0.3)
    note(not [p for p in E.used["pids"] if E.pid_alive(p)], "cleanup: no Chrome and no test server left running")
    note(all(E.port_is_free(p) for p in E.used["ports"]), "cleanup: every port the run used is free again")
    if not ran:
        return 0
    print("%d screenshots in %s" % (len(saved), out_dir))
    for p in saved:
        print("  " + p)
    print("FAILED: " + ", ".join(problems) if problems else "ALL PASSED")
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 tests/screenshots.py OUT_DIR")
    out_dir = os.path.abspath(sys.argv[1])
    os.makedirs(out_dir, exist_ok=True)
    code = run()
    shutil.rmtree(E.tmp, ignore_errors=True)
    sys.exit(code)
