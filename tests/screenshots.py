#!/usr/bin/env python3
"""Screenshots of the Mini App's key states, for design review and for the images in docs/: python3 tests/screenshots.py OUT_DIR

Reuses the harness of e2e_browser.py (throwaway voice-web instance, headless Chrome over the DevTools Protocol, a WAV file as
the microphone) and drives real flows: a click starts Live, the fake microphone speaks, the speech is recognized, the instance
posts a reply. Like the browser tests it uses real speech recognition and synthesis (4 recognitions and 2 syntheses, a few cents),
so the instance reads its keys from VOICE_ENV_FILE (default /root/.voice/env). Nothing is mirrored to Telegram and no private
data is involved: the spoken sentences below are made up.

The UI, the spoken samples and the instance (VOICE_LANG en-US) are English; SHOT_LANG=ru makes them Russian (VOICE_TEST_LANG can still
set the instance's language), and one more English shot of Live idle is always taken. Shots at 390x844 (DPR 2): Live idle with the
empty state, listening, hearing, Loading (the reply is on the screen, its sound is still being made), speaking, a helper working in
the background (the line under the controls says so, then shows the helper's own tool call; the session itself is idle), thinking (the
spoken sentence and the typing bubble), thinking with a progress line and with the line of a running command (the red "Interrupt work"
button is under the line whenever a reply is awaited or spoken), push-to-talk idle and recording; a confirmation card (voice_confirm) at
390x844 and 320x568, then idle and thinking at 320x568 and 430x932. At 320x568 it also checks that nothing scrolls sideways in either
mode, and at both of these sizes that the Interrupt work button is on the screen. The test plays the session's hook
(/internal/progress), the session itself (/internal/reply) and the channel server (/internal/confirm).

SHOT_DOCS=DIR (English UI only) also writes the images of docs/screenshots into DIR: some of these shots under the names docs/frames/
uses (see DOCS), scaled to 420 px wide and reduced to 256 colours with Pillow (docs_image), 130 to 210 KB each instead of 1.5 MB.

Headless Chrome on a server often has only DejaVu Sans, which is about 12% wider than the system fonts of a phone; if
Liberation Sans is installed, the generic names of the page's font stack are pointed at it for the screenshots.
Prints the path of every PNG, then ALL PASSED (exit 0) or the list of what failed (exit 1). Without keys it prints SKIP and exits 0."""
import asyncio, base64, json, os, re, shutil, sys, time

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

# The images of docs/screenshots (framed by docs/frames into the pictures of the README) are these shots; the key is the name of the shot
# without the language, the value the name of the image.
DOCS = {"01_live_idle_empty": "live-idle", "03_live_hearing": "live-hearing", "16_live_loading": "live-loading", "05_live_speaking": "live-speaking",
        "17_live_helper": "live-helper", "15_live_thinking_progress": "live-thinking", "19_live_interrupt": "live-interrupt",
        "07_ptt_recording": "push-to-talk", "13_confirm_card_390x844": "confirm-card"}

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


def docs_image(src, dst, width=420):
    """The shot scaled to `width` px and reduced to 256 colours: a median-cut palette, dithered (the aurora and the orb are smooth gradients, a plain
    palette makes rings of them); a pixel that dithering put far off (a stray colour in a smooth area) takes the nearest colour instead. Needs Pillow."""
    from PIL import Image, ImageChops
    im = Image.open(src).convert("RGB")
    im = im.resize((width, im.height * width // im.width), Image.LANCZOS)
    pal = im.quantize(colors=256, method=Image.Quantize.MEDIANCUT, kmeans=3)
    out = im.quantize(palette=pal, dither=Image.Dither.FLOYDSTEINBERG)
    r, g, b = ImageChops.difference(out.convert("RGB"), im).split()
    far = ImageChops.add(ImageChops.add(r, g), b).point(lambda v: 255 if v > 45 else 0)
    out.paste(im.quantize(palette=pal, dither=Image.Dither.NONE), mask=far)
    out.save(dst, optimize=True)


def write_docs(docs_dir):
    os.makedirs(docs_dir, exist_ok=True)
    for path in saved:
        name = os.path.basename(path)[:-len("_%s.png" % SHOT_LANG)]
        if name in DOCS:
            dst = os.path.join(docs_dir, DOCS[name] + ".png")
            docs_image(path, dst)
            print("  docs image %s (%d KB)" % (dst, os.path.getsize(dst) // 1024), flush=True)


async def phone(pg, w, h, dpr=2):
    """Resize the emulated phone and give the layout (and the orb's canvas) a moment to follow."""
    await pg.send("Emulation.setDeviceMetricsOverride", {"width": w, "height": h, "deviceScaleFactor": dpr, "mobile": False})
    await asyncio.sleep(0.6)


STATE = "document.getElementById('orb').dataset.state"
PROG_ON = "document.getElementById('prog').classList.contains('on')"       # the line under the controls (progress, background helpers)
PROG_TEXT = "document.getElementById('prog').textContent"
BUTTON = "!document.getElementById('interrupt').hidden"                    # the "Interrupt work" button is shown


async def reached(pg, expr, what, timeout=45):
    ok = await pg.wait(expr, timeout)
    note(bool(ok), "reached: " + what, "timed out")
    return bool(ok)


async def sideways(pg, label):
    v = await pg.ev("document.documentElement.scrollWidth<=document.documentElement.clientWidth")
    note(v is True, "no horizontal scroll: " + label)


async def said_right(pg, what):
    """The transcript of the user's line on the screen is the sentence the microphone spoke: a recognition that lost the first words
    would make a poor image."""
    got = await pg.ev("(function(){var m=document.querySelector('.msg.me');return m&&m.firstChild?m.firstChild.nodeValue:''})()")
    return note(re.findall(r"\w+", got.lower()) == re.findall(r"\w+", SPOKEN.lower()), "the transcript is what was said (%s)" % what, repr(got))


async def progress_line(pg, inst, body, what):
    """Posts a progress event the way the session's hook does (the test plays the hook) and waits until the line under the controls
    shows text that is new."""
    before = await pg.ev(PROG_TEXT)
    E.post_progress(inst, body)
    return await reached(pg, PROG_ON + "&&" + PROG_TEXT + "!==" + json.dumps(before), what, 10)


async def shoot_helper(pg, inst):
    """A subagent works in the background while the session itself is idle (Live listens): the line says so, then it shows the helper's
    own tool call. Neither needs a reply to be awaited, and the "Interrupt work" button stays hidden: nothing of the main turn runs."""
    if await progress_line(pg, inst, {"kind": "idle", "bg": 1}, "the line for a background helper"):
        note(await pg.ev(BUTTON) is False, "no Interrupt work button while only a helper works")
        await asyncio.sleep(0.6)
        await shot(pg, "17_live_helper_" + SHOT_LANG)
        if await progress_line(pg, inst, {"kind": "read", "who": "agent"}, "the helper's own tool call in the line"):
            await asyncio.sleep(0.6)
            await shot(pg, "18_live_helper_action_" + SHOT_LANG)
    E.post_progress(inst, {"kind": "idle", "bg": 0})                      # the helper is done: the line goes
    await pg.wait("!(" + PROG_ON + ")", 10)


async def shoot_interrupt(pg, inst):
    """The session is working (Thinking) and runs a command: the line says so and the red "Interrupt work" button is under it."""
    if await progress_line(pg, inst, {"kind": "run"}, "the line of a running command"):
        note(await pg.ev(BUTTON) is True, "the Interrupt work button is shown while the session works")
        await asyncio.sleep(0.6)
        await shot(pg, "19_live_interrupt_" + SHOT_LANG)


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

    # Loading, speaking and a helper in the background in one conversation: the microphone speaks one sentence and then stays silent for
    # a minute (the file loops, but the session is over long before), so that nothing else is heard while the shots are taken
    async with E.Session(inst, fx["loop"], lang=SHOT_LANG, loop=True) as pg:
        await phone(pg, 390, 844)
        await pg.click("#livebtn")
        if await reached(pg, STATE + "==='hearing'", "hearing"):
            await asyncio.sleep(1.4)
            await shot(pg, "03_live_hearing_" + SHOT_LANG)
        if await reached(pg, "document.querySelectorAll('.msg.me').length>=1", "the first transcript in the log", 60):
            await said_right(pg, "Live, one conversation")
            # the reply event reaches the page at once and its text is shown; the sound follows when its first part has been
            # synthesized (a few seconds): Loading until then, in the same call that is still running
            t0 = time.time()
            spoken = loop.run_in_executor(None, inst.reply, ANSWER)
            first = await pg.wait("(function(){var s=" + STATE + ";return s==='loading'||s==='speaking'?s:''})()", 30, 0.1)
            if note(first == "loading", "reached: loading, before any sound (the state was %r)" % first):
                await asyncio.sleep(0.9)                                      # the orb's colours and the label have settled
                note(await pg.ev(BUTTON) is True, "the Interrupt work button is shown while the reply loads")
                await shot(pg, "16_live_loading_" + SHOT_LANG)
            note(await spoken == 200, "the reply was synthesized and posted (%.1f s after its text)" % (time.time() - t0))
            if await reached(pg, STATE + "==='speaking'", "speaking", 60):
                await asyncio.sleep(1.6)
                await shot(pg, "05_live_speaking_" + SHOT_LANG)
            # the reply is played and Live listens again: a helper in the background
            if await reached(pg, STATE + "==='listening'", "listening again after the reply", 60):
                await shoot_helper(pg, inst)

    # thinking after one spoken sentence (a session of its own: the log holds the sentence and the typing bubble and nothing is cut off
    # at the top): the typing bubble, then what the session is doing, then a command that runs
    async with E.Session(inst, fx["live"], lang=SHOT_LANG, loop=False) as pg:
        await phone(pg, 390, 844)
        await pg.click("#livebtn")
        if await reached(pg, STATE + "==='thinking' && document.querySelectorAll('.msg.me').length>=1", "thinking", 60):
            await asyncio.sleep(1.2)
            await said_right(pg, "thinking")
            note(await pg.ev("document.querySelector('.typing')===document.getElementById('log').lastElementChild"), "the typing bubble is the last child of the log")
            await shot(pg, "04_live_thinking_" + SHOT_LANG)
            if await progress_line(pg, inst, {"kind": "read"}, "the progress line"):      # the hook's call is made by the test
                await asyncio.sleep(0.6)
                await shot(pg, "15_live_thinking_progress_" + SHOT_LANG)
                await shoot_interrupt(pg, inst)

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
                v = await pg.ev("(function(){var b=document.getElementById('interrupt'),r=b.getBoundingClientRect();"
                                "return !b.hidden&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight})()")
                note(v is True, "%dx%d: the Interrupt work button is shown and inside the screen while thinking" % (w, h))
                if w == 320:
                    await sideways(pg, "320x568, Live thinking")
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
    # the file starts when the page opens the microphone, and the voice detector needs a few seconds to load: the sentence must not
    # begin before it listens (it would lose its first words)
    E.write_wav(fx["live"], E.silence(6) + speech48 + E.silence(3))
    E.write_wav(fx["loop"], E.silence(6) + speech48 + E.silence(60))
    E.info("speech sample: %.1f s" % (len(speech48) / 48000))
    await run_flow(inst, fx)
    E.info("paid API calls in this run: %d recognitions, %d syntheses" % (sum(1 for l in inst.log if '"POST /api/utterance' in l),
                                                                         sum(1 for l in inst.log if '"POST /internal/reply' in l)))
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
    if os.environ.get("SHOT_DOCS"):
        if SHOT_LANG != "en":
            note(False, "SHOT_DOCS needs the English UI (SHOT_LANG=en)")
        else:
            try:
                write_docs(os.path.abspath(os.environ["SHOT_DOCS"]))
            except ImportError as e:
                note(False, "SHOT_DOCS needs Pillow", repr(e))
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
