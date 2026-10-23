# Changelog

## 1.1.0 (2026-10-23)

This release makes a voice conversation feel faster and puts you back in control while Claude is working.

### New

- **Stop Claude mid-task.** An **Interrupt work** button appears while Claude is working or speaking. It stops the speech and ends Claude's current turn, the same as pressing Escape in the terminal. You can also just say it: a phrase that starts with "stop" (or the Russian "стоп" / "остановись") interrupts the work, and the rest of the phrase reaches Claude as your next message, for example "Stop, I meant the other server."
- **Answers start within seconds.** Replies are now spoken in parts. The first sentence plays as soon as it is ready (in our tests sound started after about 4 to 5 seconds instead of 30 to 40 for a long answer), and the next part is fetched while the current one plays. Until the sound starts, the app says **Loading…**.
- **See helpers working in the background.** When Claude hands work to helper agents, the progress line keeps showing that they are busy ("A helper is working in the background", "Helper: running a command") even after Claude itself has gone quiet, and clears when they finish.
- **How it was said (experimental).** The speech recognizer can add a short hint such as "unsure", "irritated", "another voice" or "background media". Claude treats it as a hint that may be wrong, and a hint that the words may not be yours makes it more careful. The default recognition model does not produce these hints; set `VOICE_STT_MODEL=google/gemini-3.5-flash` if you want them (slower and more expensive per phrase, see the README).

### Changed

- The big button says **End conversation** instead of **Stop**, so it is not confused with **Interrupt work**.
- The separate **Stop audio** button is gone: tap the orb, press **Interrupt work** or say "stop".
- **Speak replies** is now a small switch in the corner of the screen.

### Fixed

- A failed speech recognition is now written to the log with its reason (an HTTP status or an error type) and how long it took. The audio, the text and the server's answer are still never logged.

### Upgrading

1. Pull the new code and run `sudo bash deploy.sh`.
2. Restart your Claude Code session with the voice channel (`bash restart_main_session.sh`, then confirm the development-channel prompt in tmux). The interrupt, the helper status and the hints live in the channel server and the session hooks, which are loaded only when the session starts.
3. Close the Voice app and open it again from the bot's menu.

**Interrupt work** needs the Claude Code session to run inside tmux (the restart helper starts it that way). Without tmux the button still stops the speech, but cannot stop Claude's turn.

## 1.0.0 (2026-10-23)

First public release: a Voice button in the official Telegram plugin's bot that opens a Mini App for hands-free conversation with a Claude Code session. Live mode with automatic end-of-phrase detection, push-to-talk, spoken and on-screen replies with a text copy in the chat, tap to confirm risky actions, live progress, Telegram voice notes, replay after a session restart, secret redaction, an optional session watchdog, and sandboxed services.
