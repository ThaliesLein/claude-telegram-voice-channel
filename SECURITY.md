# Security

## Threat model in short

Voice Channel lets a person speak to a Claude Code session that can act on the machine it runs on. That makes the microphone a way to give instructions to that machine, so the design assumes the worst about what comes in through it.

- **Voice is untrusted input.** The speaker is not authenticated. The words may come from someone near the phone, a video, a call, a recording, or a recognition mistake. A transcript is cleaned before Claude sees it (control and invisible characters removed, tag-like text neutralized, length capped) and is marked as coming from an unverified speaker. The recognizer's hints about how something was said (unsure, joking, another voice, background media and so on) pass only as names from a fixed list, never as text: they can make Claude more careful and never grant anything.
- **What voice alone may do.** Claude is instructed that by voice alone it may talk, answer questions, do read-only work and make local, reversible changes inside git repositories.
- **What needs a typed confirmation.** Everything else (pushing, deploying, restarting services, deleting data, spending money, installing software, changing settings, permissions or the voice channel itself, anything involving secrets) waits for a message typed in Telegram or in the terminal. A spoken "yes" never counts. The one exception is a tap on the **Confirm** button of a confirmation card in the app, which needs a login that is less than an hour old and counts for that one action only.
- **This is an instruction to the model, not a technical barrier.** The permissions of the Claude Code session itself still decide what it can do. Whoever can speak into the page can talk to your session, so keep `VOICE_ALLOWED_USER` limited to yourself and keep the session's own permissions tight.
- **Access to the page.** Every request carries data signed by Telegram. The server verifies it with the bot token, refuses data that is too old, and accepts exactly one Telegram user id. If no user id is configured, every request is refused.
- **Exposure.** `voice-web` listens on 127.0.0.1 only. A Cloudflare quick tunnel is the only way in from the internet, and Cloudflare terminates the encrypted connection. The internal API used by the channel server accepts loopback connections with a secret token only.
- **Sandboxing.** The services run as throw-away unprivileged users with no capabilities, a read-only filesystem, no access to `/root` or `/home`, a system call filter and no access to private networks.
- **Data that leaves the machine.** Audio goes to OpenRouter (the speech provider), reply text goes there for speech synthesis, and a text copy of the conversation goes to your Telegram chat unless you turn that off. Anything that looks like a key or token is replaced with "[redacted]" before it leaves, as a safety net; it is not a guarantee.
- **Retention.** Reply audio is kept for one hour and at most 20 files; the log of what was said is kept for 7 days by default.

## Kill switch

Create the file `/var/lib/voice/DISABLED` (for example `sudo touch /var/lib/voice/DISABLED`). From that moment every request from the page is answered with "voice input is disabled" (HTTP 503). No restart is needed. Delete the file to resume. To stop everything, you can also run `sudo systemctl stop voice-web voice-tunnel` and end the Claude Code session's voice channel by restarting the session without it (`restart_main_session.sh --no-voice`).

## Reporting a problem

Please do not open a public issue for a security problem. Open a private security advisory on GitHub (the **Security** tab of this repository, then **Report a vulnerability**) and describe what you found, how to reproduce it and what you expect the impact to be.

The developer notes in [`CLAUDE.md`](CLAUDE.md) describe every security rule in detail, and the tests in `tests/` pin each of them.
