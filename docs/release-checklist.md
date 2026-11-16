# Release Checklist: Calls and Screen Sharing

This is the manual part of SPEC-03 test T-57 (with amendment A2), done for every release of the desktop app and the web client that changes calls, screen sharing or the desktop shell. The automated parts run in CI: the shell's decision-function tests and static checks (`cargo test -p accord-desktop`), and the voice integration tests against the real relay (`npm run test:voice`, job "Voice Integration (SPEC-03)").

Record the results in the release notes (`CHANGELOG.md`), one table per release. The platform statements in README.md, SECURITY.md, docs/architecture.md, docs/api-reference.md, docs/user-guide.md and website/index.html follow these results, not expectations (SPEC-03 REQ-28 (b)).

## 1. Probes and a manual share, on each platform

For each platform, record what the app reports (the Share Screen control, and whether a shared screen can be watched) and do one manual share between two machines:

| Platform | Expected |
|---|---|
| Linux, GNOME on Wayland | The desktop portal's picker opens; the share is watched on the other machine. |
| Linux, KDE Plasma on Wayland | The desktop portal's picker opens; the share is watched on the other machine. |
| Windows | The WebView2 picker opens; the share is watched on the other machine. |
| macOS | Share Screen shows "Screen sharing isn't available here: this app can't capture the screen"; watching a share from another machine works. |
| Web client (each supported browser) | The browser's picker opens, or the control says why sharing is unavailable; watching works where the browser can decode VP8. |

## 2. Sharing while Accord is hidden, on each platform that can share

Share a moving source (for example a video playing in another window) for 60 s with the Accord window minimized, then for 60 s with it fully covered by another window. Record:

- the frame rate at the viewer (expected: at least 5 frames per second);
- whether the app read frames with Source A (a track processor) or Source B (its own preview; the sharing status then says sharing may pause while Accord is hidden).

## 3. Delay over a real uplink, on each platform that can share (A2)

Over a real network uplink (not loopback), record:

- **Audio delay while sharing.** The delay of the sharer's audio at a listener while sharing a screen with frequent large changes, compared with the same call without sharing. Target: at most 500 ms more than without sharing.
- **Age of drawn frames on a slow link.** The age of the frames a viewer on a slow downlink (slower than the share) draws, from when the sharer's screen showed them. Target: at most 3 s, or the tile says that no video arrives.

One way to measure both: share a window showing a clock synchronized with the viewer's clock (NTP on both machines), and compare the clock in the viewer's tile with the viewer's own clock; for audio, play a click at known clock times on the sharer and record when the listener hears it.

These depend on link speed and kernel buffers, not only on Accord (SPEC-03 §14.2), so they are measured here rather than asserted in CI. CI asserts what Accord controls: the client hands fragments to its socket only while at most 64 KiB is queued, every audio frame reaches the relay in order, and the bitrate steps down and back up as the uplink allows (T-47); every fragment reaches a slow viewer's link at most 2 s after the relay received it plus the time the relay's unsent data (`TCP_NOTSENT_LOWAT`, 32 KiB, plus up to two fragments) and the link's 64 KiB buffers take at the link's rate, and every drawn frame is at most that old (T-51). The CI job caps only the kernel's receive buffers and leaves send buffers large, so these bounds, and RG-SCR-8's bound on the bytes in transit while a viewer stops reading, fail if the relay does not set `TCP_NOTSENT_LOWAT`; the option itself is checked on both of the relay's listeners by `server/tests/spec03_notsent_lowat_test.rs`. The tests print the delays they measure on the throttled loopback link, for comparison.

**Results that miss a target go into the release notes. They do not block the release.**

Also note, for the relay platform used: whether the relay logged at startup that `TCP_NOTSENT_LOWAT` is unavailable (it is set on Linux and macOS; see docs/SELF-HOSTING.md, "Voice and Screen Sharing").

## Results template

| Platform | Probes and manual share (§1) | Hidden window: frames per second, source (§2) | Audio delay while sharing, vs. not sharing (§3) | Oldest drawn frame on a slow link (§3) | Notes |
|---|---|---|---|---|---|
| Linux GNOME Wayland | | | | | |
| Linux KDE Wayland | | | | | |
| Windows | | | | | |
| macOS | (viewing only) | — | — | | |
| Web: … | | | | | |
