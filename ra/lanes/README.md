# RED APPLE lane adapters

This package implements the Appendix C `Lane` protocol and the RA-LAN
requirements that can be enforced without hardware.

## Shared enforcement (`base.py`)

- `feed` is bounded by `feed_timeout_s` (30 s by default); a timeout raises
  `LaneError(HANG)` with a synthetic `CrashRef` instead of blocking (RA-LAN-011).
- `collect_crashes` must precede `reset`; the adapter asserts the ordering and
  rejects post-reset collection (RA-LAN-007).
- `serious` thermal pauses new work; `critical` drains the lane and releases a
  bound UDID lease once (RA-LAN-008).
- Lane failures raise only Appendix H `LaneErrorCode` values.
- Crash refs default to `context:app` until a Tier A run proves daemon reach
  (RA-LAN-010).

## Adapters

- `macos/`: tart macOS VM lane. Host needs `tart` and the VM image; the guest
  needs the pinned Xcode (`xcodes`), `sccache`, and a WebKit checkout for the
  `build-webkit --jsc-only` fast path.
- `ios/`: Tier C physical-device lane. Implements the RA-LAN-002 attach
  automaton and the RA-LAN-005 `JavaScriptCore.framework` embed ordering.

## Device-gated matrix

| Area | Runs here (fakes/unit tests) | Needs station/device |
|---|---|---|
| Lane protocol contract | yes | no |
| iOS attach automaton order | yes | no |
| Provisioning gap cards / `needs_hand` | yes | no |
| macOS tart control flow | yes (fake runner/controller) | real `tart` VM |
| WebKit `--jsc-only` build | command wiring only | guest Xcode/WebKit/sccache |
| iOS identify/trust/DDI/sign/install/probe | fake client only | iPhone + libimobiledevice/pymobiledevice3 + signing |
| Tier C JSC feed | fake transport only | on-device JSC harness (`JscTransport`) |
| RA-LAN-009 90 s attach p95 | not measured | provisioned device |
