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

## Device-gated verification checklist (RedApple QA bot)

Run these on the real macOS/iOS station; fake-runner tests are not proof of
device behavior.

- [ ] **macOS tart host/VM**: `tart --version`, `tart list`, `tart get`,
  `tart run --no-graphics`, `tart exec`, `tart stop`, and process reaping all
  work against the pinned VM image; `start` reaches `Running` within timeout.
- [ ] **macOS guest tools**: `xcodes installed` contains the pinned Xcode,
  `xcodes select` succeeds, `sccache --show-stats` is healthy, and
  `xcodebuild -version` runs inside the guest.
- [ ] **macOS WebKit fast path**: `build-webkit --jsc-only` runs in the
  configured WebKit checkout with `WK_USE_SCCACHE=YES` / `DEVELOPER_DIR`
  exports; failures surface as `HARNESS_REJECTED`.
- [ ] **macOS feed/crash/thermal**: feed argv/env through `zsh -lc`, return
  codes map to `ACCEPTED`/`SATURATED`/`REJECTED`, crash collection finds
  `.ips`, and `pmset -g therm` maps to `NOMINAL`/`SERIOUS`/`CRITICAL`.
- [ ] **iOS attach automaton**: `idevice_id`, `ideviceinfo`, `idevicepair
  validate`, and `pymobiledevice3 mounter auto-mount` work on a physical
  iPhone with Trust and Developer Mode enabled.
- [ ] **iOS sign/install/renew**: configured install/sign commands produce a
  valid harness install, `signing_expires_ms` is tracked, renewal runs before
  expiry, and renewal-budget exhaustion emits one `HumanCard`.
- [ ] **iOS probe/JSC transport**: capability probe exposes
  `javascriptcore`/`dlopen`/`context_app`; the real `JscTransport`
  `open`/`eval`/`close` path feeds JavaScriptCore on device.
- [ ] **iOS crashes/reset/lease**: crash collection reads `.ips`/`.crash`/
  `.panic`, reset works after collection, critical thermal drains and
  releases the UDID lease once, and RA-LAN-009 attach p95 is measured.
