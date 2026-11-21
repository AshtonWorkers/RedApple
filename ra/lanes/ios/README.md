# iOS lane adapters

This package implements the RED APPLE v0.3 iOS attach automaton and Tier C
lane protocol surface.

## What runs without hardware

- `IOSTierCLane` automaton ordering: identify → trust/dev-mode → DDI mount →
  sign/install → capability probe → tier assign.
- Provisioning gaps emit one `HumanCard` and park in `needs_hand`.
- Signing renewal before expiry (RA-LAN-006: re-issue at 6 days, cron at
  5d20h — modeled as renewal once less than 28 h remains on a 7-day signing),
  with bounded renewal attempts; renewal failure emits a card and parks the
  device in `needs_hand`.
- Crash collection before reset, thermal gating, feed timeout → `HANG`.

## What needs a device

- `idevice_id`, `ideviceinfo`, `idevicepair`, `idevicediagnostics`:
  libimobiledevice tools plus a trusted, Developer-Mode-enabled iPhone.
- `pymobiledevice3 mounter auto-mount`: personalized DDI mount.
- Real sign/install/probe commands: the station must configure
  `install_command`, `sign_command`, and `probe_command` on
  `LibimobiledeviceIosAttachClient`.
- `JscTransport`: a device-side JavaScriptCore harness that opens the
  on-device `JavaScriptCore.framework` with `dlopen`, sets JIT options via
  `setenv` before first context init (RA-LAN-005), evaluates submitted bytes,
  and returns `ACCEPTED | REJECTED | SATURATED`.

`jsc_embed_main.m` is reference Objective-C source for the embed ordering;
it is not compiled by the Python package.

## Tiers

- Tier A: Corellium virtual device (not implemented in this PR).
- Tier B: physical device with jailbroken/debuggable runtime (not implemented
  in this PR).
- Tier C: physical device with embedded JavaScriptCore.framework, findings
  tagged `context:app` until a Tier A daemon is reachable.
