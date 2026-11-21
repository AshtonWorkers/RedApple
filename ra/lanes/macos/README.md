# macOS VM lane

`MacOSVMLane` drives a tart macOS VM through `TartVMController`.

## Host side

`provision` checks only host prerequisites:

- `tart` is installed and `tart --version` / `tart list` succeed.
- The configured VM image exists in `tart list` (default `redapple-macos`,
  overridable via `DeviceProfile.metadata["vm_name"]`).

Missing host tools or a missing image emit one `HumanCard` and park the
profile in `needs_hand` (RA-LAN-003).

## Guest side

Guest provisioning is checked at `launch` because the VM is the execution
environment:

- required guest tools (`xcodebuild`, plus `xcodes` when
  `pinned_xcode_version` is set, plus `sccache` when enabled);
- pinned Xcode selection through `xcodes installed` / `xcodes select`;
- `sccache --show-stats` when `sccache=True`;
- `Tools/Scripts/build-webkit --jsc-only` when the harness requests
  `build_webkit` (default on) and `webkit_dir` is configured. `WK_USE_SCCACHE=YES`
  is exported for the build.

Guest gaps emit one card and raise `NOT_PROVISIONED` with the profile parked in
`needs_hand`.

## Feed / crashes / reset

- `feed` runs the harness argv through `tart exec`, pipes bytes to stdin, and
  maps exit codes: `0` → `ACCEPTED`, codes in
  `harness.metadata["saturated_return_codes"]` (default `{75}`) → `SATURATED`,
  anything else → `REJECTED`.
- `collect_crashes` reads recent `DiagnosticReports` (`.ips`/`.crash`) from the
  guest and returns `CrashRef`s with `context:app`.
- `reset` stops the tart VM; the next launch restarts it.

## What is device/station-gated here

This lane is unit-tested with a fake `CommandRunner`/`TartVMController`. A real
run needs a station with tart, a pinned macOS VM image, Xcode (via `xcodes`),
sccache, and a WebKit checkout; the 90 s attach budget (RA-LAN-009) can only be
measured there.
