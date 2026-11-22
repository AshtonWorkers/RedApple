# RedApple for macOS

A native SwiftUI macOS application, not a browser wrapper. Discovery is the home screen: start/stop the integrated `ra.app_engine` discovery engine, watch its progress and DeepSeek assessments, then triage the resulting leads. Apple patch intelligence and bounty categories provide research context.

Requires **macOS 13 or later** and **Xcode 15+ / Swift 5.9+**. The app itself does not need Python, a local web server, npm, or a browser. Launching the discovery engine additionally needs its documented Python/build dependencies.

## Build and run

From the repository root on a Mac:

```sh
swift test --package-path macos
bash macos/build-app.sh
open macos/dist/RedApple.app
```

`build-app.sh` compiles a release executable, bundles SwiftPM resources into a real `RedApple.app`, ad-hoc signs it, verifies its signature, and produces `macos/dist/RedApple-macOS.zip`. Build output targets the build Mac's architecture, not a universal binary. It is not Developer ID signed or notarized; local builds are the simplest way to run it. Distribution to other Macs needs normal Developer ID signing/notarization.

For development, open `macos/Package.swift` in Xcode and run the `RedApple` executable scheme, or use `swift run --package-path macos RedApple`. `swift build --package-path macos` also compiles the application. No Xcode project generator is needed.

The **Native macOS App** GitHub Actions workflow compiles the SwiftUI executable, runs the core tests, builds/verifies the `.app`, and uploads its ZIP as the `RedApple-macOS` artifact. CI does not exercise the desktop UI.

## Connect the discovery engine

The integrated Python engine lives in this repository as `ra/app_engine` and is backed by the hardened `ra` core: campaign orchestration and corpus scheduling drive fuzzing, crash exploitability triage grades leads, and chain/escalation reasoning feeds discovery leads.

1. Install the Python dependencies from the repository's `pyproject.toml` (or use the repository virtual environment).
2. Open **RedApple → Settings**. Choose the repository containing `ra/app_engine/__main__.py` and set the Python 3 executable (for example, the repository virtual environment).
3. Save a DeepSeek API key to macOS Keychain, or launch RedApple from an environment that already supplies `DEEPSEEK_API_KEY`. Keys are not saved in workspace files or UserDefaults.
4. Choose the same workspace as the engine. Defaults to `REDAPPLE_HOME`, or `~/Library/Application Support/RedApple`; a directory chosen in Settings takes precedence on subsequent launches.
5. Click **Start Discovery**. The app invokes the selected Python directly, without a shell: `python -m ra.app_engine run --time-budget <seconds> --json`. Build time is additional to the fuzzing budget. **Stop** invokes `stop --json` in the same repository/workspace. Closing RedApple does not deliberately stop a run; use Stop before quitting when desired.

The engine is responsible for run locking and cleanup. Output goes to `native-engine.log`; live status and lead files reload every five seconds and when the app becomes active. Reported status is not proof a process is still alive. Engine files and diagnostic artifacts are never executed by the viewer. The app only reveals artifacts in Finder.

### Shared files (engine owns these; app reads only)

| Path relative to workspace | Purpose |
| --- | --- |
| `discovery/status.json` | `schema_version: 1`, `state`, `run_id`, `model`, `updated_at`, `message`, `executions`, `crashes`, `leads` |
| `discovery/leads.json` | Array of `{id, title, component?, summary?, assessment?, rating?, created_at?, run_id?, artifact_path?, category_id?}` |
| `discovery/triage/<crash_id>.json` | Full diagnostic artifact, revealed in Finder |
| `leads.json` | Original workbench leads: `{kind,target,status,notes,updated_at,origin?}`; `origin: webkit-discovery` mirrors are hidden to avoid duplicates |
| `releases.json` | Optional original workbench patch cache, imported on first load |

The native app writes only `native-patches.json`, `native-triage.json`, and its launcher log. Triage statuses/notes are app-local overlays and never overwrite the engine's or web workbench's lead store. Writes are atomic with owner-only permissions. If an engine file is temporarily unreadable, the last good data remains visible and a warning is shown.

## Patch intelligence

The Swift core ports the Python workbench's release/advisory parsing, version-pair enrichment, and outcome/platform-scoped bounty classifier. Its bundled JSON snapshots come from PR #1 (`11ae872`), unchanged; no dependency on that PR being merged. Refresh checks the latest 20 releases on Apple's [security releases index](https://support.apple.com/en-us/100100), retains older history, and preserves cached advisory entries/build metadata on errors. The initial bundled snapshot and its fetch date are explicitly labeled.

The category catalog is a dated snapshot, not a live eligibility service. Each matched amount is labeled **Category max**, not a CVE's value. Unmapped outcomes do not show a made-up $0 reward. Apple's [current bounty categories](https://security.apple.com/bounty/categories/) and demonstrated results determine eligibility; a patched CVE and a model's assessment are not themselves payable findings.

## Verification limits

This implementation was authored on Linux: no native macOS launch, visual UI check, Keychain prompt, engine start/stop integration on macOS, Gatekeeper behavior, or actual Apple submission has been verified here. The macOS CI job covers compilation, core tests, bundle structure, and ad-hoc signature verification only. Engine fixtures in unit tests are contract tests, not real discovery results.

Core tests cover the original snapshot/catalog, platform-scoped classification, parsing, failed-refresh cache preservation, private atomic persistence, and shared-engine schema/deduplication.
