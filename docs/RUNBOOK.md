# RedApple runbook

## Setup

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

Runtime is stdlib-only; dev extras add pytest, coverage, mypy, and ruff.

## Gates

```sh
make lint        # ruff check ra tests scripts
make typecheck   # mypy --strict ra
make test        # unit + golden + injection
make coverage    # pytest --cov + scripts/check_coverage.py floors
make golden      # golden gate for bug_class
make doctor      # environment/layout check
make load        # 50k crash load harness (explicit; writes tests/load/results/load_report.json)
```

Coverage floors are enforced by `scripts/check_coverage.py`: overall line rate plus per-package floors for ledger/policy/groom/joins.

## CLI

```sh
ra doctor --layout
ra run --mode macos --db .redapple/ledger.sqlite
ra attach --udid DEVICE --tier C --build 26.0 --ring-node NODE --db .redapple/ledger.sqlite
ra retain --sweep --db .redapple/ledger.sqlite
ra replay --queue .redapple/press-replay.jsonl --check
ra golden --type bug_class --check
```

Errors are emitted as JSON on stderr (`{"error": "...", "message": "..."}`) and exit 2 for user/config errors; unexpected exceptions should not reach the CLI.

## Load harness

`tests/load/harness.py` replays synthetic crashes through `FakeLane`, compiles PRESS packets, writes claims to the ledger, ranks candidates, and dispatches work orders. It reports triage/compile/tick/ledger-submit/ledger-commit SLOs, RSS, queue depth, and SQLite busy count.

Thresholds: ledger commit p99 <= 3 ms, compile p99 <= 8 ms, tick p99 <= 5 ms, RSS < 1536 MiB, SQLite busy == 0.

## Troubleshooting

- `ra doctor --layout` checks repo layout (`grammars`, `schemas`, `migrations`, `models`, `tests/*`, `redapple.toml`). In a source checkout all must be present; `tests/fixtures/.gitkeep` keeps the fixtures directory tracked.
- `FORMAT_FAIL` from `replay` means the queue has malformed JSON or invalid records; inspect the JSONL file.
- `FORMAT_FAIL` from `golden` means the golden file is missing/unreadable or the task type is unknown.
- `FORMAT_FAIL` from `attach --ring-node` means the ring node does not exist in the ledger.
- If `make load` fails only the ledger SLO, inspect `tests/load/results/load_report.json` mailbox stats and commit samples before changing batching.
