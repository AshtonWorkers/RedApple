.PHONY: test lint format typecheck coverage golden load

PYTHON ?= python3.12

test:
	$(PYTHON) -m pytest tests/unit tests/golden tests/injection tests/test_*.py

lint:
	ruff check ra tests scripts

format:
	ruff format ra tests scripts

typecheck:
	mypy --strict ra

coverage:
	$(PYTHON) -m pytest tests/unit tests/golden tests/injection tests/test_*.py --cov=ra --cov-report=term-missing --cov-report=xml:coverage.xml
	$(PYTHON) scripts/check_coverage.py coverage.xml

golden:
	$(PYTHON) -m ra.cli.main golden --type bug_class --check

load:
	rm -f .redapple/load.sqlite tests/load/results/load_report.json
	$(PYTHON) tests/load/harness.py --crashes 50000 --rate 200 --out tests/load/results/load_report.json
