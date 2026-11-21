.PHONY: test lint format typecheck coverage

PYTHON ?= python3.12

test:
	$(PYTHON) -m pytest tests/unit

lint:
	ruff check ra tests scripts

format:
	ruff format ra tests scripts

typecheck:
	mypy --strict ra

coverage:
	$(PYTHON) -m pytest tests/unit --cov=ra --cov-report=term-missing --cov-report=xml:coverage.xml
	$(PYTHON) scripts/check_coverage.py coverage.xml
