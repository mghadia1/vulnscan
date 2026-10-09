PYTHON ?= python3.14
VENV := .venv
BIN := $(VENV)/bin
IMAGE := vulnscan:local
# What `make scan` scans.
TARGET ?= .

.PHONY: install lint format typecheck test check scan update lookup image smoke

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)

install: $(BIN)/python
	$(BIN)/python -m pip install -e '.[dev]'

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format:
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck:
	$(BIN)/mypy

test:
	$(BIN)/python -m pytest -q

# Everything CI runs before the Docker job.
check: lint typecheck test

# Scans TARGET with the working tree's code. PYTHONPATH=src rather than the
# editable install: in an iCloud-synced folder macOS marks everything in
# .venv hidden, and Python 3.13+ skips hidden .pth files.
scan:
	PYTHONPATH=src $(BIN)/python -m vulnscan scan $(TARGET)

# OSV's advisories for PyPI, npm and Go, into ~/.cache/vulnscan (the only
# command that uses the network).
update:
	PYTHONPATH=src $(BIN)/python -m vulnscan update

# make lookup Q="PyPI django 3.2.18" (exit code 1 means affected; make
# ignores it here)
lookup:
	-PYTHONPATH=src $(BIN)/python -m vulnscan lookup $(Q)

image:
	docker build -t $(IMAGE) .

# The image against a fixture: mounted read-only, with no network.
smoke: image
	./scripts/smoke.sh $(IMAGE)
