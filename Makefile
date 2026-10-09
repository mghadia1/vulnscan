PYTHON ?= python3.14
VENV := .venv
BIN := $(VENV)/bin
IMAGE := vulnscan:local
# What `make scan` scans.
TARGET ?= .

.PHONY: install lint format typecheck test check scan image smoke

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

image:
	docker build -t $(IMAGE) .

# The image against a fixture: mounted read-only, with no network.
smoke: image
	./scripts/smoke.sh $(IMAGE)
