.PHONY: run gui images test leak lint fmt setup
PY := $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
export PYTHONPATH := src:.

setup:
	python3 -m venv --system-site-packages .venv
	.venv/bin/python -m pip install -q --upgrade pip
	.venv/bin/python -m pip install -q pydantic pytest ruff jinja2 pyyaml

run:
	$(PY) -m kiwi_proxy $(ARGS)

gui:
	$(PY) -m kiwi_proxy.ui

images:
	podman build -t kiwi-proxy/gateway:latest -f containers/gateway/Containerfile containers/gateway

test:
	$(PY) -m pytest tests/unit -q

leak:
	$(PY) -m pytest tests/leak -q $(ARGS)

lint:
	.venv/bin/ruff check src tests containers
	.venv/bin/ruff format --check src tests containers

fmt:
	.venv/bin/ruff format src tests containers
	.venv/bin/ruff check --fix src tests containers
