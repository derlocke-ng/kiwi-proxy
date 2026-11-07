.PHONY: run gui images smoke test leak lint fmt setup
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

# Build the gateway image and start it both ways kiwi-proxy does, against a dummy
# SOCKS5 (tests/smoke/gateway.sh) — what ci.yml does, from a clean cache there.
# A distinct tag, so a working kiwi-proxy/gateway:latest is left alone.
smoke:
	podman build $(BUILD_FLAGS) -t kiwi-proxy/gateway:smoke -f containers/gateway/Containerfile containers/gateway
	bash tests/smoke/gateway.sh kiwi-proxy/gateway:smoke

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
