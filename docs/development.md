# Development

This page is for people who change kiwi-proxy: how to run it from a checkout,
which tests exist, what CI checks, and how a release is made.

## Run it from a checkout

```bash
make setup                  # a .venv with pydantic, pytest, ruff, jinja2 and pyyaml
make run ARGS="list"        # the command, from src/
make gui                    # the app, from src/
make images                 # build kiwi-proxy/gateway:latest from containers/gateway
```

`make setup` creates the virtual environment with `--system-site-packages`, so
the app can use the system's PyGObject, GTK 4 and libadwaita.

## Tests

| Command | What it tests | Needs |
|---|---|---|
| `make test` | The unit tests in `tests/unit`: the command line, gateway specs, DNS, snapshots, providers, the app's windows | Python only. The app tests need a display (CI uses Xvfb). Two tests need the `podman` command. |
| `make lint` | `ruff check` and `ruff format --check` over `src`, `tests` and `containers` | `make setup` |
| `make smoke` | Builds the gateway image as `kiwi-proxy/gateway:smoke` and starts it against a test SOCKS5 proxy, with and without a host port (`tests/smoke/gateway.sh`) | rootless Podman |
| `make leak ARGS="--exit NAME"` | Probes a running gateway from inside: what is dropped, what leaks, what the resolver answers (`tests/leak`) | a running exit |

`tests/unit/test_server_module.py` renders a kiwi-server host with
kiwi-server's own renderer. It runs when a kiwi-server checkout lies beside
this repository, or when `KIWI_SERVER_SRC` names one, and is skipped otherwise.

`make fmt` formats the code and fixes what ruff can fix.

## CI

`.github/workflows/ci.yml` runs on every push and pull request:

- **test**, on Ubuntu 24.04: installs Python 3.12, PyGObject, GTK 4,
  libadwaita and Xvfb, checks out kiwi-server for the server module test, runs
  ruff and then the unit tests under Xvfb.
- **gateway-image**, on GitHub's Ubuntu runner: checks the shell scripts'
  syntax, builds the gateway image without a cache, and runs
  `tests/smoke/gateway.sh` with rootless Podman.

The leak tests are not run in CI.

## Releases

A release is a signed tag. kiwi installs the newest version tag of an app, and
it updates a system app without a password only to a tag signed by the key it
pinned for that app. The maintainer therefore makes and signs the tag; CI
holds no signing key.

1. Set the new version in `kiwi.manifest` (`VERSION=`), `pyproject.toml`,
   `src/kiwi_proxy/__init__.py` (`__version__`) and
   `server-module/kiwi-proxy/module.yaml`. `tests/unit/test_release.py` fails
   when they disagree.
2. Add a section `## X.Y.Z` to
   [CHANGELOG.md](https://github.com/derlocke-ng/kiwi-proxy/blob/main/CHANGELOG.md).
3. Tag and push:

   ```bash
   git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
   ```

`.github/workflows/release.yml` then checks that the tag is annotated, signed
by a key in `.github/allowed_signers`, equal to the version in `kiwi.manifest`
and newer than every earlier release. It publishes a GitHub release with the
changelog section as its notes.

The gateway image for kiwi-server machines,
`ghcr.io/derlocke-ng/kiwi-proxy/gateway`, is built and pushed by
`.github/workflows/images.yml` for every pushed `v*` tag. It can also be run
by hand on GitHub (**Run workflow**). A desktop does not need this image:
`kiwi-proxy setup` builds its own.

The documentation in `docs/` reaches kiwi-network.eu with the next release
tag. Run the documentation checker before you tag:

```bash
python3 .claude/skills/kiwi-docs/scripts/check-docs.py .
```
