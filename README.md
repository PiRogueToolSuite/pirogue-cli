Pirogue-CLI
===========

## Local installation in a virtual environment

```
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip setuptools wheel
./.venv/bin/pip install .
```


## Usage from a local virtual environment

```
./.venv/bin/pirogue-ctl --help
./.venv/bin/pirogue-intercept-tls --help
./.venv/bin/pirogue-view-tls --help
```


## Developer setup

```
./.venv/bin/python -m pirogue-ctl --help
./.venv/bin/python -m pirogue_cli.network.intercept_tls --help
./.venv/bin/python -m pirogue_cli.network.view_tls --help
```
