Pirogue-CLI
===========

## Local installation in a virtual environment

```
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip setuptools wheel
./.venv/bin/pip install .
```


## Usage from a local virtual environment

You can run the scripts from the local virtual environment:

```bash
./.venv/bin/pirogue-ctl --help
./.venv/bin/pirogue-intercept-tls --help
./.venv/bin/pirogue-view-tls --help
```


## Developer setup

For easier hacking, you can run the scripts without `pip install`ing them
prior through the equivalent endpoints:

```bash
./.venv/bin/python -m pirogue_cli.cmd.cli --help
./.venv/bin/python -m pirogue_cli.network.intercept_tls --help
./.venv/bin/python -m pirogue_cli.network.view_tls --help
```
