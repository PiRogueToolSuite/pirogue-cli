Pirogue-CLI
===========

## Local installation in a virtual environment

```bash
git clone https://github.com/PiRogueToolSuite/pirogue-cli
cd pirogue-cli
python3 -m venv .venv
source .venv/bin/activate   
pip install --upgrade pip setuptools wheel
pip install .
```


## Usage from a local virtual environment

You can run the scripts from the local virtual environment:

```bash
pirogue-ctl --help
pirogue-intercept-tls --help
pirogue-view-tls --help
```


## Developer setup

For easier hacking, you can run the scripts without `pip install`ing them
prior through the equivalent endpoints:

```bash
python -m pirogue_cli.cmd.cli --help
python -m pirogue_cli.network.intercept_tls --help
python -m pirogue_cli.network.view_tls --help
```