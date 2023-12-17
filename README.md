<div align="center">
<img width="60px" src="https://pts-project.org/android-chrome-512x512.png">
<h1>PiRogue CLI</h1>
<p>
PiRogue CLI is the main command line interface allowing you to control and configure your PiRogue. Have a look to our guides to <a href="https://pts-project.org/guides/" alt="Learn more about PiRogue">learn more how to use the PiRogue</a>.
</p>
<p>
License: GPLv3
</p>
</div>

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
pirogue-intercept-gated --help
pirogue-view-tls --help
```


## Developer setup

For easier hacking, you can run the scripts without `pip install`ing them
prior through the equivalent endpoints:

```bash
python -m pirogue_cli.cmd.cli --help
python -m pirogue_cli.network.intercept_gated --help
python -m pirogue_cli.network.view_tls --help
```