from setuptools import find_packages, setup

setup(
    name="pirogue-cli",
    version="1.0",
    author="U+039b",
    author_email="hello@pts-project.org",
    description="CLI interface to control the PiRogue",
    url="https://github.com/PiRogueToolSuite/pirogue-cli",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "pirogue-cli = pirogue_cli.cmd.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: OS Independent",
    ],
)
