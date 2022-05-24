from setuptools import find_packages, setup

setup(
    name="pirogue-cli",
    version="1.0",
    author="U+039b",
    author_email="hello@pts-project.org",
    description="CLI interface to control the PiRogue",
    url="https://github.com/PiRogueToolSuite/pirogue-cli",
    packages=find_packages(),
    package_data={"pirogue_cli": ["frida-scripts/*.js"]},
    zip_safe=True,
    entry_points={
        "console_scripts": [
            "pirogue-cli = pirogue_cli.cmd.cli:main",
            "pirogue-intercept-tls = pirogue_cli.network.intercept_tls:start_interception",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: OS Independent",
    ],
)
