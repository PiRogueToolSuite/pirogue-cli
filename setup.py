from setuptools import find_packages, setup

requirements = [i.strip() for i in open("requirements.txt").readlines()]

setup(
    name="pirogue-cli",
    version="1.0.7",
    author="U+039b",
    author_email="hello@pts-project.org",
    description="CLI interface to control the PiRogue",
    url="https://github.com/PiRogueToolSuite/pirogue-cli",
    install_requires=requirements,
    packages=find_packages(),
    package_data={"pirogue_cli": [
        "frida-scripts/*.js",
        "config-files/*"
    ]},
    zip_safe=True,
    entry_points={
        "console_scripts": [
            "pirogue-ctl = pirogue_cli.cmd.cli:main",
            "pirogue-intercept-tls = pirogue_cli.network.intercept_single:start_interception",
            "pirogue-intercept-single = pirogue_cli.network.intercept_single:start_interception",
            "pirogue-intercept-gated = pirogue_cli.network.intercept_gated:start_interception",
            "pirogue-view-tls = pirogue_cli.network.view_tls:view_decrypted_traffic",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: OS Independent",
    ],
)
