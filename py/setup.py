from setuptools import setup, find_packages

setup(
    name="specter-card",
    version="0.1.0",
    description="Python library and CLI for Specter JavaCard applets",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "cryptography",
        "pyscard",
    ],
    entry_points={
        "console_scripts": [
            "specter-card=specter_card.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
