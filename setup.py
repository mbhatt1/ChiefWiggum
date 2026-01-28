#!/usr/bin/env python3
"""
ChiefWiggum Loop - Security Vulnerability Testing Methodology

Setup configuration for pip installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README
long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="chiefwiggum-loop",
    version="0.1.0",
    description="D'oh! I found it! A security vulnerability testing loop that actually converges",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Security Research Team",
    author_email="security@example.com",
    url="https://github.com/yourusername/chiefwiggum-loop",
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "PyYAML>=6.0",
        "click>=8.0",
        "tabulate>=0.9.0",
        "dataclasses-json>=0.5.7",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=3.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.950",
        ],
        "docs": [
            "sphinx>=4.0",
            "sphinx-rtd-theme>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "chiefwiggum=chiefwiggum.cli:main",
        ],
    },
    keywords=[
        "security",
        "vulnerability",
        "testing",
        "analysis",
        "methodology",
        "ralph",
        "search",
    ],
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/chiefwiggum-loop/issues",
        "Documentation": "https://chiefwiggum-loop.readthedocs.io",
        "Source Code": "https://github.com/yourusername/chiefwiggum-loop",
    },
)
