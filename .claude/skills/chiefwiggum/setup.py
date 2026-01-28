#!/usr/bin/env python3
"""
ChiefWiggum Loop - Security Vulnerability Testing Methodology
Setup configuration for pip installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README if it exists
readme_path = Path(__file__).parent / "SKILL.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="chiefwiggum",
    version="0.1.0",
    description="D'oh! I found it! A security vulnerability testing loop that actually converges",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Security Research Team",
    author_email="security@example.com",
    url="https://github.com/frankbria/ralph-claude-code",
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
    packages=find_packages(),
    install_requires=[
        "click>=8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
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
    ],
)
