# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial release of ChiefWiggum Loop methodology
- Core Evaluator, EvidenceLedger, SurfaceEnumerator classes
- CLI interface for managing projects
- Project creation and initialization
- Evidence persistence to disk
- Re-testing prevention via ledger

### Changed
- N/A

### Fixed
- N/A

## [0.1.0] - 2026-01-27

### Added
- **Initial Release**
  - ChiefWiggum Loop methodology for security vulnerability testing
  - D'oh! I found it! — A search loop that actually converges
  - Evidence ledger prevents infinite re-discovery
  - Structured project layout (TARGET.md, SURFACES.yaml, HYPOTHESIS.md, EVIDENCE/)
  - Python library and CLI interface
  - Evaluation results showing 30-40% improvement over unstructured analysis

### Features
- Core evaluation loop (5 steps)
- Persistent evidence storage
- Attack surface enumeration
- Hypothesis testing framework
- Result tracking and reporting
- Command-line interface

### Documentation
- Comprehensive README.md
- Getting started guide
- API reference
- Examples and templates
- Methodology documentation

### Testing
- Initial test suite
- Unit tests for core functionality
- Integration tests

---

## Roadmap

### v0.2.0 (Planned)
- Integration with static analysis tools (CodeQL, Semgrep)
- Automated surface enumeration
- Patch validation framework
- Web UI for evidence visualization
- Support for non-sanitizer vulnerabilities

### v0.3.0 (Planned)
- Agent-based testing (agentic security)
- Integration with CI/CD pipelines
- Knowledge base management
- Multi-team collaboration
- Vulnerability database integration (CVE, CWE)

### v1.0.0 (Planned)
- Stable API
- Production-ready tooling
- Full documentation
- Community contributions

---

## Semantic Versioning

This project uses semantic versioning:
- MAJOR version when making incompatible API changes
- MINOR version when adding functionality in backwards-compatible manner
- PATCH version for backwards-compatible bug fixes
