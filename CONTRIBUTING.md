# Contributing to ChiefWiggum Loop

Thanks for your interest in contributing! This document provides guidelines and instructions.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## Getting Started

1. **Fork the repo**
   ```bash
   git clone https://github.com/mbhatt1/ChiefWiggum
   cd ChiefWiggum
   ```

2. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/my-feature
   ```

## Development

### Code Style

- Follow PEP 8
- Use `black` for formatting
- Use `flake8` for linting
- Use `mypy` for type checking

```bash
# Format code
black src/ tests/

# Lint
flake8 src/ tests/

# Type check
mypy src/
```

### Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=chiefwiggum tests/

# Run specific test
pytest tests/test_core.py::test_evaluator
```

### Documentation

- Add docstrings to new functions
- Update README.md if user-facing
- Update docs/ for methodology changes

## Submission

### Before Submitting

1. **Run tests**
   ```bash
   pytest tests/
   ```

2. **Check code quality**
   ```bash
   black --check src/
   flake8 src/
   mypy src/
   ```

3. **Update CHANGELOG.md**
   - Add your change under "Unreleased"
   - Follow [Keep a Changelog](https://keepachangelog.com/) format

### Creating a Pull Request

1. Push to your fork
2. Create PR on GitHub
3. Fill out the PR template
4. Link any related issues

### PR Title Format

- `feat: Add X feature`
- `fix: Fix bug in X`
- `docs: Update X documentation`
- `refactor: Refactor X module`
- `test: Add tests for X`

### What We're Looking For

✅ **Good PRs:**
- Address a specific issue
- Have clear commit messages
- Include tests
- Update documentation
- Follow code style

❌ **PRs we may reject:**
- Large refactors without discussion
- Breaking changes without RFC
- Missing tests
- Poor code quality

## Reporting Issues

### Bug Reports

Include:
- Python version
- ChiefWiggum version
- Minimal reproduction case
- Expected vs actual behavior
- Error traceback (if applicable)

### Feature Requests

Include:
- Use case
- Proposed solution
- Alternative approaches
- Any relevant examples

## Release Process

1. Update version in `setup.py`
2. Update `CHANGELOG.md`
3. Create release PR
4. Merge to main
5. Create GitHub release
6. Push to PyPI

## Questions?

- Open an issue for bugs
- Start a discussion for questions
- Email: security@example.com

## Recognition

Contributors will be listed in:
- README.md
- CHANGELOG.md
- GitHub contributors page

Thanks for helping make ChiefWiggum Loop better! D'oh!
