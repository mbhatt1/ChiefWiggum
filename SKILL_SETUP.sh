#!/bin/bash
# ChiefWiggum Claude Code Skill Setup Script

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ChiefWiggum Claude Code Skill Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "📁 Repository: $REPO_DIR"

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed. Please install Python 3."
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "✓ Found: $PYTHON_VERSION"
echo ""

# Install in editable mode
echo "📦 Installing chiefwiggum in editable mode..."
cd "$REPO_DIR"
python3 -m pip install -e . --quiet

echo "✓ Package installed successfully"
echo ""

# Verify installation
echo "🔍 Verifying installation..."
if python3 -c "import chiefwiggum; print(f'  Version: {chiefwiggum.__version__}')" 2>&1; then
    echo "✓ ChiefWiggum module imported successfully"
else
    echo "❌ Failed to verify installation"
    exit 1
fi

# Check CLI
if command -v chiefwiggum &> /dev/null; then
    echo "✓ 'chiefwiggum' CLI command is available"
    chiefwiggum --version 2>/dev/null || echo "  (CLI version check skipped)"
else
    echo "⚠️  'chiefwiggum' CLI not found in PATH (this may be normal in some environments)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "1. Read the skill guide: cat .claude/SKILL_GUIDE.md"
echo "2. Try the skill: /chiefwiggum init --target-url http://localhost:8080"
echo "3. Check CLI help: chiefwiggum --help"
echo ""
echo "For full documentation, see: README.md"
echo ""
