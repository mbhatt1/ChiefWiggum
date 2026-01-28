#!/bin/bash
# ChiefWiggum wrapper script
# Provides a simple entry point for the CLI

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Run the CLI
python3 -m chiefwiggum "$@"
