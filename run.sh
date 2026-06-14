#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR/secops-cli:$SCRIPT_DIR/secops-core:$SCRIPT_DIR/secops-offense:$SCRIPT_DIR/secops-defense:$SCRIPT_DIR/secops"
python -m secops_cli
