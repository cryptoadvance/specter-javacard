#!/usr/bin/env python3
"""Thin launcher – the full CLI implementation lives in specter_card/cli.py."""
import os
import sys

# Allow running directly from the py/ directory without installing the package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from specter_card.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
