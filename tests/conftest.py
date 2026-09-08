"""
Pytest configuration for ElderShield.

Ensures the repository root is available on Python's import path
when tests are executed from different working directories.
"""

from __future__ import annotations

import sys
from pathlib import Path


# Repository root:
# tests/conftest.py
#        ↑
#      tests
#        ↑
# repository root
ROOT_DIR = Path(__file__).resolve().parents[1]

root_string = str(ROOT_DIR)

if root_string not in sys.path:
    sys.path.insert(0, root_string)
