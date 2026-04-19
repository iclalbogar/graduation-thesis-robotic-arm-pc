"""Pytest configuration: put `source/` on sys.path so tests can
`from security import ...` without a package install.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
_SOURCE = os.path.join(_ROOT, "source")
if _SOURCE not in sys.path:
    sys.path.insert(0, _SOURCE)
