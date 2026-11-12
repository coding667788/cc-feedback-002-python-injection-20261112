"""Offline cross-module taint scanner for Python source code.

Only the Python standard library (:mod:`ast`, :mod:`sqlite3`, ...) is used.
The scanner parses source text only; it never imports or executes the code
under analysis.
"""

__version__ = "1.0.0"
