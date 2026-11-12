"""Version constants. Bump RULES_VERSION when source/sink/sanitizer rules change,
ANALYZER_VERSION when the analysis algorithm or cache format changes."""

ANALYZER_VERSION = "1.0.0"
RULES_VERSION = "1.0.0"
CACHE_SCHEMA_VERSION = 3

# Capacities that keep the abstract domain finite (see DESIGN.md).
MAX_TRACE_EDGES = 40
MAX_PATH_ATOMS = 8
MAX_SIG_DEPTH = 3
MAX_FIXPOINT_ROUNDS = 200
