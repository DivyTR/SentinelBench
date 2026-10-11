import sys
from pathlib import Path

# Make `core` importable when pytest is run from the repo root or tests/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
