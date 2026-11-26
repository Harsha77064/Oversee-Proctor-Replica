"""`python -m server.testing` (npm test): runs the pytest suite with the project's Python."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

if __name__ == "__main__":
    sys.exit(pytest.main([str(ROOT / "tests"), "-q", "-p", "no:cacheprovider", *sys.argv[1:]]))
