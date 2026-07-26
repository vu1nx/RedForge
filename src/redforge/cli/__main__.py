"""Module execution wrapper for ``python -m redforge.cli``."""

import sys

from redforge.cli import main

if __name__ == "__main__":
    sys.exit(main())
