"""``python -m vulnscan``: the same as the ``vulnscan`` command."""

import sys

from vulnscan.cli import main

sys.exit(main())
