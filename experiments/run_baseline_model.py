
#!/usr/bin/env python3
"""Generate baseline-comparison proxy tables."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from sable.baselines import main


if __name__ == '__main__':
    main()
