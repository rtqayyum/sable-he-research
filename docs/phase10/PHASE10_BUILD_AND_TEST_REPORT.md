# Phase 10 build and test report

Phase 10 adds the compaction-theory module, CLI commands, documentation,
example, tool wrapper, and tests.  The package is an internal top-venue
strengthening artifact and is not intended for immediate PyPI publication unless
merged into the final combined release.

Expected validation commands:

```bash
pytest
sable-he compaction-info
sable-he compaction-analyze --family coordinate
sable-he compaction-analyze --family projective --q 3 --block-width 2
sable-he compaction-compare
sable-he compaction-theorems
sable-he compaction-package --output /tmp/sable_phase10_compaction
```
