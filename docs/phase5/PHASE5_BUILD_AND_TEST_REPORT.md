# Phase 5 Build and Test Report

Generated for v0.6.0.

Expected checks:

```bash
pytest
sable-he standardization-info
sable-he standardization-readiness
sable-he assumptions-spec
sable-he parameter-template --json
sable-he review-checklist
sable-he review-package --output tmp_review
sable-he repo-hygiene
sable-he release-check
```

The generated review package must contain no paper drafts, PDFs, private logs, `dist/`, or build artifacts.
