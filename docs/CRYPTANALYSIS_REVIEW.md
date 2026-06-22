# Independent cryptanalysis review

Use the Phase 3 review tools:

```bash
sable-he cryptanalysis-info
sable-he cryptanalysis-report --preset c7_standard_toy_noisy --depth 1 --json
sable-he cryptanalysis-vector --json
sable-he cryptanalysis-template --output attack_report.md
sable-he cryptanalysis-bundle --output review_bundle
```

The generated bundle includes review scope, deterministic known-answer vectors, public-surface summaries, and attack-surface reports. These are screening artifacts, not security certificates.
