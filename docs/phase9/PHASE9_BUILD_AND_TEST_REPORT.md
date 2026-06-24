# Phase 9 build and test report

Phase 9 adds the benchmark-comparison framework for top-venue evaluation work.

Validation performed in the packaging environment:

- pytest suite: pass (`163` tests);
- public repository hygiene scan: pass;
- release check: pass after deterministic KAT regeneration for version `0.10.0`;
- CLI smoke tests: pass;
- local wheel install: pass;
- benchmark package generation: pass;
- measured SABLE local workload smoke test: pass.

CLI smoke commands exercised:

```bash
sable-he benchmark-info
sable-he benchmark-workloads
sable-he benchmark-sable --repetitions 1 --workload add_scalar
sable-he benchmark-package --output /tmp/sable_phase9_wheel_pkg --repetitions 1 --workload add_scalar
```

Important scope statement: the package measures SABLE-HE locally and produces templates for external FHE baselines. It does not ship fabricated wall-clock results for OpenFHE, Microsoft SEAL, TFHE-rs, Concrete, or Lattigo.
