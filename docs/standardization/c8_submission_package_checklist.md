# C8 standardization-submission checklist

## Required artifacts

- Algorithm specification: KeyGen, Enc, Expand, EvalAdd, EvalSub, EvalScalar,
  EvalMul, Compact, Dec.
- Exact parameter profiles.
- Security proof.
- Correctness proof.
- Failure-probability theorem.
- Known-answer tests.
- Reference implementation.
- Optimized implementation or realistic performance model.
- Comparison with TFHE/FHEW, BFV/BGV, CKKS, and LPN aggregation baselines.
- Cryptanalysis report.
- Side-channel analysis.
- IPR/patent disclosure statement.
- Reproducibility instructions.
- Interoperability/serialization specification.

## SABLE-C8 status

| Artifact | Status |
|---|---|
| Algorithm specification | Present in manuscript, needs freeze |
| Reference implementation | Present, Python research prototype |
| Arithmetic tests | Present |
| KAT vectors | Initial toy vector added in C8 |
| Parameter profiles | Toy/research only |
| Security proof | Draft proof present, needs external review |
| Cryptanalysis report | Initial internal screens only |
| Side-channel analysis | Checklist only |
| External benchmarks | Proxy only |
| Interoperability spec | Not frozen |
| IPR statement | Not present |

## Naming recommendation

Use this name for external discussion:

**SABLE-HE-C7: a code/LPN-based leveled SHE research candidate with coordinate relation-resistant compaction.**
