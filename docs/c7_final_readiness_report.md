# SABLE-HE v0.9 C7 final readiness report

## Status

The project is ready to stop at the current milestone as a complete research prototype package.

The main candidate is now **SABLE-HE-C7 coordinate relation-resistant compaction**.  Earlier variants remain in the repository:

- C2 full block dictionary: algebraically correct but large public dictionary.
- C3 seeded dictionary: storage improvement only; public relation surface remains.
- C4 projective dictionary: compact and correct, but C6 found many weight-3 public relations.
- C7 screened-random masks: experimental optimization, not the main claim.

## Arithmetic coverage

C7 was tested on the full low-degree arithmetic suite:

- addition;
- subtraction;
- negation;
- public scalar multiplication;
- public constant addition;
- multiplication;
- square;
- affine combinations;
- dot products;
- polynomial evaluation;
- balanced products;
- quadratic forms;
- Boolean NOT, AND, OR, XOR, NAND, NOR, XNOR, and implication encoded over F_q.

The generated C7 arithmetic run tested 20 operation families over 60 toy-clean trials and recorded 0 failures.

## Performance comparison status

The package includes proxy comparisons against existing HE method families.  These are operation-count comparisons, not wall-clock claims against optimized C++/Rust libraries.

- TFHE/FHEW-style schemes are the natural Boolean-gate and programmable-bootstrapping baseline.
- BFV/BGV are the natural exact modular/integer arithmetic baseline.
- CKKS is the natural approximate real/complex arithmetic baseline, not exact finite-field output.

Measured external-library comparisons should be done next only if the project continues beyond this milestone.

## Stop condition

The stop condition is met for this phase:

1. construction drafted;
2. proofs and limitations documented;
3. prototype implemented;
4. arithmetic operations tested;
5. relation-surface issue found and resolved conservatively;
6. paper updated;
7. repository packaged.

The project is ready as a research artifact, not as deployable cryptography.
