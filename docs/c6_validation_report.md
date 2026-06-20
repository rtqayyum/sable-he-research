# SABLE-HE v0.8 C6 validation report

C6 adds a projective-relation attack-surface estimator for the C4/C5 compaction
layer.

## New code

- `src/sable/c6_relation_estimator.py`
- `experiments/run_c6_relation_estimator.py`
- `experiments/run_c6_parameter_grid.py`
- `tests/test_c6_relation_estimator.py`

## Validation

The complete test suite passes:

```text
88 passed
```

## Main finding

C4 projective compaction is smaller than C2/C3, but full projective blocks of
width at least two expose many weight-3 public linear relations.  Combining the
corresponding CLPN ciphertexts cancels the encrypted block secret and produces a
known-zero q-ary-LPN surface with three-term accumulated noise.

For the `c2_design_smallq` screen:

```text
C4 entries: 9747
C2 entries: 58482
Raw weight-3 relations: 545832
Raw weight-3 relation rows: 2235727872
Rank-capped relation rows: 37822464
Verdict: reject-for-current-security-claim
```

For the `prototype_medium` screen with q=65537 and block width 2:

```text
C4 entries: 16777729
Raw weight-3 relation rows: 12298392338153078784
Rank-capped relation rows: 17179869184
Verdict: reject-for-current-security-claim
```

These numbers are diagnostic.  The raw relation rows are not claimed to be
independent; C6 separately reports a rank-capped relation surface.  The problem
remains serious because even the rank-capped surface is large and low-noise in
current presets.

## Correctness of arithmetic scope

C6 does not remove the C5 arithmetic layer.  The project still tests addition,
subtraction, negation, public scalar multiplication, constants, multiplication,
squaring, powers, affine combinations, polynomial evaluation, dot products,
quadratic forms, and Boolean gates encoded over `F_q`.

## Next design step

C7 should replace full projective compaction with an incomplete randomized
additive basis or a salted relation-resistant compactor.  The target property is
not only coverage; it is high minimum sparse-kernel weight under the public
basis, while preserving manageable compaction noise.
