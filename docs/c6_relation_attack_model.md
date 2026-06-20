# C6 relation-surface attack model

C6 adds a dedicated diagnostic layer for C4 projective compaction.  C4 reduced
C2/C3 dictionary entries by publishing one representative per projective line in
each block, but a full projective block contains many low-weight linear
relations.

For a block of width `b` over `F_q`, the public basis has

```text
M = (q^b - 1)/(q - 1)
```

projective representatives.  The total relation space has dimension `M - b`.
More importantly, for every projective line in `PG(b-1,q)`, every triple of
distinct points on that line is linearly dependent.  The number of projective
lines is the Gaussian binomial coefficient

```text
[b choose 2]_q = ((q^b - 1)(q^(b-1) - 1))/((q^2 - 1)(q - 1)).
```

So the raw number of weight-3 projective-line relations in one block is

```text
[b choose 2]_q * C(q+1,3).
```

Combining the corresponding CLPN ciphertexts cancels the hidden block message
and yields known-zero noisy linear equations with effective q-ary noise

```text
eta_3 = (q-1)/q * (1 - (1 - q*eta_c/(q-1))^3).
```

The raw relation count is not an independence claim.  C6 therefore reports two
surfaces:

1. `raw_weight3_relation_rows`: all low-weight projective triple combinations;
2. `rank_capped_relation_rows`: a conservative independence proxy using only
   `(M-b) * m_c` relation rows per block.

Both are useful.  The raw count shows the adversary's relation-search surface;
the rank-capped count prevents the estimator from pretending every relation is
independent.

## Current C6 conclusion

C6 rejects the current C4 projective compactor as the main security candidate
for block width at least two.  The problem is not algebraic correctness; the
problem is the public relation surface.  C6 corrects the earlier C5 heuristic:
the minimum projective relation weight is `3` for any block width `b >= 2`, not
`b+1`.

This means the next design step should be one of:

- use block width one and accept more compaction noise;
- use randomized incomplete additive bases with screened sparse-kernel weight;
- add secret salting/masking so public relation combinations no longer cancel
  to known-zero CLPN samples;
- replace the projective dictionary with a code-based decoder compactor whose
  public generator has no abundant low-weight relations.

C6 is a screen, not a proof.  It must be followed by specialist sparse-LPN and
q-ary-LPN cryptanalysis before any security claim.
