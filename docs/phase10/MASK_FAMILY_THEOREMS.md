# Mask-family theorem statements

## Theorem 1: mask-family compaction correctness

If every active final-row block \(\alpha_B\) is represented as a linear
combination of masks in \(U_B\), then CLPN linear evaluation on ciphertexts of
\(\langle u,s_B\rangle\) produces a CLPN encryption of the final decryption inner
product.

## Theorem 2: coordinate relation-resistance

For coordinate masks \(U=I_b\), the only vector \(z\) satisfying \(U^Tz=0\) is
\(z=0\).  Therefore coordinate compaction has no intra-block known-zero
mask-kernel relation.

## Theorem 3: projective/full dictionary relation warning

For block width \(b\ge2\), full and projective block dictionaries contain
low-weight linear dependencies among public masks.  These dependencies can cancel
the block-secret plaintext and should be counted as public relation surfaces.

## Theorem 4: q-ary compaction-noise piling-up

Combining \(T\) independent q-ary symmetric CLPN error terms of rate \(\eta_c\)
produces effective error rate

\[
\eta_T=\frac{q-1}{q}\left(1-\left(1-\frac{q\eta_c}{q-1}\right)^T\right).
\]
