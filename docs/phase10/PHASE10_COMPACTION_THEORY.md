# Phase 10: stronger compaction theory

Phase 10 strengthens the SABLE-HE manuscript around the compaction layer.  It
models compaction as a public mask-family problem over \(\mathbb F_q^b\).  For a
secret block \(s_B\), a public mask \(u\) corresponds to a CLPN encryption of
\(\langle u,s_B\rangle\).  The evaluator decomposes a final GSW row block into
public masks and uses CLPN linear homomorphism to produce a compact output.

The key security-design question is not only correctness.  It is whether the
published mask family contains low-weight known-zero relations

\[
        U^T z = 0,
\]

because such relations can cancel the hidden block secret and produce derived
q-ary-LPN-style samples.  This is why the final SABLE-HE proposal keeps
coordinate compaction as the conservative main scheme: it has a minimal public
mask surface and no nonzero intra-block mask-kernel relation.

## Main contribution

The Phase 10 contribution is a theorem-ready formulation:

1. define mask-family CLPN compaction;
2. prove blockwise correctness from linear homomorphism;
3. define sparse mask-kernel distance as a public-relation metric;
4. show coordinate compaction has no intra-block known-zero mask relation;
5. show richer full/projective block dictionaries reduce noise but introduce
   low-weight public relations;
6. preserve richer dictionaries only as optional optimizations pending external
   cryptanalysis.

This material is intended for the final paper and supplementary review package.
It does not certify parameters.
