# Relation-resistant compaction model

Let \(U=\{u_1,\dots,u_M\}\subseteq\mathbb F_q^b\) be a public mask family for a
block of the extended GSW secret \(s_B\in\mathbb F_q^b\).  The compaction key
publishes CLPN ciphertexts

\[
  Z_j = \operatorname{CLPN.Enc}_r(\langle u_j,s_B\rangle).
\]

For a final-row block \(\alpha\), the evaluator uses a representation

\[
  \alpha = \sum_j z_j u_j
\]

and outputs \(\sum_j z_j Z_j\).  Correctness follows because the plaintext is
\(\langle\alpha,s_B\rangle\).

A known-zero mask relation is a nonzero vector \(z\) with \(U^Tz=0\).  Such a
relation makes the mask plaintext cancel:

\[
  \sum_j z_j\langle u_j,s_B\rangle = \langle U^Tz,s_B\rangle = 0.
\]

The sparse mask-kernel distance is

\[
  d_\perp(U)=\min_{z\ne0, U^Tz=0}\|z\|_0.
\]

Large \(d_\perp(U)\) is desirable.  Coordinate compaction uses \(U=I_b\), so no
nonzero kernel exists.  Projective/full block dictionaries are smaller/noisier
tradeoffs, but for block width at least two they contain low-weight relations.
