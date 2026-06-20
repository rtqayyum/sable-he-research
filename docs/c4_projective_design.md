# SABLE-HE-C4 projective sparse additive-basis compaction

C4 replaces the C2/C3 full block dictionary with a projective additive basis.
For a block of width `b` over `F_q`, C2/C3 publish `q^b - 1` encrypted block
inner-products. C4 publishes one representative for each one-dimensional line,
so the public entries are `(q^b - 1)/(q - 1)`.

For every nonzero coefficient block `alpha`, the evaluator writes
`alpha = lambda * u`, where `u` is the normalized projective representative and
`lambda` is the first nonzero coordinate of `alpha`. Since CLPN is linearly
homomorphic, the evaluator scales the stored encryption of `<u, s_B>` by
`lambda`. Therefore C4 keeps one compaction term per active block, as in C2/C3,
while reducing the public CLPN sample surface by a factor of `q - 1` for each
full block.

This is still a research candidate. The projective public key is structured,
and its large-sample LPN surface still needs dedicated cryptanalysis.
