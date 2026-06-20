# Release notes: v0.8 C6 relation-surface estimator

C6 adds a dedicated estimator for C4 projective public relations.

Highlights:

- counts projective points, projective lines, and weight-3 relation triples;
- separates raw relation rows from rank-capped relation rows;
- screens row-difference CLPN samples and relation-derived known-zero samples;
- runs a compact parameter grid over block size and CLPN noise;
- updates the manuscript with Appendix K.

Main result: the full C4 projective basis should not be used as the main
security candidate for block width at least two without a new relation-resistant
argument.  It is algebraically useful but exposes abundant low-weight public
relations.
