# Phase 8 advanced attack-estimator framework

Phase 8 strengthens the internal cryptanalytic screening layer for SABLE-HE.
It introduces surface-specific estimates for sparse q-ary LPN and q-ary
LPN/code surfaces, including clean-subset, Prange-style ISD, Stern/Dumer-style
proxy screens, May--Ozerov-style proxy screens, and q-ary BKW scan summaries.

The estimates are intended for paper appendices and external review packages.
They are not a substitute for expert cryptanalysis.  The correct interpretation
is: a candidate that fails these screens should not be submitted as secure; a
candidate that passes them still needs specialist review.
