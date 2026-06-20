# SABLE-HE v0.9 C7: relation-resistant compaction

C6 rejected full C4 projective compaction as the main security candidate.  The issue was not algebraic correctness; it was public relation surface.  A full projective block contains many weight-3 projective-line relations, and public CLPN ciphertexts can be linearly combined along those relations to create known-zero q-ary-LPN-style samples.

C7 makes the default construction conservative:

- publish only a coordinate basis per compaction block in the main security profile;
- optionally allow screened random masks as an experimental optimization;
- always keep the coordinate basis first, so every coefficient block has a guaranteed fallback representation;
- screen optional masks for projective duplicates and low-weight relations before accepting them;
- keep C2/C3/C4 in the repository as experimental variants, not the main claim.

## Main profile

The default C7 profile is block width 1 coordinate compaction.  It has the same public entry count as the legacy coordinate compactor, but it is now explicitly framed as the relation-resistant security baseline.

For an N-coordinate GSW secret, the public C7 compaction key contains N CLPN ciphertexts.  A final sparse row with B active coordinates uses B CLPN terms.  Dense worst-case compaction uses N terms.

## Experimental screened-random profile

The screened-random profile stores the coordinate basis plus optional dense masks.  A mask is rejected if it is a projective duplicate or creates a low-weight relation under the local screen.  This can reduce average compaction terms for some blocks, but it is not the main security claim.

## Readiness statement

C7 is ready as a research prototype and manuscript package.  It is not production cryptography, not a standardization candidate, and not a certified concrete parameter set.  Remaining research work is clearly isolated: stronger q-ary/sparse-LPN estimation, stronger coding than repetition decoding, and measured external-library benchmarks.
