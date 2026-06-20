# Sparse/q-ary-LPN surface estimator

The seeded C3 compactor exposes the same number of q-ary LPN samples as dense
C2.  The dedicated estimator reports:

- public sample count;
- sample-to-dimension ratio;
- expected number of noisy samples;
- no-clean-subset and Prange/ISD proxies inherited from the v2 attack screen;
- a q-ary block-BKW scan that accounts for the q^b table size;
- warnings when the public sample surface is too large for the simple screen to
  justify security.

The estimator is intentionally conservative and is not a certified LPN security
estimator.  Its role is to reject clearly weak or unclear parameter regimes and
to show exactly where specialist cryptanalysis is still required.
