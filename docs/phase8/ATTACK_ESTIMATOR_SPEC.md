# Attack estimator specification

The Phase 8 estimator reports five attack-family screens for each public surface.

1. **Clean-subset screen**: estimates the cost of finding enough error-free equations for linear solving.
2. **Prange/ISD screen**: uses an information-set success probability proxy.
3. **Stern/Dumer screen**: applies a coarse list-collision gain against the Prange proxy.
4. **q-ary block-BKW screen**: reports a sample-aware table/bias proxy using the q-ary character bias.
5. **Low-noise screen**: flags surfaces with extremely low expected error count.

All outputs must be interpreted as internal screens pending external sparse-LPN, q-ary-LPN, ISD, and BKW review.
