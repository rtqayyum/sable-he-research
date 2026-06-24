# Attack-estimation models

The estimator uses transparent first-order and proxy models. The clean-subset
line detects low-noise LPN regimes where a random information set is likely to
be error-free. The Prange line models a baseline information-set decoder. The
Stern and Dumer lines are conservative proxy floors derived from the Prange
line; they are not replacements for specialist ISD tools. The BKW lines model
q-ary block reduction using a residual bias term and an optimistic coded-BKW
proxy.

Every output must be interpreted as an internal screen. Final SABLE-HE security
claims require external sparse-LPN, q-ary-LPN, ISD, and BKW review.
