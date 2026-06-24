# LPN/ISD/BKW model notes

The estimator separates public surfaces because SABLE-HE exposes different noisy
linear equation families:

1. sparse q-ary LPN rows from the expansion key;
2. q-ary LPN/code rows from the compaction key;
3. message-cancelling CLPN row-difference surfaces;
4. deployment-dependent sparse-LPN input ciphertext rows.

The implemented screens are conservative engineering checks.  They include:

- clean-subset probability screens;
- Prange-style information-set decoding screens;
- Stern/Dumer/May--Ozerov-inspired proxy screens;
- q-ary BKW block-width/level scans based on q-ary symmetric-noise bias.

The proxy labels are intentional.  Specialist estimators must replace them
before any final security claim.
