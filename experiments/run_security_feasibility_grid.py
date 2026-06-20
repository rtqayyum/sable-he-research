
#!/usr/bin/env python3
"""Explore the correctness/security tension for k=1 SABLE-HE candidates.

This script does not instantiate real parameters.  It solves the simple
clean-subset inequality n * -log2(1-eta) >= target_bits together with the
conservative correctness inequality eta <= 1/(10*A*w0^(2^D-1)).
"""

from __future__ import annotations

import math


def required_n_for_clean_subset(target_bits: int, eta: float) -> int:
    if eta <= 0:
        return math.inf
    return math.ceil(target_bits * math.log(2.0) / (-math.log1p(-eta)))


def main() -> None:
    target_bits = 128
    print('D,k,A,w0,eta_max_for_correctness,required_n_clean_subset,expansion_key_entries_approx')
    for D in range(1, 5):
        for k in [1, 2, 3]:
            A = 1
            w0 = (k + 1) ** 2
            eta_max = 1.0 / (10.0 * A * (w0 ** (2 ** D - 1)))
            # Use half of the upper bound to leave correctness margin.
            eta = eta_max / 2.0
            n = required_n_for_clean_subset(target_bits, eta)
            expansion_entries = (n + 1) * (n + 1) * (k + 1)
            print(f'{D},{k},{A},{w0},{eta:.8g},{n},{expansion_entries}')


if __name__ == '__main__':
    main()
