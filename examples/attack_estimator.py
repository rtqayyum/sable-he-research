"""Run the strengthened SABLE-HE LPN/ISD/BKW estimator."""
from __future__ import annotations

from sable import lpn_estimator
from sable.parameter_sets import get_candidate

spec = get_candidate("sable_cat1_depth1_q31prime")
report = lpn_estimator.attack_report(spec.to_params(), target_bits=spec.target_bits)
print(lpn_estimator.format_report(report))
