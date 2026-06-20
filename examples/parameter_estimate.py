"""Print a SABLE parameter-estimator report."""

from sable.estimator import estimate, format_estimate
from sable.params import PRESETS

report = estimate(PRESETS["c7_standard_toy_clean"], depth=1, additions=1)
print(format_estimate(report))
