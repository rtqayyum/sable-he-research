"""Generate a SABLE-HE Phase 5 external review package."""

from sable.standardization import write_review_package

manifest = write_review_package("sable_phase5_review_package", presets=["c7_standard_toy_noisy"], depth=1)
print(manifest)
