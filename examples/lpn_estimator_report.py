from sable.lpn_estimators import estimate_candidate, format_candidate_report

report = estimate_candidate("sable_cat1_depth1_review", target_bits=128)
print(format_candidate_report(report))
