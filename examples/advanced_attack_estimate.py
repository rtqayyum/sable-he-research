from sable.advanced_attacks import estimate_candidate, format_candidate_attack_report

report = estimate_candidate("sable_cat1_depth1_review")
print(format_candidate_attack_report(report))
