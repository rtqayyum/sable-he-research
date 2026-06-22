from sable.cryptanalysis import write_challenge_bundle

manifest = write_challenge_bundle("review_bundle", presets=["c7_standard_toy_noisy"], target_bits=64)
print(manifest)
