from sable import PRESETS
from sable.cryptanalysis import build_review_bundle, write_review_bundle

params = PRESETS["c7_standard_toy_noisy"]
bundle = build_review_bundle(params, target_bits=128)
print(bundle.to_markdown().splitlines()[0])
paths = write_review_bundle("review_bundle_example", preset=params.name)
print(paths)
