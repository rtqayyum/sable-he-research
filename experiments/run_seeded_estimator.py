from sable.estimator_seeded import estimate_seeded_c2, format_seeded_estimate
from sable.params import PRESETS


def main() -> None:
    for preset, depth in [('c2_toy_noisy', 1), ('c2_design_smallq', 2)]:
        print('=' * 80)
        print(format_seeded_estimate(estimate_seeded_c2(PRESETS[preset], depth=depth)))


if __name__ == '__main__':
    main()
