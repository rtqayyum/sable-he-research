"""Estimator and C7 relation-screen example."""

from sable.params import PRESETS
from sable.estimator import estimate, format_estimate
from sable.c7_relation_screen import estimate_c7_relations, format_c7_report


def main() -> None:
    params = PRESETS["c7_standard_toy_noisy"]
    print(format_estimate(estimate(params, depth=1, additions=1)))
    print("\n" + "=" * 72 + "\n")
    print(format_c7_report(estimate_c7_relations(params)))


if __name__ == "__main__":
    main()
