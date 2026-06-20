"""Print a correctness/size/security-screen estimate."""

from sable.estimator import estimate, format_estimate
from sable.params import PRESETS


def main() -> None:
    est = estimate(PRESETS["c7_standard_toy_clean"], depth=1, additions=1)
    print(format_estimate(est))


if __name__ == "__main__":
    main()
