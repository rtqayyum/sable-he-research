"""Plaintext/tensor robust FL aggregation methods."""

from sable.fl import PlainFLAggregator


def main() -> None:
    models = [
        [1.0, 10.0],
        [2.0, 20.0],
        [100.0, 30.0],
        [3.0, 40.0],
        [4.0, 50.0],
    ]
    agg = PlainFLAggregator()

    print("mean:", agg.mean(models))
    print("coordinate_min:", agg.coordinate_min(models))
    print("coordinate_max:", agg.coordinate_max(models))
    print("coordinate_median:", agg.coordinate_median(models))
    print("trimmed_mean:", agg.trimmed_mean(models, trim_ratio=0.2))
    print("krum:", agg.krum(models, f=0))


if __name__ == "__main__":
    main()
