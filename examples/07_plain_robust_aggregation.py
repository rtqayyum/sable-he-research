"""Plain/decrypt-side robust FL aggregation helpers."""

from sable.fl import PlainFLAggregator

models = [
    [1.0, 10.0],
    [2.0, 20.0],
    [100.0, 30.0],
    [3.0, 40.0],
    [4.0, 50.0],
]

agg = PlainFLAggregator()
print("min", agg.coordinate_min(models))
print("max", agg.coordinate_max(models))
print("median", agg.coordinate_median(models))
print("trimmed", agg.trimmed_mean(models, trim_ratio=0.2))
print("krum", agg.krum(models, f=0))
