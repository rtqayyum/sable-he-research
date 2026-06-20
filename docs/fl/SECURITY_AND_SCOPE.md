# Security and scope

The FL API is designed for research, reproducible demos, and experimentation with SABLE-HE encrypted aggregation.

Encrypted-native methods are additive:

```text
sum, mean, weighted_sum, weighted_average, FedAvg, FedSGD-style averaging
```

Methods that require ordering, comparison, sorting, norms, or pairwise distances are not encrypted-native in this release:

```text
min, max, median, trimmed_mean, norm_clipped_mean, geometric_median, Krum, Multi-Krum
```

Those methods are available for plaintext/decrypt-side tensors through `PlainFLAggregator` and `clear_aggregate_arrays`.

Before using any new cryptographic construction for sensitive data, obtain independent cryptanalysis, select reviewed parameters, audit implementation safety, and benchmark against established secure aggregation or HE systems.
