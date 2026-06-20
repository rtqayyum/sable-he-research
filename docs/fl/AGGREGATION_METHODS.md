# Aggregation methods

| Method | Encrypted native | Plain/decrypt-side | Notes |
|---|---:|---:|---|
| `sum` | yes | yes | Element-wise sum. |
| `mean` | yes | yes | Encrypted sum plus divisor metadata. |
| `weighted_sum` | yes | yes | Public integer or fixed-point weights. |
| `weighted_average` / `weighted_mean` | yes | yes | Weighted mean. |
| `fedavg` | yes | yes | Standard sample-count weighted model average. |
| `fedsgd` | yes | yes | Same weighted aggregation applied to gradients. |
| `coordinate_min` / `min` | no | yes | Requires comparison. |
| `coordinate_max` / `max` | no | yes | Requires comparison. |
| `coordinate_median` / `median` | no | yes | Requires sorting/order statistics. |
| `trimmed_mean` | no | yes | Requires sorting/order statistics. |
| `norm_clipped_mean` | no | yes | Requires plaintext norms. |
| `geometric_median` | no | yes | Requires iterative distance calculations. |
| `krum` | no | yes | Requires pairwise distances and sorting. |
| `multi_krum` | no | yes | Requires pairwise distances and sorting. |

Run:

```bash
sable-he fl-methods
```

or:

```python
from sable.fl import fl_capabilities
for row in fl_capabilities():
    print(row)
```
