# Candidate Parameter Sets

The Phase 7 candidate rows are depth-1 review targets. Depth is intentionally limited because the present sparse-row multiplication invariant grows quickly with multiplicative depth.

The candidate families are:

| Name | Target | Purpose |
|---|---:|---|
| `sable-review-128-d1` | 128 bits | Category-I-style review target |
| `sable-review-192-d1` | 192 bits | Category-III-style review target |
| `sable-review-256-d1` | 256 bits | Category-V-style review target |

Each row includes a correctness budget and public surface accounting. The internal finite screens are conservative diagnostics only. A parameter row may pass finite screens and still fail under a sharper attack.
