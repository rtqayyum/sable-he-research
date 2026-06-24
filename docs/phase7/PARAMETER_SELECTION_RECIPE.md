# Parameter-selection recipe

A reviewer-facing parameter workflow is:

1. Fix workload class: multiplicative depth, addition budget, model length, number of clients.
2. Choose `k` and compute fresh row support `w0=(k+1)(k+2)`.
3. Bound row support after depth.
4. Choose sparse-LPN noise `eta` so correctness remains below the one-replica threshold.
5. Choose compactor code family and `eta_c` so q-ary compaction noise is decodable.
6. Count all public samples exposed by keys and deployment.
7. Run clean-subset, BKW, and ISD screens.
8. Increase dimensions until candidate target bits are exceeded by a review margin.
9. Submit the resulting package for external cryptanalysis.

The final step cannot be replaced by internal testing.
