# Next step summary after C2

The C2 block-dictionary compactor has been added and validated on clean toy examples.  The estimator shows that C2 can reduce final compaction noise terms when evaluated rows become dense, but it significantly increases public CLPN key size and public sample exposure.

The next best research step is not a user-facing library yet.  It is a stronger C2 security/feasibility layer:

1. replace the current screening shim with a dedicated sparse/q-ary-LPN estimator;
2. add parameter sweeps over `(q, ell, n, k, eta, eta_c, m_c, depth)`;
3. model CRT lanes with small primes instead of large prime fields;
4. add seeded dictionary generation to avoid materializing huge C2 keys;
5. compare C2 against the q-ary plurality-only compactor and the original coordinate compactor.

The current package remains research-only and does not claim certified post-quantum security.
