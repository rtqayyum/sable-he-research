"""Key-sum attack experiment (paper Table: key-sum attack).  Needs python-flint.

Server view: every client's upload b_c, the public sparse vectors, and the summed
key T (released so the server can decrypt the sum).  At replica positions where
the aggregate residual equals the decoded sum, every client's noise is zero
(except with probability ~K^2 eta^2 / q).  Differences of two clean replicas of
one coordinate give noise-free linear equations in t_c.  Gaussian elimination
then recovers t_c and every individual update.
"""
import sys, time, json
import numpy as np
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, 'src'), ROOT]
from sable.fast_regev import (RegevAggParams, keygen, encrypt, aggregate, decrypt_sum,
                              public_sparse_vectors, choose_replicas, CHUNK, _dot)


def all_vectors(p, round_seed, d):
    idx, co = [], []
    for s in range(0, d, CHUNK):
        i, c = public_sparse_vectors(p, round_seed, s, min(d, s + CHUNK))
        idx.append(i); co.append(c)
    return np.concatenate(idx), np.concatenate(co)


def run(n, K, d, eta=0.003, k=5, q=2147483647, seed=1, solve=True, max_extra=10**9):
    R = choose_replicas(n, k, q, eta, K)
    p = RegevAggParams('t', n=n, k=k, q=q, eta=eta, replicas=R)
    rng = np.random.default_rng(seed)
    keys = [keygen(p, 1000 * seed + c) for c in range(K)]
    T = sum(keys) % q
    msgs = [rng.integers(0, 2**28, size=d) for _ in range(K)]
    rs = 7 + seed
    ups = [encrypt(p, keys[c], msgs[c], round_seed=rs, noise_seed=500 * seed + c) for c in range(K)]
    B = aggregate(ups, q)
    M = decrypt_sum(p, T, B, rs)['value']
    idx, co = all_vectors(p, rs, d)
    resid = (B - _dot(idx, co, T, q) - M[:, None]) % q
    clean = resid == 0
    # ground truth: are all individual noises zero where the aggregate is clean?
    noise_free = np.ones_like(clean)
    for c in range(K):
        e = (ups[c] - _dot(idx, co, keys[c], q) - msgs[c][:, None]) % q
        noise_free &= (e == 0)
    false_clean = int(np.sum(clean & ~noise_free))
    # equations for target client 0: differences of clean replicas within a coordinate
    tgt = 0
    b = ups[tgt]
    rows_idx, rows_co, rhs = [], [], []
    for j in range(d):
        cr = np.nonzero(clean[j])[0]
        if len(cr) < 2:
            continue
        r0 = cr[0]
        for r in cr[1:]:
            rows_idx.append(np.concatenate([idx[j, r], idx[j, r0]]))
            rows_co.append(np.concatenate([co[j, r], (q - co[j, r0]) % q]))
            rhs.append((int(b[j, r]) - int(b[j, r0])) % q)
    n_eq = len(rhs)
    res = dict(n=n, K=K, d=d, eta=eta, R=R, p_replica=(1 - eta) ** K, clean_positions=int(clean.sum()),
               false_clean=false_clean, equations=n_eq, equations_over_n=n_eq / n)
    if solve and n_eq >= n:
        import flint
        use = min(n_eq, n + max_extra)
        t0 = time.time()
        A = flint.nmod_mat(use, n + 1, q)
        for i in range(use):
            for col, val in zip(rows_idx[i], rows_co[i]):
                A[i, int(col)] = (int(A[i, int(col)]) + int(val)) % q
            A[i, n] = rhs[i]
        Rm, rank = A.rref()
        res['solve_s'] = time.time() - t0
        res['rank'] = int(rank)
        # pivot structure of the RREF: variable p is determined if its row has no free-column entries
        piv = {}
        for i in range(rank):
            row = [int(Rm[i, c]) for c in range(n)]
            nz = [c for c, v in enumerate(row) if v]
            if nz:
                piv[nz[0]] = (i, nz)
        free = set(range(n)) - set(piv)
        t_rec = np.full(n, -1, dtype=np.int64)
        for pc, (i, nz) in piv.items():
            if all(c == pc or c not in free for c in nz) and len(nz) == 1:
                t_rec[pc] = int(Rm[i, n])
        known = t_rec >= 0
        res['key_coords_recovered'] = int(known.sum())
        res['key_coords_correct'] = int(np.sum(t_rec[known] == keys[tgt][known]))
        # decrypt the target's update from replicas whose support is fully recovered
        ok = known[idx].all(axis=2)          # (d, R)
        tr = np.where(known, t_rec, 0)
        resid_t = (b - _dot(idx, co, tr, q)) % q
        rec = 0
        for j in range(d):
            vals = resid_t[j][ok[j]]
            if len(vals) == 0:
                continue
            u, cnt = np.unique(vals, return_counts=True)
            if u[cnt.argmax()] == msgs[tgt][j]:
                rec += 1
        res['update_coords_recovered'] = rec / d
    return res


if __name__ == '__main__':
    out = []
    for n, K in [(1024, 10), (2048, 10), (4096, 10), (2048, 100), (4096, 100)]:
        d = int(round(0.1198 * n))  # same d/n ratio as LR (d=7850) at n=65536
        r = run(n, K, d)
        print(json.dumps(r), flush=True)
        out.append(r)
