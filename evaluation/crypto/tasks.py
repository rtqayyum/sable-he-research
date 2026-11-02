"""Crypto-track task functions.  Each takes a config dict and returns a JSON-able dict."""

from __future__ import annotations

import time
from typing import Any

import numpy as np

from evaluation.common import peak_rss_gb, stable_seed

# --------------------------------------------------------------------------- correctness


def correctness_agg(cfg: dict[str, Any]) -> dict[str, Any]:
    """Decoding failures of key-additive sparse-LPN aggregation vs clients K and replicas R."""
    from sable.fast_regev import RegevAggParams, aggregate, decrypt_sum, encrypt, keygen

    p = RegevAggParams("grid", n=int(cfg["n"]), k=int(cfg["k"]), q=int(cfg.get("q", 2147483647)),
                       eta=float(cfg["eta"]), replicas=int(cfg["R"]))
    K, d, trials = int(cfg["K"]), int(cfg["d"]), int(cfg["trials"])
    seed = int(cfg["seed"])
    fails = 0
    p_emp = []
    t0 = time.perf_counter()
    for tr in range(trials):
        rng = np.random.default_rng(stable_seed(seed, tr))
        T = np.zeros(p.n, dtype=np.int64)
        B = None
        expected = np.zeros(d, dtype=np.int64)
        for c in range(K):
            t = keygen(p, stable_seed(seed, tr, "key", c))
            m = rng.integers(-1000, 1000, d, dtype=np.int64) % p.q
            expected = (expected + m) % p.q
            b = encrypt(p, t, m, stable_seed(seed, tr, "round"), stable_seed(seed, tr, "noise", c))
            B = b if B is None else aggregate([B, b], p.q)
            T = (T + t) % p.q
        out = decrypt_sum(p, T, B, stable_seed(seed, tr, "round"))
        ok = out["value"] == expected
        fails += int((~ok).sum())
        p_emp.append(float(out["votes"][ok].mean()) / p.replicas if ok.any() else 0.0)
    coords = d * trials
    return {
        "coords": coords,
        "coord_failures": fails,
        "coord_failure_rate": fails / coords,
        "p_replica_correct_empirical": float(np.mean(p_emp)),
        "p_replica_correct_theory": p.p_replica_correct(K),
        "failure_bound": p.failure_bound(K),
        "upload_bytes_per_scalar": p.upload_bytes(1),
        "seconds": time.perf_counter() - t0,
    }


def correctness_she(cfg: dict[str, Any]) -> dict[str, Any]:
    """Per-replica correctness of SHE operations; plurality bound for several R."""
    from sable import fast_she as fs
    from sable.sparse_attacks import plurality_failure_bound

    p = fs.SheParams("grid", n=int(cfg["n"]), k=int(cfg["k"]), q=fs.Q28, eta=float(cfg["eta"]), replicas=1)
    keys = fs.keygen(p, int(cfg["seed"]))
    op, trials = cfg["op"], int(cfg["trials"])
    rng = np.random.default_rng(stable_seed(cfg["seed"], op))
    correct = 0
    t0 = time.perf_counter()
    for tr in range(trials):
        if op == "add":
            a, b = (int(x) for x in rng.integers(0, 1000, 2))
            C = fs.add(fs.expand(keys, fs.encrypt(keys, a, stable_seed(tr, 1))), fs.expand(keys, fs.encrypt(keys, b, stable_seed(tr, 2))), p.q)
            want = (a + b) % p.q
        elif op == "mul":
            a, b = (int(x) for x in rng.integers(0, 1000, 2))
            C = fs.mul(fs.expand(keys, fs.encrypt(keys, a, stable_seed(tr, 1))), fs.expand(keys, fs.encrypt(keys, b, stable_seed(tr, 2))), p.q)
            want = (a * b) % p.q
        elif op == "dot4":
            xs = [int(x) for x in rng.integers(0, 100, 8)]
            C = None
            for i in range(4):
                P = fs.mul(fs.expand(keys, fs.encrypt(keys, xs[i], stable_seed(tr, i, "x"))),
                           fs.expand(keys, fs.encrypt(keys, xs[4 + i], stable_seed(tr, i, "y"))), p.q)
                C = P if C is None else fs.add(C, P, p.q)
            want = sum(xs[i] * xs[4 + i] for i in range(4)) % p.q
        else:
            raise ValueError(op)
        correct += int(fs.decrypt_replica(keys, C[0]) == want)
        if tr % 5 == 4:
            keys.clear_cache()
    pc = correct / trials
    return {
        "p_replica_correct": pc,
        "trials": trials,
        "plurality_bound": {str(R): plurality_failure_bound(R, pc, p.q) for R in (15, 51, 151, 301)},
        "seconds": time.perf_counter() - t0,
        "peak_rss_gb": peak_rss_gb(),
    }


# --------------------------------------------------------------------------- benchmarks


def bench_she(cfg: dict[str, Any]) -> dict[str, Any]:
    """Per-operation time and size of the SHE pipeline (one replica)."""
    from sable import fast_she as fs

    p = fs.SheParams("bench", n=int(cfg["n"]), k=int(cfg["k"]), q=fs.Q28, eta=float(cfg["eta"]), replicas=1)
    reps = int(cfg.get("reps", 3))
    out: dict[str, list[float]] = {k: [] for k in ["x_matrix_gen", "encrypt", "expand", "add", "mul", "decrypt", "scalar_mul"]}
    nnz_exp, nnz_mul, correct = [], [], 0
    for rep in range(reps):
        keys = fs.keygen(p, stable_seed(cfg["seed"], rep))
        t0 = time.perf_counter()
        for i in range(p.k + 1):
            keys.X(i)
        out["x_matrix_gen"].append((time.perf_counter() - t0) / (p.k + 1))
        t0 = time.perf_counter(); a = fs.encrypt(keys, 3, 1); b = fs.encrypt(keys, 5, 2); out["encrypt"].append((time.perf_counter() - t0) / 2)
        t0 = time.perf_counter(); A = fs.expand(keys, a); B = fs.expand(keys, b); out["expand"].append((time.perf_counter() - t0) / 2)
        t0 = time.perf_counter(); fs.add(A, B, p.q); out["add"].append(time.perf_counter() - t0)
        t0 = time.perf_counter(); fs.scalar_mul(A, 7, p.q); out["scalar_mul"].append(time.perf_counter() - t0)
        t0 = time.perf_counter(); C = fs.mul(A, B, p.q); out["mul"].append(time.perf_counter() - t0)
        t0 = time.perf_counter(); v = fs.decrypt_replica(keys, C[0]); out["decrypt"].append(time.perf_counter() - t0)
        correct += int(v == 15)
        nnz_exp.append(fs.nnz(A)); nnz_mul.append(fs.nnz(C))
        del A, B, C
        keys.clear_cache()
    res: dict[str, Any] = {f"{k}_s": float(np.median(v)) for k, v in out.items()}
    res.update(
        expanded_nnz=float(np.mean(nnz_exp)), product_nnz=float(np.mean(nnz_mul)),
        expanded_bytes=float(np.mean(nnz_exp)) * 12, product_bytes=float(np.mean(nnz_mul)) * 12,
        full_keygen_extrapolated_s=res["x_matrix_gen_s"] * p.N,
        key_sizes=fs.key_sizes(fs.SheParams("x", p.n, p.k, p.q, p.eta, int(cfg.get("R_report", 151)))),
        decrypt_correct=correct, reps=reps, peak_rss_gb=peak_rss_gb(),
    )
    if cfg.get("compact_n_c"):
        cp = fs.CompactParams(int(cfg["compact_n_c"]), int(cfg["compact_m_c"]), float(cfg["eta"]))
        keys = fs.keygen(p, stable_seed(cfg["seed"], "compact"))
        ck = fs.compact_keygen(keys, cp, 5)
        A = fs.expand(keys, fs.encrypt(keys, 11, 3))
        terms = len(fs.last_row(A[0])[0])
        t0 = time.perf_counter(); for_key = [ck.b(i) for i in fs.last_row(A[0])[0].tolist()]; t_key = time.perf_counter() - t0
        t0 = time.perf_counter(); o = fs.compact(ck, A[0]); t_c = time.perf_counter() - t0
        t0 = time.perf_counter(); v, votes = fs.decrypt_compact(ck, o); t_d = time.perf_counter() - t0
        del for_key
        res.update(compact_terms=terms, compact_key_entries_s_per_term=t_key / terms, compact_s=t_c,
                   compact_decrypt_s=t_d, compact_decrypt_s_per_term=t_d / terms, compact_correct=int(v == 11),
                   compact_votes=votes, compact_m_c=cp.m_c, compact_n_c=cp.n_c)
    return res


def bench_agg(cfg: dict[str, Any]) -> dict[str, Any]:
    """One aggregation round of a backend on random client vectors."""
    from evaluation.aggregation import make_backend, quantized_reference

    d, K = int(cfg["d"]), int(cfg["K"])
    rng = np.random.default_rng(stable_seed(cfg["seed"], d, K))
    deltas = [rng.normal(0, 0.02, d).astype(np.float32) for _ in range(K)]
    w = np.full(K, 1.0 / K)
    b = make_backend(cfg["method"], d, K, int(cfg["seed"]), **cfg.get("backend_opts", {}))
    t0 = time.perf_counter()
    setup = b.setup()
    t_setup = time.perf_counter() - t0
    rounds = []
    for r in range(int(cfg.get("rounds", 2))):
        agg, met = b.run_round(r, deltas, w)
        met["max_abs_err_vs_quantized"] = float(np.max(np.abs(agg - quantized_reference(deltas, w))))
        rounds.append(met)
    keys = [k for k, v in rounds[0].items() if isinstance(v, (int, float)) and not isinstance(v, bool)]
    res = {k: float(np.median([m[k] for m in rounds])) for k in keys}
    res.update(setup=setup, setup_s=t_setup, backend=b.describe(), extrapolated=bool(rounds[0].get("extrapolated", False)),
               peak_rss_gb=peak_rss_gb())
    return res


# --------------------------------------------------------------------------- attacks


def attack_two_sparse(cfg: dict[str, Any]) -> dict[str, Any]:
    from sable.sparse_attacks import generate_two_sparse_instance, solve_two_sparse_lpn

    n, m = int(cfg["n"]), int(cfg["ratio"] * cfg["n"])
    inst = generate_two_sparse_instance(n, m, int(cfg.get("q", 65537)), float(cfg["eta"]), seed=int(cfg["seed"]))
    t0 = time.perf_counter()
    out = solve_two_sparse_lpn(inst["I"], inst["J"], inst["ai"], inst["aj"], inst["b"], n, inst["q"])
    secs = time.perf_counter() - t0
    frac = float(np.mean(out["s"] == inst["s"]))
    return {"fraction_correct": frac, "exact": bool(frac == 1.0), "reached": out["reached"],
            "root_votes": out["root_votes"], "seconds": secs, "samples": m, "peak_rss_gb": peak_rss_gb()}


def attack_known_plaintext(cfg: dict[str, Any]) -> dict[str, Any]:
    """Recover s from the expansion-key matrix that encrypts 1 (one linear solve)."""
    from sable import fast_she as fs
    from sable.sparse_attacks import solve_mod

    n, q, eta = int(cfg["n"]), int(cfg.get("q", 65537)), float(cfg["eta"])
    rng = np.random.default_rng(stable_seed(cfg["seed"], n, eta))
    s = rng.integers(0, q, n, dtype=np.int64)
    p = fs.SheParams("kp", n=n, k=int(cfg.get("k", 3)), q=q, eta=eta)
    X = fs.gsw_matrix(p, s, 1, rng)
    Xd = X.toarray()
    A = Xd[:, :n].copy()
    A[np.arange(n), np.arange(n)] -= 1
    bvec = Xd[:, n].copy()
    bvec[n] -= 1
    t0 = time.perf_counter()
    s_hat = solve_mod(A % p.q, bvec % p.q, p.q)
    secs = time.perf_counter() - t0
    ok = s_hat is not None and bool(np.array_equal(s_hat % p.q, s % p.q))
    return {"success": ok, "seconds": secs, "predicted_success": (1 - eta) ** (n + 1), "q": p.q, "peak_rss_gb": peak_rss_gb()}


# --------------------------------------------------------------------------- tables


LATTICE_REFERENCE = {
    "source": "HomomorphicEncryption.org security standard (Albrecht et al., 2018/2021), 128-bit classical, ternary secrets",
    "rows": [
        {"scheme": "CKKS (TenSEAL)", "N": 8192, "log_q": 160, "max_log_q_128": 218},
        {"scheme": "BFV (TenSEAL default)", "N": 8192, "log_q": 218, "max_log_q_128": 218},
        {"scheme": "LWE-KAHE (this harness)", "n": 2048, "log_q": 32, "max_log_q_128": 54},
    ],
    "note": "Paillier 3072-bit ~128-bit classical, not post-quantum; SecAgg+ relies on ECDH + PRG, not post-quantum",
}


def params_tables(cfg: dict[str, Any]) -> dict[str, Any]:
    from sable import fast_she as fs
    from sable.fast_regev import FL_PARAMS
    from sable.parameter_sets import CANDIDATES, screen_candidate

    cand = []
    for c in CANDIDATES:
        s = screen_candidate(c)
        cand.append({"name": c.name, "target_bits": c.target_bits, "q": c.q, "n": c.n, "k": c.k, "eta": c.eta,
                     "n_c": c.n_c, "m_c": c.m_c, "replicas": c.replicas, "min_bits": s.min_finite_screen_bits,
                     "final_failure_bound": s.final_replicated_failure_bound, "status": s.status, "blockers": list(s.blockers),
                     "sparse_screen": s.attack_screens.get("sparse_specific"),
                     "sizes": fs.key_sizes(fs.SheParams("x", c.n, c.k, fs.Q28, c.eta, c.replicas), fs.CompactParams(c.n_c, c.m_c, c.eta_c))})
    fl = []
    for name, p in FL_PARAMS.items():
        for d in (7850, 18378, 101770):
            for rounds in (1, 100):
                fl.append({"name": name, "d": d, "rounds_per_key": rounds, "samples_per_key": d * p.replicas * rounds,
                           "screen": p.security_screen(d * p.replicas * rounds),
                           "upload_bytes": p.upload_bytes(d), "failure_bound_K100": p.failure_bound(100),
                           "failure_bound_K500": p.failure_bound(500)})
    return {"candidates": cand, "fl_params": fl, "lattice_reference": LATTICE_REFERENCE}


TASKS = {
    "correctness_agg": correctness_agg,
    "correctness_she": correctness_she,
    "bench_she": bench_she,
    "bench_agg": bench_agg,
    "attack_two_sparse": attack_two_sparse,
    "attack_known_plaintext": attack_known_plaintext,
    "params_tables": params_tables,
}
