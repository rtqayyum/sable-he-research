"""Secure-aggregation backends used by the FL case study and the crypto benchmarks.

Every backend aggregates client vectors that are already weighted on the
client side (FedAvg weight p_c = n_c / sum n).  Exact backends share one
fixed-point grid (scale 2^17, clip 3.9) so their decrypted aggregate must
equal the same integer reference; CKKS is approximate and is compared with
the float reference.

Threat-model notes (recorded in every result row):
* sable-ka, lwe-kahe: key-additive.  Each client has its own secret; the
  server only receives the summed key, so it can decrypt only the sum.
* secagg+: pairwise masking (Bell et al. 2020 graph variant), no dropouts.
* paillier, ckks, bfv: one shared key pair held by the clients.  This is how
  these schemes are commonly used in FL papers.  A malicious client can
  decrypt other clients' uploads.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from evaluation.common import stable_seed

SCALE = 2**17
CLIP = 3.9


def fixed_point(x: np.ndarray, weight: float) -> np.ndarray:
    return np.rint(np.clip(np.asarray(x, dtype=np.float64), -CLIP, CLIP) * weight * SCALE).astype(np.int64)


def quantized_reference(deltas: list[np.ndarray], weights: np.ndarray) -> np.ndarray:
    acc = np.zeros(deltas[0].shape[0], dtype=np.int64)
    for x, w in zip(deltas, weights):
        acc += fixed_point(x, float(w))
    return acc.astype(np.float64) / SCALE


def float_reference(deltas: list[np.ndarray], weights: np.ndarray) -> np.ndarray:
    acc = np.zeros(deltas[0].shape[0], dtype=np.float64)
    for x, w in zip(deltas, weights):
        acc += np.clip(np.asarray(x, dtype=np.float64), -CLIP, CLIP) * float(w)
    return acc


@dataclass
class Backend:
    name: str = "base"
    assumption: str = ""
    post_quantum: bool = False
    key_model: str = ""
    exact: bool = True
    d: int = 0
    K: int = 0
    seed: int = 0
    opts: dict[str, Any] = field(default_factory=dict)

    def setup(self) -> dict[str, Any]:
        return {}

    def reference(self, deltas: list[np.ndarray], weights: np.ndarray) -> np.ndarray:
        return quantized_reference(deltas, weights) if self.exact else float_reference(deltas, weights)

    def run_round(self, r: int, deltas: list[np.ndarray], weights: np.ndarray) -> tuple[np.ndarray, dict[str, Any]]:
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {"backend": self.name, "assumption": self.assumption, "post_quantum": self.post_quantum,
                "key_model": self.key_model, "exact": self.exact, "opts": self.opts}


def _metrics(**kw: Any) -> dict[str, Any]:
    base = {"upload_bytes_client": 0, "client_encrypt_s": 0.0, "server_aggregate_s": 0.0, "decrypt_s": 0.0,
            "coord_failures": 0, "extrapolated": False}
    base.update(kw)
    return base


# --------------------------------------------------------------------------- plaintext


class PlainBackend(Backend):
    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        super().__init__("plain", "none", False, "none (no privacy)", False, d, K, seed, opts)

    def run_round(self, r, deltas, weights):
        t0 = time.perf_counter()
        agg = float_reference(deltas, weights)
        return agg, _metrics(upload_bytes_client=self.d * 4, server_aggregate_s=time.perf_counter() - t0)


# --------------------------------------------------------------------------- SABLE key-additive


class SableBackend(Backend):
    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        from sable.fast_regev import FL_PARAMS, params_for_clients

        if "param_set" in opts:
            self.p = FL_PARAMS[opts["param_set"]]
        else:  # replicas chosen from the plurality bound for this number of clients
            self.p = params_for_clients(int(opts.get("n", 65536)), float(opts.get("eta", 0.003)), K,
                                        k=int(opts.get("k", 5)), target_failure=float(opts.get("target_failure", 1e-12)))
        label = opts.get("label", "sable")
        super().__init__(label, f"sparse q-ary LPN (n={self.p.n}, k={self.p.k}, eta={self.p.eta}, R={self.p.replicas})", True,
                         "key-additive (server sees only the summed key)", True, d, K, seed, opts)
        self.keys: list[np.ndarray] = []

    def setup(self):
        from sable.fast_regev import keygen

        t0 = time.perf_counter()
        self.keys = [keygen(self.p, stable_seed(self.seed, "sable-key", c)) for c in range(self.K)]
        self.T = sum(self.keys) % self.p.q
        return {"keygen_s_client": (time.perf_counter() - t0) / max(1, self.K),
                "key_bytes_client": math.ceil(self.p.n * self.p.coeff_bits / 8),
                "params": self.p.to_jsonable(),
                "failure_bound": self.p.failure_bound(self.K),
                "samples_per_key_per_round": self.d * self.p.replicas}

    def run_round(self, r, deltas, weights):
        from sable.fast_regev import aggregate, decrypt_sum, encrypt, to_signed

        q = self.p.q
        round_seed = stable_seed(self.seed, "sable-round", r)
        enc_t: list[float] = []
        t_agg = 0.0
        B = None
        expected = np.zeros(self.d, dtype=np.int64)
        for c, (x, w) in enumerate(zip(deltas, weights)):  # server adds uploads as they arrive
            m = fixed_point(x, float(w)) % q
            expected = (expected + m) % q
            t0 = time.perf_counter()
            b = encrypt(self.p, self.keys[c], m, round_seed, stable_seed(self.seed, "noise", r, c))
            enc_t.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            B = b if B is None else aggregate([B, b], q)
            t_agg += time.perf_counter() - t0
            del b
        t0 = time.perf_counter()
        out = decrypt_sum(self.p, self.T, B, round_seed)
        t_dec = time.perf_counter() - t0
        fails = int(np.sum(out["value"] != expected))
        agg = to_signed(out["value"], q).astype(np.float64) / SCALE
        return agg, _metrics(upload_bytes_client=self.p.upload_bytes(self.d), client_encrypt_s=float(np.mean(enc_t)),
                             server_aggregate_s=t_agg, decrypt_s=t_dec, coord_failures=fails,
                             min_votes=int(out["votes"].min()), replicas=self.p.replicas)


# --------------------------------------------------------------------------- LWE key-additive (Regev/KAHE)


class LweKaheBackend(Backend):
    """Key-additive Regev/LWE with a public seeded matrix, ternary secrets, q = 2^32.

    n = 2048, sigma = 3.2, log q = 32 is inside the 128-bit region of the
    HomomorphicEncryption.org standard table for ternary secrets.
    """

    N_LWE = 2048
    P_BITS = 20  # plaintext modulus 2^20, delta = 2^12

    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        super().__init__("lwe-kahe", "LWE (n=2048, q=2^32, ternary, sigma=3.2)", True,
                         "key-additive (server sees only the summed key)", True, d, K, seed, opts)
        if K > 1000:
            raise ValueError("float64-exact A*T needs K <= 1000")

    def setup(self):
        t0 = time.perf_counter()
        self.keys = [np.random.default_rng(stable_seed(self.seed, "lwe-key", c)).integers(-1, 2, self.N_LWE).astype(np.float64)
                     for c in range(self.K)]
        self.T = np.sum(self.keys, axis=0)
        return {"keygen_s_client": (time.perf_counter() - t0) / self.K, "key_bytes_client": self.N_LWE * 4}

    def _A(self, round_seed: int, start: int, stop: int) -> np.ndarray:
        g = np.random.default_rng(stable_seed(round_seed, start))
        return g.integers(0, 2**32, size=(stop - start, self.N_LWE), dtype=np.uint64).astype(np.float64)

    def _As(self, round_seed: int, s: np.ndarray) -> np.ndarray:
        out = np.empty(self.d, dtype=np.uint64)
        step = 8192
        for a in range(0, self.d, step):
            b = min(self.d, a + step)
            v = self._A(round_seed, a, b) @ s  # exact: |entries| < 2^53
            out[a:b] = np.mod(v, 2.0**32).astype(np.uint64)
        return out

    def run_round(self, r, deltas, weights):
        round_seed = stable_seed(self.seed, "lwe-round", r)
        delta = 1 << (32 - self.P_BITS)
        P = 1 << self.P_BITS
        enc_t: list[float] = []
        B = np.zeros(self.d, dtype=np.int64)
        t_agg = 0.0
        for c, (x, w) in enumerate(zip(deltas, weights)):  # server adds uploads as they arrive
            m = fixed_point(x, float(w)) % P
            t0 = time.perf_counter()
            e = np.rint(np.random.default_rng(stable_seed(self.seed, "lwe-e", r, c)).normal(0, 3.2, self.d)).astype(np.int64)
            b = (self._As(round_seed, self.keys[c]).astype(np.int64) + e + m * delta) % (1 << 32)
            enc_t.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            B = (B + b) % (1 << 32)
            t_agg += time.perf_counter() - t0
        t0 = time.perf_counter()
        AT = self._As(round_seed, self.T)
        phase = (B - AT.astype(np.int64)) % (1 << 32)
        mval = np.rint(phase / delta).astype(np.int64) % P
        signed = np.where(mval >= P // 2, mval - P, mval)
        t_dec = time.perf_counter() - t0
        expected = sum(fixed_point(x, float(w)) for x, w in zip(deltas, weights))
        fails = int(np.sum(signed != expected))
        return signed.astype(np.float64) / SCALE, _metrics(upload_bytes_client=self.d * 4, client_encrypt_s=float(np.mean(enc_t)),
                                                         server_aggregate_s=t_agg, decrypt_s=t_dec, coord_failures=fails)


# --------------------------------------------------------------------------- SecAgg+ masking


class SecAggPlusBackend(Backend):
    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        super().__init__("secagg+", "pairwise masking (PRG + key agreement)", False,
                         "pairwise masks over an O(log K)-degree graph; no dropouts", True, d, K, seed, opts)
        deg = min(K - 1, 2 * math.ceil(math.log2(max(2, K))))
        self.deg = deg - (deg % 2) if K > 2 else K - 1
        rng = np.random.default_rng(stable_seed(seed, "graph"))
        order = rng.permutation(K)
        self.edges: set[tuple[int, int]] = set()
        for pos in range(K):
            for h in range(1, self.deg // 2 + 1):
                i, j = int(order[pos]), int(order[(pos + h) % K])
                if i != j:
                    self.edges.add((min(i, j), max(i, j)))

    def setup(self):
        per_client = [sum(1 for e in self.edges if c in e) for c in range(self.K)]
        return {"graph_degree_mean": float(np.mean(per_client)), "key_bytes_client": 0}

    def run_round(self, r, deltas, weights):
        M = 1 << 32
        enc_t: list[float] = []
        nbrs: dict[int, list[tuple[int, int]]] = {c: [] for c in range(self.K)}
        for i, j in self.edges:
            nbrs[i].append((i, j))
            nbrs[j].append((i, j))
        S = np.zeros(self.d, dtype=np.int64)
        t_agg = 0.0
        for c, (x, w) in enumerate(zip(deltas, weights)):  # server adds uploads as they arrive
            t0 = time.perf_counter()
            y = fixed_point(x, float(w)) % M
            for i, j in nbrs[c]:
                mask = np.random.default_rng(stable_seed(self.seed, "pair", r, i, j)).integers(0, M, self.d, dtype=np.int64)
                y = (y + mask) % M if c == i else (y - mask) % M
            enc_t.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            S = (S + y) % M
            t_agg += time.perf_counter() - t0
        signed = np.where(S >= M // 2, S - M, S)
        expected = sum(fixed_point(x, float(w)) for x, w in zip(deltas, weights))
        fails = int(np.sum(signed != expected))
        deg = np.mean([len(nbrs[c]) for c in range(self.K)])
        overhead = int(deg * (32 + 2 * 32))  # public key + two Shamir shares per neighbour
        return signed.astype(np.float64) / SCALE, _metrics(upload_bytes_client=self.d * 4 + overhead,
                                                         client_encrypt_s=float(np.mean(enc_t)), server_aggregate_s=t_agg,
                                                         coord_failures=fails)


# --------------------------------------------------------------------------- Paillier (python-phe)


class PaillierBackend(Backend):
    """Shared-key Paillier.  Too slow to run on every coordinate, so it encrypts a
    sample of coordinates for a few clients and extrapolates linearly in d and K."""

    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        bits = int(opts.get("key_bits", 3072))
        super().__init__("paillier", f"DCR (Paillier {bits}-bit)", False, "shared key pair held by clients", True, d, K, seed, opts)
        self.bits = bits
        self.coord_limit = int(opts.get("coord_limit", 256))
        self.client_limit = int(opts.get("client_limit", 3))

    def setup(self):
        from phe import paillier

        t0 = time.perf_counter()
        self.pk, self.sk = paillier.generate_paillier_keypair(n_length=self.bits)
        return {"keygen_s": time.perf_counter() - t0, "key_bytes_client": 0}

    def run_round(self, r, deltas, weights):
        L = min(self.d, self.coord_limit)
        C = min(self.K, self.client_limit)
        cts, enc_t = [], []
        for c in range(C):
            m = fixed_point(deltas[c][:L], float(weights[c]))
            t0 = time.perf_counter()
            cts.append([self.pk.encrypt(int(v)) for v in m])
            enc_t.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        acc = cts[0]
        for other in cts[1:]:
            acc = [a + b for a, b in zip(acc, other)]
        t_agg = time.perf_counter() - t0
        t0 = time.perf_counter()
        dec = np.array([self.sk.decrypt(a) for a in acc], dtype=np.int64)
        t_dec = time.perf_counter() - t0
        exp_part = sum(fixed_point(deltas[c][:L], float(weights[c])) for c in range(C))
        fails = int(np.sum(dec != exp_part))
        ct_bytes = 2 * self.bits // 8
        scale_d = self.d / L
        agg_scale = scale_d * (self.K - 1) / max(1, C - 1)
        agg = quantized_reference(deltas, weights)  # exact scheme: decrypted sum equals the reference
        return agg, _metrics(upload_bytes_client=self.d * ct_bytes, client_encrypt_s=float(np.mean(enc_t)) * scale_d,
                             server_aggregate_s=t_agg * agg_scale, decrypt_s=t_dec * scale_d, coord_failures=fails,
                             extrapolated=True, sampled_coords=L, sampled_clients=C)


# --------------------------------------------------------------------------- TenSEAL CKKS / BFV


class TensealBackend(Backend):
    def __init__(self, d: int, K: int, seed: int, scheme: str = "ckks", **opts: Any) -> None:
        exact = scheme == "bfv"
        super().__init__(scheme, f"RLWE ({scheme.upper()}, N=8192, TenSEAL/SEAL)", True, "shared key pair held by clients",
                         exact, d, K, seed, opts)
        self.scheme = scheme

    def setup(self):
        import tenseal as ts

        t0 = time.perf_counter()
        if self.scheme == "ckks":
            ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 60])
            ctx.global_scale = 2**40
            self.slots = 4096
        else:
            ctx = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=8192, plain_modulus=1032193)
            self.slots = 8192
        self.ctx = ctx
        return {"keygen_s": time.perf_counter() - t0, "key_bytes_client": 0, "slots": self.slots}

    def run_round(self, r, deltas, weights):
        import tenseal as ts

        chunks = [(a, min(self.d, a + self.slots)) for a in range(0, self.d, self.slots)]
        enc_t, sizes = [], []
        acc = None
        t_agg = 0.0
        for c, (x, w) in enumerate(zip(deltas, weights)):  # server adds uploads as they arrive
            t0 = time.perf_counter()
            if self.scheme == "ckks":
                v = np.clip(np.asarray(x, dtype=np.float64), -CLIP, CLIP) * float(w)
                cts = [ts.ckks_vector(self.ctx, v[a:b].tolist()) for a, b in chunks]
            else:
                v = fixed_point(x, float(w))
                cts = [ts.bfv_vector(self.ctx, v[a:b].tolist()) for a, b in chunks]
            enc_t.append(time.perf_counter() - t0)
            if c < 3:  # serialized size is identical for every client; measure a few
                sizes.append(sum(len(ct.serialize()) for ct in cts))
            t0 = time.perf_counter()
            acc = cts if acc is None else [a + b for a, b in zip(acc, cts)]
            t_agg += time.perf_counter() - t0
            del cts
        t0 = time.perf_counter()
        out = np.concatenate([np.asarray(c.decrypt(), dtype=np.float64) for c in acc])[: self.d]
        t_dec = time.perf_counter() - t0
        if self.scheme == "bfv":
            expected = sum(fixed_point(x, float(w)) for x, w in zip(deltas, weights))
            fails = int(np.sum(np.rint(out).astype(np.int64) != expected))
            agg = out / SCALE
            err = 0.0
        else:
            ref = float_reference(deltas, weights)
            fails = 0
            agg = out
            err = float(np.max(np.abs(out - ref)))
        return agg, _metrics(upload_bytes_client=int(np.mean(sizes)), client_encrypt_s=float(np.mean(enc_t)),
                             server_aggregate_s=t_agg, decrypt_s=t_dec, coord_failures=fails, ckks_max_abs_err=err)


BACKENDS = {
    "plain": PlainBackend,
    "sable": SableBackend,
    "sable_ln": lambda d, K, seed, **o: SableBackend(d, K, seed, **{"n": 131072, "eta": 0.001, "label": "sable_ln", **o}),
    "lwe": LweKaheBackend,
    "secagg": SecAggPlusBackend,
    "paillier": PaillierBackend,
    "ckks": lambda d, K, seed, **o: TensealBackend(d, K, seed, scheme="ckks", **o),
    "bfv": lambda d, K, seed, **o: TensealBackend(d, K, seed, scheme="bfv", **o),
}


def make_backend(method: str, d: int, K: int, seed: int, **opts: Any) -> Backend:
    if method not in BACKENDS:
        raise KeyError(f"unknown backend {method!r}")
    return BACKENDS[method](d, K, seed, **opts)


def available_backends() -> dict[str, str]:
    """Check which optional libraries are importable."""
    out = {"plain": "ok", "sable": "ok", "sable_ln": "ok", "lwe": "ok", "secagg": "ok"}
    for name, mod in [("paillier", "phe"), ("ckks", "tenseal"), ("bfv", "tenseal")]:
        try:
            __import__(mod)
            out[name] = "ok"
        except Exception as exc:  # noqa: BLE001
            out[name] = f"unavailable: {type(exc).__name__}: {exc}"
    return out
