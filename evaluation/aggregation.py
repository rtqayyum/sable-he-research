"""Secure-aggregation backends used by the FL case study and the crypto benchmarks.

Every backend aggregates client vectors that are already weighted on the
client side (FedAvg weight p_c = n_c / sum n).  Exact backends encode each
weighted value on a fixed-point grid whose scale fills that scheme's
plaintext space (scale_for_capacity), so the decrypted aggregate equals the
integer reference at the backend's own scale.  A single coarse grid shared
by all methods (2^-17, set by a 20-bit plaintext space) rounded 99% of the
per-client values to zero at K = 1000; with per-scheme scales the rounding
error is below 1e-7 per coordinate.  CKKS is approximate and is compared
with the float reference.

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

SCALE = 2**17  # legacy default; backends use scale_for_capacity
CLIP = 3.9  # each client clips its update to [-CLIP, CLIP] before weighting


def scale_for_capacity(half_range: int, clients: int) -> int:
    """Largest power-of-two scale with K * 0.5 + CLIP * scale < half_range.

    Weights sum to 1, so the weighted sum of clipped updates is at most CLIP in
    absolute value; each client's rounding adds at most 0.5.  The aggregate
    therefore never wraps around the plaintext modulus.
    """
    return 1 << int(math.floor(math.log2((half_range - clients) / CLIP)))


def fixed_point(x: np.ndarray, weight: float, scale: int = SCALE) -> np.ndarray:
    v = np.clip(np.asarray(x, dtype=np.float64), -CLIP, CLIP) * weight * float(scale)
    return np.rint(v).astype(np.int64)


def quantized_reference(deltas: list[np.ndarray], weights: np.ndarray, scale: int = SCALE) -> np.ndarray:
    acc = np.zeros(deltas[0].shape[0], dtype=np.int64)
    for x, w in zip(deltas, weights):
        acc += fixed_point(x, float(w), scale)
    return acc.astype(np.float64) / scale


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
    scale: int = SCALE

    def setup(self) -> dict[str, Any]:
        return {}

    def fp(self, x: np.ndarray, w: float) -> np.ndarray:
        return fixed_point(x, w, self.scale)

    def expected_sum(self, deltas: list[np.ndarray], weights: np.ndarray) -> np.ndarray:
        acc = np.zeros(self.d, dtype=np.int64)
        for x, w in zip(deltas, weights):
            acc += self.fp(x, float(w))
        return acc

    def reference(self, deltas: list[np.ndarray], weights: np.ndarray) -> np.ndarray:
        return quantized_reference(deltas, weights, self.scale) if self.exact else float_reference(deltas, weights)

    def run_round(self, r: int, deltas: list[np.ndarray], weights: np.ndarray) -> tuple[np.ndarray, dict[str, Any]]:
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {"backend": self.name, "assumption": self.assumption, "post_quantum": self.post_quantum,
                "key_model": self.key_model, "exact": self.exact, "opts": self.opts,
                "fixed_point_bits": int(math.log2(self.scale)) if self.exact else None}


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
        self.scale = scale_for_capacity(self.p.q // 2, K)
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
            m = self.fp(x, float(w)) % q
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
        agg = to_signed(out["value"], q).astype(np.float64) / self.scale
        return agg, _metrics(upload_bytes_client=self.p.upload_bytes(self.d), client_encrypt_s=float(np.mean(enc_t)),
                             server_aggregate_s=t_agg, decrypt_s=t_dec, coord_failures=fails,
                             min_votes=int(out["votes"].min()), replicas=self.p.replicas)


# --------------------------------------------------------------------------- LWE key-additive (Regev/KAHE)


class LweKaheBackend(Backend):
    """Key-additive Regev/LWE with a public seeded matrix and ternary secrets, modulus q = 2^64.

    n = 4096 with log q = 64 and sigma = 3.2 is inside the 128-bit region of
    the HomomorphicEncryption.org standard for ternary secrets (n = 4096 allows
    log q <= 109).  The plaintext space is 2^40 (delta = 2^24), large enough
    for a fine fixed-point grid with up to 1000 clients.  Arithmetic mod 2^64
    uses numpy uint64 wrap-around.
    """

    N_LWE = 4096
    P_BITS = 40
    DELTA_BITS = 64 - P_BITS
    CHUNK = 1024

    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        super().__init__("lwe-kahe", "LWE (n=4096, q=2^64, ternary, sigma=3.2)", True,
                         "key-additive (server sees only the summed key)", True, d, K, seed, opts)
        self.scale = scale_for_capacity(1 << (self.P_BITS - 1), K)

    def setup(self):
        t0 = time.perf_counter()
        self.keys = [np.random.default_rng(stable_seed(self.seed, "lwe-key", c)).integers(-1, 2, self.N_LWE).astype(np.int64)
                     for c in range(self.K)]
        self.T = np.sum(self.keys, axis=0).astype(np.int64)
        return {"keygen_s_client": (time.perf_counter() - t0) / self.K, "key_bytes_client": self.N_LWE // 4}

    def _As(self, round_seed: int, s: np.ndarray) -> np.ndarray:
        """A s mod 2^64 for the seeded public matrix A (d x n, uniform 64-bit entries)."""
        s_u = np.asarray(s, dtype=np.int64).view(np.uint64)
        out = np.empty(self.d, dtype=np.uint64)
        for a in range(0, self.d, self.CHUNK):
            b = min(self.d, a + self.CHUNK)
            A = np.random.default_rng(stable_seed(round_seed, a)).bit_generator.random_raw((b - a, self.N_LWE))
            out[a:b] = (A * s_u).sum(axis=1, dtype=np.uint64)
        return out

    def run_round(self, r, deltas, weights):
        round_seed = stable_seed(self.seed, "lwe-round", r)
        delta = np.uint64(1 << self.DELTA_BITS)
        enc_t: list[float] = []
        B = np.zeros(self.d, dtype=np.uint64)
        t_agg = 0.0
        expected = np.zeros(self.d, dtype=np.int64)
        for c, (x, w) in enumerate(zip(deltas, weights)):  # server adds uploads as they arrive
            m = self.fp(x, float(w))
            expected += m
            t0 = time.perf_counter()
            e = np.rint(np.random.default_rng(stable_seed(self.seed, "lwe-e", r, c)).normal(0, 3.2, self.d)).astype(np.int64)
            b = self._As(round_seed, self.keys[c]) + e.view(np.uint64) + m.view(np.uint64) * delta
            enc_t.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            B += b
            t_agg += time.perf_counter() - t0
        t0 = time.perf_counter()
        phase = (B - self._As(round_seed, self.T)).view(np.int64)  # = sum(m) * delta + sum(e), as a signed 64-bit value
        half = np.int64(1 << (self.DELTA_BITS - 1))
        msum = np.floor_divide(phase + half, np.int64(1 << self.DELTA_BITS))
        t_dec = time.perf_counter() - t0
        fails = int(np.sum(msum != expected))
        return msum.astype(np.float64) / self.scale, _metrics(upload_bytes_client=self.d * 8, client_encrypt_s=float(np.mean(enc_t)),
                                                            server_aggregate_s=t_agg, decrypt_s=t_dec, coord_failures=fails)


# --------------------------------------------------------------------------- SecAgg+ masking


class SecAggPlusBackend(Backend):
    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        super().__init__("secagg+", "pairwise masking (PRG + key agreement)", False,
                         "pairwise masks over an O(log K)-degree graph; no dropouts", True, d, K, seed, opts)
        self.scale = scale_for_capacity(1 << 31, K)
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
            y = self.fp(x, float(w)) % M
            for i, j in nbrs[c]:
                mask = np.random.default_rng(stable_seed(self.seed, "pair", r, i, j)).integers(0, M, self.d, dtype=np.int64)
                y = (y + mask) % M if c == i else (y - mask) % M
            enc_t.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            S = (S + y) % M
            t_agg += time.perf_counter() - t0
        signed = np.where(S >= M // 2, S - M, S)
        expected = self.expected_sum(deltas, weights)
        fails = int(np.sum(signed != expected))
        deg = np.mean([len(nbrs[c]) for c in range(self.K)])
        overhead = int(deg * (32 + 2 * 32))  # public key + two Shamir shares per neighbour
        return signed.astype(np.float64) / self.scale, _metrics(upload_bytes_client=self.d * 4 + overhead,
                                                         client_encrypt_s=float(np.mean(enc_t)), server_aggregate_s=t_agg,
                                                         coord_failures=fails)


# --------------------------------------------------------------------------- Paillier (python-phe)


class PaillierBackend(Backend):
    """Shared-key Paillier.  Too slow to run on every coordinate, so it encrypts a
    sample of coordinates for a few clients and extrapolates linearly in d and K."""

    def __init__(self, d: int, K: int, seed: int, **opts: Any) -> None:
        bits = int(opts.get("key_bits", 3072))
        super().__init__("paillier", f"DCR (Paillier {bits}-bit)", False, "shared key pair held by clients", True, d, K, seed, opts)
        self.scale = 1 << 40
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
            m = self.fp(deltas[c][:L], float(weights[c]))
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
        exp_part = sum(self.fp(deltas[c][:L], float(weights[c])) for c in range(C))
        fails = int(np.sum(dec != exp_part))
        ct_bytes = 2 * self.bits // 8
        scale_d = self.d / L
        agg_scale = scale_d * (self.K - 1) / max(1, C - 1)
        agg = self.reference(deltas, weights)  # exact scheme: decrypted sum equals the reference
        return agg, _metrics(upload_bytes_client=self.d * ct_bytes, client_encrypt_s=float(np.mean(enc_t)) * scale_d,
                             server_aggregate_s=t_agg * agg_scale, decrypt_s=t_dec * scale_d, coord_failures=fails,
                             extrapolated=True, sampled_coords=L, sampled_clients=C)


# --------------------------------------------------------------------------- TenSEAL CKKS / BFV


class TensealBackend(Backend):
    BFV_PLAIN = 2147352577  # prime, = 1 mod 2*8192 (batching), 31 bits
    def __init__(self, d: int, K: int, seed: int, scheme: str = "ckks", **opts: Any) -> None:
        exact = scheme == "bfv"
        super().__init__(scheme, f"RLWE ({scheme.upper()}, N=8192, TenSEAL/SEAL)", True, "shared key pair held by clients",
                         exact, d, K, seed, opts)
        self.scheme = scheme
        if exact:
            self.scale = scale_for_capacity((self.BFV_PLAIN - 1) // 2, K)

    def setup(self):
        import tenseal as ts

        t0 = time.perf_counter()
        if self.scheme == "ckks":
            ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 60])
            ctx.global_scale = 2**40
            self.slots = 4096
        else:
            ctx = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=8192, plain_modulus=self.BFV_PLAIN)
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
                v = self.fp(x, float(w))
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
            expected = self.expected_sum(deltas, weights)
            fails = int(np.sum(np.rint(out).astype(np.int64) != expected))
            agg = out / self.scale
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
