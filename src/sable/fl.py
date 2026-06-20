"""Federated-learning aggregation helpers for SABLE-HE.

The native encrypted FL path supports additive/linear aggregation:
``sum``, ``mean``, ``weighted_sum``, ``weighted_average``, ``FedAvg``, and
``FedSGD``.  These operations use encrypted addition and public scalar
multiplication, which are the server-side operations needed for standard
FedAvg-style aggregation.

Comparison/ranking methods such as min, max, median, trimmed mean, geometric
median, Krum, and Multi-Krum are provided for plaintext tensors or for a
decryptor-side workflow after decryption.  They are not silently presented as
native encrypted operations because encrypted comparison requires a dedicated
comparison-circuit backend.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from numbers import Number
from typing import Any, Iterator, Mapping, Sequence

from . import operations as ops
from .params import SableParams
from .sable import KeyPair, compact_c7, decrypt_c7, encrypt, expand, keygen_c7

try:  # Optional dependency; the package works without NumPy for Python lists.
    import numpy as _np  # type: ignore
except Exception:  # pragma: no cover
    _np = None  # type: ignore


class EncryptedComparisonNotSupported(NotImplementedError):
    """Raised when an encrypted aggregation requires comparison/sorting."""


UnsupportedEncryptedAggregation = EncryptedComparisonNotSupported


@dataclass(frozen=True)
class FixedPointEncoder:
    """Signed fixed-point encoder over a prime field.

    Parameters
    ----------
    q:
        Optional field modulus.  If omitted, pass ``q`` to ``encode``/``decode``.
    scale:
        Number of integer units per real unit.  ``scale=1000`` keeps three
        decimal places.
    strict_range:
        If true, reject encoded values outside the signed field interval.
    """

    q: int | None = None
    scale: int = 1000
    strict_range: bool = True

    def __post_init__(self) -> None:
        if self.scale <= 0:
            raise ValueError("scale must be positive")
        if self.q is not None and self.q < 3:
            raise ValueError("q must be at least 3")

    def _q(self, q: int | None = None) -> int:
        modulus = self.q if q is None else q
        if modulus is None:
            raise ValueError("field modulus q is required")
        return int(modulus)

    def encode(self, value: int | float, q: int | None = None) -> int:
        if not isinstance(value, Number):
            raise TypeError(f"cannot fixed-point encode non-number {type(value)!r}")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("cannot encode NaN or infinity")
        modulus = self._q(q)
        z = int(round(float(value) * self.scale))
        if self.strict_range and not (-(modulus // 2) < z < modulus // 2):
            raise ValueError(
                f"encoded value {z} is outside signed field range for q={modulus}; "
                "increase q, reduce scale, or normalize the values"
            )
        return z % modulus

    def encode_scalar(self, value: int | float, q: int | None = None) -> int:
        return self.encode(value, q=q)

    def decode_int(self, value: int, q: int | None = None) -> int:
        modulus = self._q(q)
        z = int(value) % modulus
        return z - modulus if z > modulus // 2 else z

    def decode(self, value: int, *, divisor: int | float = 1, q: int | None = None) -> float:
        if divisor == 0:
            raise ZeroDivisionError("decode divisor cannot be zero")
        return self.decode_int(value, q=q) / (self.scale * divisor)

    def decode_scalar(self, value: int, q: int | None = None, *, divisor: int | float = 1) -> float:
        return self.decode(value, q=q, divisor=divisor)


@dataclass(frozen=True)
class TensorSpec:
    """Dependency-optional tree/tensor shape descriptor."""

    kind: str
    shape: tuple[int, ...] = ()
    dtype: str | None = None
    children: tuple["TensorSpec", ...] = ()
    keys: tuple[Any, ...] = ()
    length: int = 1
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EncryptedTensor:
    """Flattened encrypted tensor/model weights plus restoration metadata."""

    values: tuple[Any, ...]
    spec: TensorSpec
    encoder: FixedPointEncoder
    divisor: int | float = 1
    label: str = "encrypted_tensor"

    def __len__(self) -> int:
        return len(self.values)

    @property
    def q(self) -> int:
        return self.encoder._q()

    @property
    def scale(self) -> int:
        return self.encoder.scale


EncryptedArray = EncryptedTensor
EncryptedModel = EncryptedTensor


@dataclass(frozen=True)
class AggregationResult:
    """Encrypted aggregate with method metadata.

    The actual divisor is stored inside ``encrypted.divisor``.
    """

    encrypted: EncryptedTensor
    method: str = "sum"
    metadata: dict[str, Any] | None = None

    @property
    def divisor(self) -> int | float:
        return self.encrypted.divisor


@dataclass(frozen=True)
class FLCapability:
    method: str
    encrypted_native: bool
    plaintext_tensor: bool
    notes: str


def _is_numpy_array(obj: Any) -> bool:
    return _np is not None and isinstance(obj, _np.ndarray)


def _is_torch_tensor(obj: Any) -> bool:
    mod = type(obj).__module__.split(".", 1)[0]
    return mod == "torch" and hasattr(obj, "detach") and hasattr(obj, "cpu")


def _is_tensorflow_like(obj: Any) -> bool:
    mod = type(obj).__module__.split(".", 1)[0]
    return mod in {"tensorflow", "keras", "tf_keras"} and hasattr(obj, "numpy")


def _to_numpy_list(obj: Any) -> tuple[list[float], TensorSpec]:
    if _np is None:  # pragma: no cover
        raise RuntimeError("NumPy is required for this tensor adapter")
    arr = _np.asarray(obj)
    values = [float(x) for x in arr.reshape(-1).tolist()]
    return values, TensorSpec("numpy", tuple(int(x) for x in arr.shape), str(arr.dtype), length=len(values))


def flatten_tree(obj: Any) -> tuple[list[float], TensorSpec]:
    """Flatten scalar/list/tuple/dict/NumPy/TensorFlow/Keras/Torch objects."""

    if hasattr(obj, "get_weights") and callable(obj.get_weights):
        weights = list(obj.get_weights())
        flat, spec = flatten_tree(weights)
        return flat, TensorSpec("keras_model_weights", children=(spec,), length=len(flat), meta={"class": type(obj).__name__})

    if isinstance(obj, Number):
        return [float(obj)], TensorSpec("scalar", (), type(obj).__name__, length=1)

    if _is_numpy_array(obj):
        return _to_numpy_list(obj)

    if _is_torch_tensor(obj):
        arr = obj.detach().cpu().numpy()
        flat, spec = _to_numpy_list(arr)
        return flat, TensorSpec("torch", spec.shape, str(getattr(obj, "dtype", "")), length=len(flat))

    if _is_tensorflow_like(obj):
        arr = obj.numpy()
        flat, spec = _to_numpy_list(arr)
        return flat, TensorSpec("tensorflow", spec.shape, str(getattr(obj, "dtype", "")), length=len(flat))

    if isinstance(obj, Mapping):
        keys = tuple(obj.keys())
        flats: list[float] = []
        children: list[TensorSpec] = []
        for key in keys:
            f, s = flatten_tree(obj[key])
            flats.extend(f)
            children.append(s)
        return flats, TensorSpec("dict", children=tuple(children), keys=keys, length=len(flats))

    if isinstance(obj, list):
        flats: list[float] = []
        children: list[TensorSpec] = []
        for item in obj:
            f, s = flatten_tree(item)
            flats.extend(f)
            children.append(s)
        return flats, TensorSpec("list", children=tuple(children), length=len(flats))

    if isinstance(obj, tuple):
        flats = []
        children = []
        for item in obj:
            f, s = flatten_tree(item)
            flats.extend(f)
            children.append(s)
        return flats, TensorSpec("tuple", children=tuple(children), length=len(flats))

    if hasattr(obj, "numpy") and callable(obj.numpy):
        arr = obj.numpy()
        flat, spec = _to_numpy_list(arr)
        return flat, TensorSpec("array_like", spec.shape, str(getattr(obj, "dtype", "")), length=len(flat))

    raise TypeError(f"unsupported model/tensor object type: {type(obj)!r}")


def _take(iterator: Iterator[float], n: int) -> list[float]:
    return [next(iterator) for _ in range(n)]


def _restore_numpy(values: list[float], spec: TensorSpec) -> Any:
    if _np is None:
        if not spec.shape:
            return values[0]
        return values
    arr = _np.asarray(values, dtype=float).reshape(spec.shape)
    # Do not cast decoded model weights back to int dtypes; preserve float output.
    return arr


def _torch_dtype(dtype_name: str | None) -> Any:
    try:  # pragma: no cover - optional dependency
        import torch  # type: ignore
    except Exception:  # pragma: no cover
        return None
    if not dtype_name:
        return None
    return getattr(torch, dtype_name.replace("torch.", ""), None)


def unflatten_tree(values: Sequence[float], spec: TensorSpec, *, prefer: str | None = None) -> Any:
    """Restore flattened values according to ``TensorSpec``."""

    iterator = iter([float(v) for v in values])

    def build(s: TensorSpec) -> Any:
        if s.kind == "scalar":
            return next(iterator)
        if s.kind in {"numpy", "array_like"}:
            return _restore_numpy(_take(iterator, s.length), s)
        if s.kind == "torch":
            vals = _take(iterator, s.length)
            arr = _restore_numpy(vals, TensorSpec("numpy", s.shape, None, length=s.length))
            try:  # pragma: no cover
                import torch  # type: ignore

                dtype = _torch_dtype(s.dtype)
                return torch.tensor(arr, dtype=dtype) if dtype is not None else torch.tensor(arr)
            except Exception:  # pragma: no cover
                return arr
        if s.kind == "tensorflow":
            vals = _take(iterator, s.length)
            arr = _restore_numpy(vals, TensorSpec("numpy", s.shape, None, length=s.length))
            try:  # pragma: no cover
                import tensorflow as tf  # type: ignore

                return tf.convert_to_tensor(arr)
            except Exception:  # pragma: no cover
                return arr
        if s.kind == "list":
            return [build(child) for child in s.children]
        if s.kind == "tuple":
            return tuple(build(child) for child in s.children)
        if s.kind == "dict":
            return {key: build(child) for key, child in zip(s.keys, s.children)}
        if s.kind == "keras_model_weights":
            return build(s.children[0])
        raise TypeError(f"unsupported TensorSpec kind: {s.kind}")

    del prefer
    return build(spec)


def extract_model_weights(model_or_weights: Any) -> Any:
    """Return Keras-style weights for models, otherwise return object itself."""
    if hasattr(model_or_weights, "get_weights") and callable(model_or_weights.get_weights):
        return list(model_or_weights.get_weights())
    return model_or_weights


def assign_model_weights(model: Any, weights: Any) -> Any:
    """Assign Keras-style weights to ``model`` and return the model."""
    if not hasattr(model, "set_weights") or not callable(model.set_weights):
        raise TypeError("model must provide set_weights(weights)")
    model.set_weights(weights)
    return model


def fl_capabilities() -> list[FLCapability]:
    return [
        FLCapability("sum", True, True, "native encrypted addition"),
        FLCapability("mean", True, True, "encrypted sum plus public divisor after decryption"),
        FLCapability("weighted_sum", True, True, "public integer or fixed-point weights"),
        FLCapability("weighted_average", True, True, "FedAvg-compatible"),
        FLCapability("fedavg", True, True, "sample-count weighted average"),
        FLCapability("fedsgd", True, True, "same weighted-average primitive applied to gradients"),
        FLCapability("coordinate_min", False, True, "requires comparison"),
        FLCapability("coordinate_max", False, True, "requires comparison"),
        FLCapability("coordinate_median", False, True, "requires sorting/order statistics"),
        FLCapability("trimmed_mean", False, True, "requires sorting/order statistics"),
        FLCapability("norm_clipped_mean", False, True, "requires plaintext norms/comparisons"),
        FLCapability("geometric_median", False, True, "iterative distance-based robust aggregation"),
        FLCapability("krum", False, True, "requires pairwise distances and sorting"),
        FLCapability("multi_krum", False, True, "requires pairwise distances and sorting"),
    ]


def _same_spec(a: TensorSpec, b: TensorSpec) -> bool:
    return a == b


def _require_compatible_encrypted(models: Sequence[EncryptedTensor]) -> None:
    if not models:
        raise ValueError("at least one encrypted tensor/model is required")
    first = models[0]
    for i, model in enumerate(models[1:], start=1):
        if len(model) != len(first):
            raise ValueError(f"model {i} has {len(model)} values, expected {len(first)}")
        if model.q != first.q or model.scale != first.scale:
            raise ValueError("encrypted models use incompatible q/scale")
        if not _same_spec(model.spec, first.spec):
            raise ValueError("encrypted models have different tensor/model structure")


def _integerize_weights(weights: Sequence[int | float], *, weight_scale: int = 1) -> list[int]:
    if not weights:
        raise ValueError("weights cannot be empty")
    if weight_scale <= 0:
        raise ValueError("weight_scale must be positive")
    out: list[int] = []
    for w in weights:
        if not isinstance(w, Number):
            raise TypeError("weights must be numeric")
        if isinstance(w, float) and not math.isfinite(w):
            raise ValueError("weights cannot contain NaN or infinity")
        out.append(int(round(float(w) * weight_scale)))
    if all(w == 0 for w in out):
        raise ValueError("at least one weight must be nonzero")
    return out


class EncryptedFLAggregator:
    """Encrypted FedAvg-style aggregation API."""

    def __init__(self, keypair: KeyPair, *, scale: int = 1000, seed: int = 1000) -> None:
        self.keypair = keypair
        self.encoder = FixedPointEncoder(keypair.params.q, scale=scale)
        self.seed = int(seed)
        self._counter = 0

    @classmethod
    def from_params(cls, params: SableParams, *, key_seed: int = 123, scale: int = 1000, seed: int = 1000) -> "EncryptedFLAggregator":
        kp = keygen_c7(params, seed=key_seed, mode="coordinate")
        return cls(kp, scale=scale, seed=seed)

    def encrypt_model(self, model_or_weights: Any, *, seed: int | None = None) -> EncryptedTensor:
        obj = extract_model_weights(model_or_weights)
        flat, spec = flatten_tree(obj)
        base = self.seed + self._counter * 1_000_003 if seed is None else int(seed)
        self._counter += 1
        encrypted_values = []
        for i, value in enumerate(flat):
            encoded = self.encoder.encode(value)
            encrypted_values.append(expand(self.keypair, encrypt(self.keypair, encoded, seed=base + 7919 * i)))
        return EncryptedTensor(tuple(encrypted_values), spec, self.encoder, divisor=1, label="encrypted_model")

    def decrypt_model(self, encrypted_model: EncryptedTensor, *, divisor: int | float | None = None) -> Any:
        div = encrypted_model.divisor if divisor is None else divisor
        decoded: list[float] = []
        for ct in encrypted_model.values:
            field_value = decrypt_c7(self.keypair, compact_c7(self.keypair, ct))
            decoded.append(encrypted_model.encoder.decode(field_value, divisor=div))
        return unflatten_tree(decoded, encrypted_model.spec)

    def add(self, left: EncryptedTensor, right: EncryptedTensor) -> EncryptedTensor:
        _require_compatible_encrypted([left, right])
        values = tuple(ops.add(a, b) for a, b in zip(left.values, right.values))
        return EncryptedTensor(values, left.spec, left.encoder, divisor=1, label="encrypted_add")

    def scalar_mul(self, model: EncryptedTensor, scalar: int) -> EncryptedTensor:
        values = tuple(ops.scalar_mul(ct, int(scalar)) for ct in model.values)
        return EncryptedTensor(values, model.spec, model.encoder, divisor=model.divisor, label="encrypted_scalar_mul")

    def sum(self, models: Sequence[EncryptedTensor]) -> EncryptedTensor:
        return sum_encrypted(models)

    def mean(self, models: Sequence[EncryptedTensor]) -> EncryptedTensor:
        return mean_encrypted(models)

    def weighted_sum(self, models: Sequence[EncryptedTensor], weights: Sequence[int | float], *, weight_scale: int = 1) -> EncryptedTensor:
        return weighted_sum_encrypted(models, weights, weight_scale=weight_scale)

    def weighted_average(self, models: Sequence[EncryptedTensor], weights: Sequence[int | float], *, weight_scale: int = 1) -> EncryptedTensor:
        return weighted_mean_encrypted(models, weights, weight_scale=weight_scale)

    def fedavg(self, models: Sequence[EncryptedTensor], sample_counts: Sequence[int]) -> EncryptedTensor:
        if any(int(c) < 0 for c in sample_counts):
            raise ValueError("sample counts must be nonnegative")
        return weighted_mean_encrypted(models, [int(c) for c in sample_counts])

    def fedsgd(self, gradients: Sequence[EncryptedTensor], sample_counts: Sequence[int]) -> EncryptedTensor:
        return self.fedavg(gradients, sample_counts)

    def min(self, *_: Any, **__: Any) -> EncryptedTensor:
        raise EncryptedComparisonNotSupported("encrypted min requires a comparison-circuit backend; use PlainFLAggregator.coordinate_min or min_after_decrypt")

    def max(self, *_: Any, **__: Any) -> EncryptedTensor:
        raise EncryptedComparisonNotSupported("encrypted max requires a comparison-circuit backend; use PlainFLAggregator.coordinate_max or max_after_decrypt")

    def median(self, *_: Any, **__: Any) -> EncryptedTensor:
        raise EncryptedComparisonNotSupported("encrypted median requires sorting/order statistics; use PlainFLAggregator.coordinate_median or median_after_decrypt")

    def trimmed_mean(self, *_: Any, **__: Any) -> EncryptedTensor:
        raise EncryptedComparisonNotSupported("encrypted trimmed mean requires sorting/order statistics; use PlainFLAggregator.trimmed_mean or trimmed_mean_after_decrypt")


class PlainFLAggregator:
    """Plaintext/tensor FL aggregation with NumPy/TensorFlow/Keras/Torch adapters."""

    def _matrix_and_spec(self, models: Sequence[Any]) -> tuple[list[list[float]], TensorSpec]:
        if not models:
            raise ValueError("at least one model is required")
        flats: list[list[float]] = []
        specs: list[TensorSpec] = []
        for model in models:
            flat, spec = flatten_tree(extract_model_weights(model))
            flats.append(flat)
            specs.append(spec)
        first = specs[0]
        for i, spec in enumerate(specs[1:], start=1):
            if spec != first:
                raise ValueError(f"model {i} has incompatible tensor structure")
        return flats, first

    def _restore(self, values: Sequence[float], spec: TensorSpec) -> Any:
        return unflatten_tree(values, spec)

    def sum(self, models: Sequence[Any]) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        return self._restore([sum(row[j] for row in matrix) for j in range(len(matrix[0]))], spec)

    def mean(self, models: Sequence[Any]) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        n = len(matrix)
        return self._restore([sum(row[j] for row in matrix) / n for j in range(len(matrix[0]))], spec)

    def weighted_sum(self, models: Sequence[Any], weights: Sequence[int | float]) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        if len(matrix) != len(weights):
            raise ValueError("model/weight length mismatch")
        return self._restore([sum(float(w) * row[j] for row, w in zip(matrix, weights)) for j in range(len(matrix[0]))], spec)

    def weighted_average(self, models: Sequence[Any], weights: Sequence[int | float]) -> Any:
        denom = float(sum(weights))
        if denom == 0:
            raise ValueError("sum of weights cannot be zero")
        matrix, spec = self._matrix_and_spec(models)
        if len(matrix) != len(weights):
            raise ValueError("model/weight length mismatch")
        return self._restore([sum(float(w) * row[j] for row, w in zip(matrix, weights)) / denom for j in range(len(matrix[0]))], spec)

    def fedavg(self, models: Sequence[Any], sample_counts: Sequence[int]) -> Any:
        return self.weighted_average(models, sample_counts)

    def coordinate_min(self, models: Sequence[Any]) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        return self._restore([min(row[j] for row in matrix) for j in range(len(matrix[0]))], spec)

    def coordinate_max(self, models: Sequence[Any]) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        return self._restore([max(row[j] for row in matrix) for j in range(len(matrix[0]))], spec)

    def coordinate_median(self, models: Sequence[Any]) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        out = []
        for j in range(len(matrix[0])):
            col = sorted(row[j] for row in matrix)
            mid = len(col) // 2
            out.append(col[mid] if len(col) % 2 else (col[mid - 1] + col[mid]) / 2)
        return self._restore(out, spec)

    def trimmed_mean(self, models: Sequence[Any], *, trim_ratio: float = 0.1) -> Any:
        if not (0 <= trim_ratio < 0.5):
            raise ValueError("trim_ratio must be in [0, 0.5)")
        matrix, spec = self._matrix_and_spec(models)
        n = len(matrix)
        trim = int(math.floor(n * trim_ratio))
        out = []
        for j in range(len(matrix[0])):
            col = sorted(row[j] for row in matrix)
            kept = col[trim: n - trim] if trim else col
            if not kept:
                raise ValueError("trim_ratio removes all values")
            out.append(sum(kept) / len(kept))
        return self._restore(out, spec)

    def norm_clipped_mean(self, models: Sequence[Any], *, clip_norm: float) -> Any:
        if clip_norm <= 0:
            raise ValueError("clip_norm must be positive")
        matrix, spec = self._matrix_and_spec(models)
        clipped: list[list[float]] = []
        for row in matrix:
            norm = math.sqrt(sum(x * x for x in row))
            factor = min(1.0, clip_norm / norm) if norm > 0 else 1.0
            clipped.append([factor * x for x in row])
        return self._restore([sum(row[j] for row in clipped) / len(clipped) for j in range(len(clipped[0]))], spec)

    def geometric_median(self, models: Sequence[Any], *, max_iter: int = 100, tol: float = 1e-6, eps: float = 1e-12) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        d = len(matrix[0])
        x = [sum(row[j] for row in matrix) / len(matrix) for j in range(d)]
        for _ in range(max_iter):
            weights = []
            for row in matrix:
                dist = math.sqrt(sum((row[j] - x[j]) ** 2 for j in range(d)))
                weights.append(1.0 / max(dist, eps))
            denom = sum(weights)
            nxt = [sum(w * row[j] for w, row in zip(weights, matrix)) / denom for j in range(d)]
            delta = math.sqrt(sum((nxt[j] - x[j]) ** 2 for j in range(d)))
            x = nxt
            if delta < tol:
                break
        return self._restore(x, spec)

    def krum(self, models: Sequence[Any], *, f: int = 0) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        n = len(matrix)
        if n < 2 * f + 3:
            raise ValueError("Krum requires n >= 2f + 3")
        scores = []
        for i, row_i in enumerate(matrix):
            distances = []
            for j, row_j in enumerate(matrix):
                if i != j:
                    distances.append(sum((a - b) ** 2 for a, b in zip(row_i, row_j)))
            distances.sort()
            scores.append((sum(distances[: n - f - 2]), i))
        _, best = min(scores)
        return self._restore(matrix[best], spec)

    def multi_krum(self, models: Sequence[Any], *, f: int = 0, m: int | None = None) -> Any:
        matrix, spec = self._matrix_and_spec(models)
        n = len(matrix)
        if n < 2 * f + 3:
            raise ValueError("Multi-Krum requires n >= 2f + 3")
        if m is None:
            m = max(1, n - f - 2)
        if not (1 <= m <= n):
            raise ValueError("m must be in [1, n]")
        scores = []
        for i, row_i in enumerate(matrix):
            distances = []
            for j, row_j in enumerate(matrix):
                if i != j:
                    distances.append(sum((a - b) ** 2 for a, b in zip(row_i, row_j)))
            distances.sort()
            scores.append((sum(distances[: n - f - 2]), i))
        selected = [idx for _, idx in sorted(scores)[:m]]
        out = [sum(matrix[i][j] for i in selected) / m for j in range(len(matrix[0]))]
        return self._restore(out, spec)


# Encrypted functional API.

def encrypt_array(kp: KeyPair, values: Any, *, scale: int = 1000, seed: int = 1000, encoder: FixedPointEncoder | None = None, name: str | None = None) -> EncryptedTensor:
    del name
    scale_value = encoder.scale if encoder is not None else scale
    return EncryptedFLAggregator(kp, scale=scale_value, seed=seed).encrypt_model(values, seed=seed)


def decrypt_array(kp: KeyPair, encrypted_values: EncryptedTensor, *, divisor: int | float | None = None, output: str | None = None) -> Any:
    del output
    return EncryptedFLAggregator(kp, scale=encrypted_values.scale).decrypt_model(encrypted_values, divisor=divisor)


def encrypt_model(kp: KeyPair, model_or_weights: Any, *, scale: int = 1000, seed: int = 1000) -> EncryptedTensor:
    return encrypt_array(kp, model_or_weights, scale=scale, seed=seed)


def decrypt_model(kp: KeyPair, encrypted_model: EncryptedTensor) -> Any:
    return decrypt_array(kp, encrypted_model)


def encrypt_model_weights(kp: KeyPair, model_or_weights: Any, *, scale: int = 1000, seed: int = 1000, encoder: FixedPointEncoder | None = None, name: str | None = None) -> EncryptedTensor:
    return encrypt_array(kp, model_or_weights, scale=scale, seed=seed, encoder=encoder, name=name)


def decrypt_model_weights(kp: KeyPair, encrypted_model: EncryptedTensor, *, divisor: int | float | None = None, output: str | None = None) -> Any:
    return decrypt_array(kp, encrypted_model, divisor=divisor, output=output)


def sum_encrypted(models: Sequence[EncryptedTensor]) -> EncryptedTensor:
    _require_compatible_encrypted(models)
    values = list(models[0].values)
    for model in models[1:]:
        values = [ops.add(a, b) for a, b in zip(values, model.values)]
    return EncryptedTensor(tuple(values), models[0].spec, models[0].encoder, divisor=1, label="encrypted_sum")


def secure_sum_encrypted(models: Sequence[EncryptedTensor]) -> EncryptedTensor:
    return sum_encrypted(models)


def mean_encrypted(models: Sequence[EncryptedTensor]) -> EncryptedTensor:
    summed = sum_encrypted(models)
    return EncryptedTensor(summed.values, summed.spec, summed.encoder, divisor=len(models), label="encrypted_mean")


def weighted_sum_encrypted(models: Sequence[EncryptedTensor], weights: Sequence[int | float], *, weight_scale: int = 1) -> EncryptedTensor:
    _require_compatible_encrypted(models)
    if len(models) != len(weights):
        raise ValueError("model/weight length mismatch")
    coeffs = _integerize_weights(weights, weight_scale=weight_scale)
    values = []
    for j in range(len(models[0])):
        acc = ops.scalar_mul(models[0].values[j], coeffs[0])
        for model, coeff in zip(models[1:], coeffs[1:]):
            acc = ops.add(acc, ops.scalar_mul(model.values[j], coeff))
        values.append(acc)
    return EncryptedTensor(tuple(values), models[0].spec, models[0].encoder, divisor=weight_scale, label="encrypted_weighted_sum")


def weighted_mean_encrypted(models: Sequence[EncryptedTensor], weights: Sequence[int | float], *, weight_scale: int = 1) -> EncryptedTensor:
    weighted = weighted_sum_encrypted(models, weights, weight_scale=weight_scale)
    coeffs = _integerize_weights(weights, weight_scale=weight_scale)
    denom = sum(coeffs)
    if denom == 0:
        raise ValueError("sum of weights cannot be zero")
    return EncryptedTensor(weighted.values, weighted.spec, weighted.encoder, divisor=denom, label="encrypted_weighted_mean")


weighted_average_encrypted = weighted_mean_encrypted


def fedavg_encrypted(kp: KeyPair, encrypted_models: Sequence[EncryptedTensor], sample_counts: Sequence[int]) -> EncryptedTensor:
    del kp
    if any(int(c) < 0 for c in sample_counts):
        raise ValueError("sample counts must be nonnegative")
    return weighted_mean_encrypted(encrypted_models, [int(c) for c in sample_counts])


def fedsgd_encrypted(kp: KeyPair, encrypted_gradients: Sequence[EncryptedTensor], sample_counts: Sequence[int]) -> EncryptedTensor:
    return fedavg_encrypted(kp, encrypted_gradients, sample_counts)


def decrypt_aggregation(kp: KeyPair, result: AggregationResult | EncryptedTensor, *, output: str | None = None) -> Any:
    encrypted = result.encrypted if isinstance(result, AggregationResult) else result
    return decrypt_array(kp, encrypted, output=output)


def fedavg(kp_or_models: KeyPair | Sequence[Any], client_models_or_counts: Sequence[EncryptedTensor] | Sequence[int], sample_counts: Sequence[int] | None = None, *, output: str | None = None) -> Any:
    """FedAvg convenience API.

    ``fedavg(kp, encrypted_models, sample_counts)`` performs encrypted FedAvg
    and decrypts the result.  ``fedavg(plain_models, sample_counts)`` performs
    plaintext/tensor FedAvg.
    """
    if isinstance(kp_or_models, KeyPair):
        if sample_counts is None:
            raise ValueError("encrypted fedavg requires sample_counts")
        result = fedavg_encrypted(kp_or_models, client_models_or_counts, sample_counts)  # type: ignore[arg-type]
        return decrypt_array(kp_or_models, result, output=output)
    return PlainFLAggregator().fedavg(kp_or_models, client_models_or_counts)  # type: ignore[arg-type]


# Plain/after-decrypt API.

def clear_aggregate_arrays(values: Sequence[Any], *, method: str = "mean", weights: Sequence[int | float] | None = None, trim_ratio: float = 0.1, output: str | None = None, **kwargs: Any) -> Any:
    del output
    agg = PlainFLAggregator()
    name = method.lower().replace("-", "_")
    if name in {"sum", "secure_sum"}:
        return agg.sum(values)
    if name in {"mean", "average"}:
        return agg.mean(values)
    if name == "weighted_sum":
        if weights is None:
            raise ValueError("weights are required for weighted_sum")
        return agg.weighted_sum(values, weights)
    if name in {"weighted_average", "weighted_mean", "fedavg"}:
        if weights is None:
            raise ValueError("weights/sample counts are required")
        return agg.weighted_average(values, weights)
    if name in {"min", "coordinate_min"}:
        return agg.coordinate_min(values)
    if name in {"max", "coordinate_max"}:
        return agg.coordinate_max(values)
    if name in {"median", "coordinate_median"}:
        return agg.coordinate_median(values)
    if name == "trimmed_mean":
        return agg.trimmed_mean(values, trim_ratio=trim_ratio)
    if name == "norm_clipped_mean":
        return agg.norm_clipped_mean(values, clip_norm=float(kwargs["clip_norm"]))
    if name == "geometric_median":
        return agg.geometric_median(values, max_iter=int(kwargs.get("max_iter", 100)), tol=float(kwargs.get("tol", 1e-6)))
    if name == "krum":
        return agg.krum(values, f=int(kwargs.get("f", 0)))
    if name == "multi_krum":
        return agg.multi_krum(values, f=int(kwargs.get("f", 0)), m=kwargs.get("m"))
    raise ValueError(f"unknown aggregation method: {method}")


clear_aggregate_models = clear_aggregate_arrays
aggregate_plain_arrays = clear_aggregate_arrays
aggregate_plain_models = clear_aggregate_arrays


def aggregate_after_decrypt(kp: KeyPair, encrypted_models: Sequence[EncryptedTensor], *, method: str, weights: Sequence[int | float] | None = None, **kwargs: Any) -> Any:
    clear_models = [decrypt_array(kp, model) for model in encrypted_models]
    return clear_aggregate_arrays(clear_models, method=method, weights=weights, **kwargs)


def min_after_decrypt(kp: KeyPair, encrypted_models: Sequence[EncryptedTensor]) -> Any:
    return aggregate_after_decrypt(kp, encrypted_models, method="min")


def max_after_decrypt(kp: KeyPair, encrypted_models: Sequence[EncryptedTensor]) -> Any:
    return aggregate_after_decrypt(kp, encrypted_models, method="max")


def median_after_decrypt(kp: KeyPair, encrypted_models: Sequence[EncryptedTensor]) -> Any:
    return aggregate_after_decrypt(kp, encrypted_models, method="median")


def trimmed_mean_after_decrypt(kp: KeyPair, encrypted_models: Sequence[EncryptedTensor], *, trim_ratio: float = 0.1) -> Any:
    return aggregate_after_decrypt(kp, encrypted_models, method="trimmed_mean", trim_ratio=trim_ratio)


def min_encrypted(*args: Any, **kwargs: Any) -> EncryptedTensor:
    del args, kwargs
    raise EncryptedComparisonNotSupported("encrypted min requires comparison circuits; use min_after_decrypt or PlainFLAggregator.coordinate_min")


def max_encrypted(*args: Any, **kwargs: Any) -> EncryptedTensor:
    del args, kwargs
    raise EncryptedComparisonNotSupported("encrypted max requires comparison circuits; use max_after_decrypt or PlainFLAggregator.coordinate_max")


def median_encrypted(*args: Any, **kwargs: Any) -> EncryptedTensor:
    del args, kwargs
    raise EncryptedComparisonNotSupported("encrypted median requires sorting/order statistics; use median_after_decrypt or PlainFLAggregator.coordinate_median")


encrypted_min_arrays = min_encrypted
encrypted_max_arrays = max_encrypted


__all__ = [
    "AggregationResult", "EncryptedArray", "EncryptedComparisonNotSupported", "EncryptedFLAggregator",
    "EncryptedModel", "EncryptedTensor", "FLCapability", "FixedPointEncoder", "PlainFLAggregator",
    "TensorSpec", "UnsupportedEncryptedAggregation", "aggregate_after_decrypt", "aggregate_plain_arrays",
    "aggregate_plain_models", "assign_model_weights", "clear_aggregate_arrays", "clear_aggregate_models",
    "decrypt_aggregation", "decrypt_array", "decrypt_model", "decrypt_model_weights", "encrypted_max_arrays",
    "encrypted_min_arrays", "encrypt_array", "encrypt_model", "encrypt_model_weights", "extract_model_weights",
    "fedavg", "fedavg_encrypted", "fedsgd_encrypted", "fl_capabilities", "flatten_tree",
    "max_after_decrypt", "max_encrypted", "mean_encrypted", "median_after_decrypt", "median_encrypted",
    "min_after_decrypt", "min_encrypted", "secure_sum_encrypted", "sum_encrypted", "trimmed_mean_after_decrypt",
    "unflatten_tree", "weighted_average_encrypted", "weighted_mean_encrypted", "weighted_sum_encrypted",
]
