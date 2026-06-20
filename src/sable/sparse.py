"""Sparse vector and matrix arithmetic over prime fields."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping, Sequence


@dataclass(frozen=True)
class SparseVector:
    length: int
    data: dict[int, int]
    q: int

    def __post_init__(self) -> None:
        if self.length <= 0:
            raise ValueError("length must be positive")
        cleaned: dict[int, int] = {}
        for i, v in self.data.items():
            if i < 0 or i >= self.length:
                raise IndexError(f"index {i} outside vector length {self.length}")
            vv = v % self.q
            if vv != 0:
                cleaned[int(i)] = vv
        object.__setattr__(self, "data", cleaned)

    @classmethod
    def zero(cls, length: int, q: int) -> "SparseVector":
        return cls(length, {}, q)

    @classmethod
    def from_dense(cls, values: Sequence[int], q: int) -> "SparseVector":
        return cls(len(values), {i: v % q for i, v in enumerate(values) if v % q}, q)

    def to_dense(self) -> list[int]:
        out = [0] * self.length
        for i, v in self.data.items():
            out[i] = v
        return out

    def nnz(self) -> int:
        return len(self.data)

    def get(self, idx: int) -> int:
        if idx < 0 or idx >= self.length:
            raise IndexError(idx)
        return self.data.get(idx, 0)

    def scale(self, alpha: int) -> "SparseVector":
        a = alpha % self.q
        if a == 0:
            return SparseVector.zero(self.length, self.q)
        return SparseVector(self.length, {i: (a * v) % self.q for i, v in self.data.items()}, self.q)

    def add(self, other: "SparseVector") -> "SparseVector":
        return self.add_scaled(other, 1)

    def add_scaled(self, other: "SparseVector", alpha: int) -> "SparseVector":
        if self.length != other.length or self.q != other.q:
            raise ValueError("incompatible vectors")
        a = alpha % self.q
        if a == 0:
            return self
        out = dict(self.data)
        for i, v in other.data.items():
            nv = (out.get(i, 0) + a * v) % self.q
            if nv:
                out[i] = nv
            elif i in out:
                del out[i]
        return SparseVector(self.length, out, self.q)

    def dot_dense(self, dense: Sequence[int]) -> int:
        if len(dense) != self.length:
            raise ValueError("length mismatch")
        return sum((v * dense[i]) % self.q for i, v in self.data.items()) % self.q

    def dot_sparse(self, other: "SparseVector") -> int:
        if self.length != other.length or self.q != other.q:
            raise ValueError("incompatible vectors")
        if self.nnz() <= other.nnz():
            return sum((v * other.data.get(i, 0)) % self.q for i, v in self.data.items()) % self.q
        return sum((v * self.data.get(i, 0)) % self.q for i, v in other.data.items()) % self.q


@dataclass(frozen=True)
class SparseMatrix:
    nrows: int
    ncols: int
    rows: list[SparseVector]
    q: int

    def __post_init__(self) -> None:
        if self.nrows <= 0 or self.ncols <= 0:
            raise ValueError("matrix dimensions must be positive")
        if len(self.rows) != self.nrows:
            raise ValueError("row count mismatch")
        for row in self.rows:
            if row.length != self.ncols or row.q != self.q:
                raise ValueError("incompatible row")

    @classmethod
    def zero(cls, nrows: int, ncols: int, q: int) -> "SparseMatrix":
        return cls(nrows, ncols, [SparseVector.zero(ncols, q) for _ in range(nrows)], q)

    @classmethod
    def from_rows(cls, rows: list[SparseVector], q: int) -> "SparseMatrix":
        if not rows:
            raise ValueError("rows cannot be empty")
        ncols = rows[0].length
        return cls(len(rows), ncols, rows, q)

    def row_supports(self) -> list[int]:
        return [row.nnz() for row in self.rows]

    def max_row_support(self) -> int:
        return max(self.row_supports()) if self.rows else 0

    def total_nnz(self) -> int:
        return sum(row.nnz() for row in self.rows)

    def scale(self, alpha: int) -> "SparseMatrix":
        return SparseMatrix(self.nrows, self.ncols, [row.scale(alpha) for row in self.rows], self.q)

    def add(self, other: "SparseMatrix") -> "SparseMatrix":
        return self.add_scaled(other, 1)

    def add_scaled(self, other: "SparseMatrix", alpha: int) -> "SparseMatrix":
        if self.nrows != other.nrows or self.ncols != other.ncols or self.q != other.q:
            raise ValueError("incompatible matrices")
        return SparseMatrix(
            self.nrows,
            self.ncols,
            [r.add_scaled(o, alpha) for r, o in zip(self.rows, other.rows)],
            self.q,
        )

    def matmul(self, other: "SparseMatrix") -> "SparseMatrix":
        if self.ncols != other.nrows or self.q != other.q:
            raise ValueError("matrix dimension mismatch")
        out_rows: list[SparseVector] = []
        for row in self.rows:
            acc = SparseVector.zero(other.ncols, self.q)
            for k, coeff in row.data.items():
                acc = acc.add_scaled(other.rows[k], coeff)
            out_rows.append(acc)
        return SparseMatrix(self.nrows, other.ncols, out_rows, self.q)

    def apply_to_dense(self, vector: Sequence[int]) -> list[int]:
        if len(vector) != self.ncols:
            raise ValueError("dimension mismatch")
        return [row.dot_dense(vector) for row in self.rows]

    def last_row(self) -> SparseVector:
        return self.rows[-1]


def sample_sparse_prefix(length: int, prefix: int, weight: int, q: int, rng) -> SparseVector:
    """Sample a sparse vector whose support lies in range(prefix)."""
    if prefix > length:
        raise ValueError("prefix cannot exceed length")
    if weight < 0 or weight > prefix:
        raise ValueError("invalid sparse weight")
    positions = rng.sample(range(prefix), weight)
    data = {i: rng.randrange(1, q) for i in positions}
    return SparseVector(length, data, q)
