"""Experimental CRT wrapper for SABLE lanes."""

from __future__ import annotations

from dataclasses import dataclass

from .crt import CRTModuli
from .params import SableParams
from . import sable


@dataclass(frozen=True)
class CRTKeyPair:
    lane_keypairs: list[sable.KeyPair]
    crt: CRTModuli


def keygen(lane_params: list[SableParams], seed: int | None = None) -> CRTKeyPair:
    if not lane_params:
        raise ValueError("lane_params cannot be empty")
    kps = [sable.keygen(p, seed=None if seed is None else seed + i) for i, p in enumerate(lane_params)]
    return CRTKeyPair(kps, CRTModuli(tuple(p.q for p in lane_params)))


def encrypt(kp: CRTKeyPair, x: int, seed: int | None = None):
    residues = kp.crt.residues(x)
    return [sable.expand(lane, sable.encrypt(lane, residue, seed=None if seed is None else seed + i)) for i, (lane, residue) in enumerate(zip(kp.lane_keypairs, residues))]


def eval_add(left, right):
    return [sable.eval_add(a, b) for a, b in zip(left, right)]


def eval_mul(left, right):
    return [sable.eval_mul(a, b) for a, b in zip(left, right)]


def decrypt(kp: CRTKeyPair, ciphertext) -> int:
    residues = [sable.decrypt(lane, sable.compact(lane, ct)) for lane, ct in zip(kp.lane_keypairs, ciphertext)]
    return kp.crt.reconstruct(tuple(residues))
